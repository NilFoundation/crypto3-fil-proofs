//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020 Wukong Moscow Algorithm Lab
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef FILECOIN_STORAGE_PROOFS_POST_RATIONAL_VANILLA_HPP
#define FILECOIN_STORAGE_PROOFS_POST_RATIONAL_VANILLA_HPP

#include <nil/crypto3/hash/blake2b.hpp>

#include <nil/filecoin/storage/proofs/core/parameter_cache.hpp>
#include <nil/filecoin/storage/proofs/core/sector.hpp>
#include <nil/filecoin/storage/proofs/core/proof/proof.hpp>
#include <nil/filecoin/storage/proofs/core/btree/map.hpp>

namespace nil {
    namespace filecoin {
        namespace post {
            namespace rational {
                struct SetupParams {
                    /// The size of a sector.
                    std::uint64_t sector_size;
                    // TODO: can we drop this?
                    /// How many challenges there are in total.
                    std::size_t challenges_count;
                };

                struct PublicParams : public parameter_set_metadata {
                    virtual std::string identifier() const override {
                        return std::string();
                    }
                    virtual size_t sector_size() const override {
                        return ssize;
                    }

                    /// The size of a sector.
                    std::uint64_t ssize;
                    /// How many challenges there are in total.
                    std::size_t challenges_count;
                };

                struct Challenge {
                    // The identifier of the challenged sector.
                    sector_id_type sector;
                    // The leaf index this challenge points at.
                    std::uint64_t leaf;
                };

                template<typename Domain>
                struct PublicInputs {
                    typedef Challenge challenge_type;

                    /// The challenges, which leafs to prove.
                    std::vector<challenge_type> challenges;
                    ordered_sector_set faults;
                    std::vector<Domain> comm_rs;
                };

                template<typename MerkleTreeType>
                struct PrivateInputs {
                    btree::map<sector_id_type,
                               MerkleTreeWrapper<typename MerkleTreeType::hash_type, MerkleTreeType::Store,
                                                 MerkleTreeType::base_arity, MerkleTreeType::sub_tree_arity,
                                                 MerkleTreeType::top_tree_arity>>
                        trees;
                    std::vector<typename MerkleTreeType::hash_type::digest_type> comm_cs;
                    std::vector<typename MerkleTreeType::hash_type::digest_type> comm_r_lasts;
                };

                template<typename MerkleProofType>
                struct Proof {
                    std::vector<typename MerkleTreeType::hash_type::digest_type> leafs() {
                        return inclusion_proofs.iter().map(MerkleProof::leaf).collect();
                    }

                    std::vector<typename MerkleTreeType::hash_type::digest_type> commitments() {
                        return inclusion_proofs.iter().map(MerkleProof::root).collect();
                    }

                    std::vector<std::vector<
                        std::pair<std::vector<typename MerkleTreeType::hash_type::digest_type>, std::size_t>>>
                        paths() {
                        return inclusion_proofs.iter().map(MerkleProof::path).collect();
                    }

                    std::vector<MerkleProof<typename MerkleProofType::hash_type, MerkleProofType::Arity,
                                            MerkleProofType::SubTreeArity, MerkleProofType::TopTreeArity>>
                        inclusion_proofs;
                    std::vector<typename MerkleTreeType::hash_type::digest_type> comm_cs;
                };

                template<typename MerkleTreeType>
                class RationalPoSt
                    : public proof_scheme<
                          PublicParams, SetupParams, PublicInputs<typename MerkleTreeType::hash_type::digest_type>,
                          PrivateInputs<MerkleTreeType>, Proof<typename MerkleTreeType::proof_type>, no_requirements> {
                    typedef proof_scheme<
                        PublicParams, SetupParams, PublicInputs<typename MerkleTreeType::hash_type::digest_type>,
                        PrivateInputs<MerkleTreeType>, Proof<typename MerkleTreeType::proof_type>, no_requirements>
                        policy_type;

                public:
                    typedef typename policy_type::public_params_type public_params_type;
                    typedef typename policy_type::setup_params setup_params_type;
                    typedef typename policy_type::public_inputs public_inputs_type;
                    typedef typename policy_type::private_inputs private_inputs_type;
                    typedef typename policy_type::proof_type proof_type;
                    typedef typename policy_type::requirements_type requirements_type;

                    virtual public_params_type setup(const setup_params_type &p) override {
                        return {p.sector_size, p.challenges_count};
                    }

                    virtual proof_type prove(const public_params_type &params,
                                             const public_inputs_type &inputs,
                                             const private_inputs_type &pinputs) override {
                        assert(
                            ("mismatched challenges and comm_rs", inputs.challenges.size() == inputs.comm_rs.size()));
                        assert(
                            ("mismatched challenges and comm_cs", inputs.challenges.size() == pinputs.comm_cs.size()));
                        assert(("mismatched challenges and comm_r_lasts",
                                pub_inputs.challenges.size() == priv_inputs.comm_r_lasts.size()));
                        const auto challenges = pub_inputs.challenges;

                        const auto proofs =
                            challenges.iter()
                                .zip(priv_inputs.comm_r_lasts.iter())
                                .map(| (challenge, comm_r_last) |
                                     {
                                         const auto challenged_leaf = challenge.leaf;

                                         if const auto
                                             Some(tree) = priv_inputs.trees.get(&challenge.sector) {
                                                 ensure !(comm_r_last == &tree.root(), Error::InvalidCommitment);

                                                 tree.gen_cached_proof(challenged_leaf as usize, None)
                                             }
                                         else {
                                             bail !(Error::MalformedInput);
                                         }
                                     })
                                .collect::<Result<Vec<_>>>();

                        return {proofs, pinputs.comm_cs.to_vec()};
                    }
                    virtual bool verify(const public_params_type &pub_params,
                                        const public_inputs_type &pub_inputs,
                                        const proof_type &pr) override {
                        const auto challenges = pub_inputs.challenges;

                        assert(challenges.size() == pub_inputs.comm_rs.size());

                        assert(challenges.size() == pr.inclusion_proofs.size());

                        // validate each proof
                        for ((((merkle_proof, challenge), comm_r), comm_c) : proof.inclusion_proofs.iter()
                                                                                 .zip(challenges.iter())
                                                                                 .zip(pub_inputs.comm_rs.iter())
                                                                                 .zip(proof.comm_cs.iter())) {
                            const auto challenged_leaf = challenge.leaf;

                            // verify that H(Comm_c || Comm_r_last) == Comm_R
                            // comm_r_last is the root of the proof
                            const auto comm_r_last = merkle_proof.root();

                            if (AsRef::<[u8]>::as_ref(&<typename MerkleTreeType::hash_type>::Function::hash2(
                                    comm_c, &comm_r_last, )) != AsRef::<[u8]>::as_ref(&comm_r)) {
                                return false;
                            }

                            // validate the path length
                            const auto expected_path_length =
                                merkle_proof.expected_len(pub_params.sector_size as usize / NODE_SIZE);

                            if (expected_path_length != merkle_proof.path().size()) {
                                return false;
                            }

                            if (!merkle_proof.validate(challenged_leaf)) {
                                return false;
                            }
                        }

                        return true;
                    }
                };

                Challenge derive_challenge(const std::vector<std::uint8_t> &seed, std::uint64_t n,
                                           std::uint64_t attempt, std::uin64_t sector_size,
                                           const ordered_sector_set &sectors) {
                    auto data = seed.to_vec();
                    data.extend_from_slice(&n.to_le_bytes()[..]);
                    data.extend_from_slice(&attempt.to_le_bytes()[..]);

                    const auto hash = blake2b_simd::blake2b(&data);
                    const auto challenge_bytes = hash.as_bytes();
                    const auto sector_challenge = LittleEndian::read_u64(&challenge_bytes[..8]);
                    const auto leaf_challenge = LittleEndian::read_u64(&challenge_bytes[8..16]);

                    const auto sector_index = (std::uint64_t(sector_challenge % sectors.len())) as usize;
                    const auto sector = *sectors.iter().nth(sector_index).context("invalid challenge generated") ? ;

                    return {sector, leaf_challenge % (sector_size / NODE_SIZE)};
                }

                /// Rational PoSt specific challenge derivation.
                std::vector<Challenge> derive_challenges(std::size_t challenge_count, std::uint64_t sector_size,
                                                         const ordered_sector_set &sectors,
                                                         const std::vector<std::uint8_t> &seed,
                                                         const ordered_sector_set &faults) {
                    (0..challenge_count)
                        .map(| n |
                             {
                                 auto attempt = 0;
                                 auto attempted_sectors = HashSet::new ();
                                 while (true) {
                                     const auto c = derive_challenge(seed, std::uint64_t(n), attempt, sector_size, sectors);

                                     // check for faulty sector
                                     if (!faults.contains(&c.sector)) {
                                         // valid challenge, not found
                                         return c;
                                     } else {
                                         attempt += 1;
                                         attempted_sectors.insert(c.sector);

                                         assert(("all sectors are faulty", attempted_sectors.size() < sectors.size()));
                                     }
                                 }
                             })
                        .collect();
                }
            }    // namespace rational
        }        // namespace post
    }            // namespace filecoin
}    // namespace nil

#endif

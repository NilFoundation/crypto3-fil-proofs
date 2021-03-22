//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nemo@nil.foundation>
//
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

                template<typename MerkleTreeType>
                struct Proof {
                    std::vector<typename MerkleTreeType::hash_type::digest_type> leafs() {
                        return std::accumulate(inclusion_proofs.begin(), inclusion_proofs.end(),
                                               std::vector<typename MerkleTreeType::hash_type::digest_type>(),
                                               [&](auto &val, const auto &itr) { val.emplace_back(itr.leaf()); });
                    }

                    std::vector<typename MerkleTreeType::hash_type::digest_type> commitments() {
                        return std::accumulate(inclusion_proofs.begin(), inclusion_proofs.end(),
                                               std::vector<typename MerkleTreeType::hash_type::digest_type>(),
                                               [&](auto &val, const auto &itr) { val.emplace_back(itr.root()); });
                    }

                    std::vector<std::vector<
                        std::pair<std::vector<typename MerkleTreeType::hash_type::digest_type>, std::size_t>>>
                        paths() {
                        return std::accumulate(inclusion_proofs.begin(), inclusion_proofs.end(),
                                               std::vector<typename MerkleTreeType::hash_type::digest_type>(),
                                               [&](auto &val, const auto &itr) { val.emplace_back(itr.path()); });
                    }

                    std::vector<MerkleProof<typename MerkleTreeType::hash_type, MerkleTreeType::Arity,
                                            MerkleTreeType::SubTreeArity, MerkleTreeType::TopTreeArity>>
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
                        BOOST_ASSERT_MSG(inputs.challenges.size() == inputs.comm_rs.size(),
                                         "mismatched challenges and comm_rs");
                        BOOST_ASSERT_MSG(inputs.challenges.size() == pinputs.comm_cs.size(),
                                         "mismatched challenges and comm_cs");
                        BOOST_ASSERT_MSG(inputs.challenges.size() == pinputs.comm_r_lasts.size(),
                                         "mismatched challenges and comm_r_lasts");
                        const auto challenges = inputs.challenges;

                        std::vector<proof_type> proofs(challenges.size());

                        for (int i = 0; i < challenges.size() && i < pinputs.comm_r_lasts.size(); i++) {
                            const auto challenged_leaf = challenges[i].leaf;

                            auto tree = pinputs.trees[challenges[i].sector];

                            if (tree) {
                                assert(pinputs.comm_r_lasts[i] == tree.root());

                                proofs.emplace_back(tree.gen_cached_proof(challenged_leaf, None));
                            } else {
                                throw Error::MalformedInput;
                            }
                        }

                        return {proofs, pinputs.comm_cs.to_vec()};
                    }
                    virtual bool verify(const public_params_type &pub_params,
                                        const public_inputs_type &pub_inputs,
                                        const proof_type &pr) override {
                        const auto challenges = pub_inputs.challenges;

                        assert(challenges.size() == pub_inputs.comm_rs.size());

                        assert(challenges.size() == pr.inclusion_proofs.size());

                        // validate each proof
                        for (int i = 0; i < pr.inclusion_proofs.size() && i < challenges.size() &&
                                        i < pub_inputs.comm_rs.size() && i < pr.comm_cs.size();
                             i++) {
                            const auto challenged_leaf = challenges[i].leaf();

                            // verify that H(Comm_c || Comm_r_last) == Comm_R
                            // comm_r_last is the root of the proof
                            const auto comm_r_last = pr.inclusion_proofs[i].root();

                            if (AsRef::<[u8]>::as_ref(&<typename MerkleTreeType::hash_type>::Function::hash2(
                                    pr.comm_cs[i], &comm_r_last, )) != AsRef::<[u8]>::as_ref(pub_inputs.comm_rs[i])) {
                                return false;
                            }

                            // validate the path length
                            const auto expected_path_length =
                                pr.inclusion_proofs[i].expected_len(pub_params.sector_size / NODE_SIZE);

                            if (expected_path_length != pr.inclusion_proofs[i].path().size()) {
                                return false;
                            }

                            if (!pr.inclusion_proofs[i].validate(challenged_leaf)) {
                                return false;
                            }
                        }
                        return true;
                    }
                };

                Challenge derive_challenge(const std::vector<std::uint8_t> &seed, std::uint64_t n,
                                           std::uint64_t attempt, std::uin64_t sector_size,
                                           const ordered_sector_set &sectors) {
                    seed.extend_from_slice(&n.to_le_bytes()[..]);
                    seed.extend_from_slice(&attempt.to_le_bytes()[..]);

                    const auto hash = blake2b_simd::blake2b(seed);
                    const auto challenge_bytes = hash.as_bytes();
                    const auto sector_challenge = LittleEndian::read_u64(&challenge_bytes[..8]);
                    const auto leaf_challenge = LittleEndian::read_u64(&challenge_bytes[8..16]);

                    const auto sector_index = (std::uint64_t(sector_challenge % sectors.len())) as usize;
                    const auto sector = *sectors.iter().nth(sector_index).context("invalid challenge generated");

                    return {sector, leaf_challenge % (sector_size / NODE_SIZE)};
                }

                /// Rational PoSt specific challenge derivation.
                std::vector<Challenge> derive_challenges(std::size_t challenge_count, std::uint64_t sector_size,
                                                         const ordered_sector_set &sectors,
                                                         const std::vector<std::uint8_t> &seed,
                                                         const ordered_sector_set &faults) {
                    for (int i = 0; i < challenge_count; i++) {
                        auto attempt = 0;
                        unordered_sector_set attempted_sectors;
                        while (true) {
                            const auto c = derive_challenge(seed, i, attempt, sector_size, sectors);

                            // check for faulty sector
                            if (!faults.contains(c.sector)) {
                                // valid challenge, not found
                                return {c};
                            } else {
                                attempt += 1;
                                attempted_sectors.insert(c.sector);

                                BOOST_ASSERT_MSG(attempted_sectors.size() < sectors.size(), "all sectors are faulty");
                            }
                        }
                    }
                }
            }    // namespace rational
        }        // namespace post
    }            // namespace filecoin
}    // namespace nil

#endif

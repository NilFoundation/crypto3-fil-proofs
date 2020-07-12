//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020 Gokuyun Moscow Algorithm Lab
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

#ifndef FILECOIN_STORAGE_PROOFS_POST_FALLBACK_VANILLA_HPP
#define FILECOIN_STORAGE_PROOFS_POST_FALLBACK_VANILLA_HPP

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/filecoin/storage/proofs/core/parameter_cache.hpp>
#include <nil/filecoin/storage/proofs/core/sector.hpp>
#include <nil/filecoin/storage/proofs/core/proof/proof.hpp>

namespace nil {
    namespace filecoin {
        namespace post {
            namespace fallback {
                struct SetupParams {
                    /// Size of the sector in bytes.
                    std::uint64_t sector_size;
                    /// Number of challenges per sector.
                    std::size_t challenge_count;
                    /// Number of challenged sectors.
                    std::size_t sector_count;
                };

                struct PublicParams : public parameter_set_metadata {
                    virtual std::string identifier() const override {
                        return std::string("FallbackPoSt::PublicParams{{sector_size: ") +
                               std::to_string(sector_size()) + ", challenge_count: " + std::to_string(challenge_count) +
                               " , sector_count: " + std::to_string(sector_count) + "}}";
                    }
                    virtual size_t sector_size() const override {
                        return ssize;
                    }

                    /// Size of the sector in bytes.
                    std::uint64_t ssize;
                    /// Number of challenges per sector.
                    std::size_t challenge_count;
                    /// Number of challenged sectors.
                    std::size_t sector_count;
                };

                struct ChallengeRequirements {
                    /// The sum of challenges across all challenged sectors. (even across partitions)
                    std::size_t minimum_challenge_count;
                };

                template<typename Domain>
                struct PublicSector {
                    sector_id_type id;
                    Domain comm_r;
                };

                template<typename Domain>
                struct PublicInputs {
                    Domain randomness;
                    Domain prover_id;
                    std::vector<PublicSector<Domain>> sectors;
                    /// Partition index
                    std::size_t k;
                };

                template<typename MerkleTreeType>
                struct PrivateSector {
                    MerkleTreeWrapper<typename MerkleTreeType::hash_type, MerkleTreeType::Store, MerkleTreeType::Arity,
                                      MerkleTreeType::SubTreeArity, MerkleTreeType::TopTreeArity>
                        tree;
                    typename MerkleTreeType::hash_type::digest_type comm_c;
                    typename MerkleTreeType::hash_type::digest_type comm_r_last;
                };

                template<typename MerkleTreeType>
                struct PrivateInputs {
                    std::vector<PrivateSector<MerkleTreeType>> sectors;
                };

                template<typename MerkleProofType>
                struct SectorProof {
                    std::vector<typename MerkleProofType::hash_type::digest_type> leafs() {
                        return inclusion_proofs.iter().map(MerkleProofTrait::leaf).collect();
                    }

                    typename MerkleProofType::hash_type::digest_type comm_r_last() {
                        return inclusion_proofs[0].root();
                    }

                    std::vector<typename MerkleProofType::hash_type::digest_type> commitments() {
                        return inclusion_proofs.iter().map(MerkleProofTrait::root).collect();
                    }

                    std::vector<std::vector<
                        std::pair<std::vector<typename MerkleProofType::hash_type::digest_type>, std::size_t>>>
                        paths() {
                        return inclusion_proofs.iter().map(MerkleProofTrait::path).collect();
                    }

                    std::vector<std::vector<std::pair<std::vector<Fr>, std::size_t>>> as_options() {
                        return inclusion_proofs.iter().map(MerkleProofTrait::as_options).collect();
                    }

                    std::vector<MerkleProof<typename MerkleProofType::hash_type, MerkleProofType::Arity,
                                            MerkleProofType::SubTreeArity, MerkleProofType::TopTreeArity>>
                        inclusion_proofs;
                    typename MerkleProofType::hash_type::digest_type comm_c;
                    typename MerkleProofType::hash_type::digest_type comm_r_last;
                };

                template<typename MerkleProofType>
                struct Proof {
                    std::vector<SectorProof<MerkleProofType>> sectors;
                };

                template<typename MerkleTreeType>
                class FallbackPoSt
                    : public proof_scheme<PublicParams, SetupParams,
                                          PublicInputs<typename MerkleTreeType::hash_type::digest_type>,
                                          PrivateInputs<MerkleTreeType>, Proof<typename MerkleTreeType::proof_type>,
                                          ChallengeRequirements> {
                    typedef proof_scheme<PublicParams, SetupParams,
                                         PublicInputs<typename MerkleTreeType::hash_type::digest_type>,
                                         PrivateInputs<MerkleTreeType>, Proof<typename MerkleTreeType::proof_type>,
                                         ChallengeRequirements>
                        policy_type;

                public:
                    typedef typename policy_type::public_params_type public_params_type;
                    typedef typename policy_type::setup_params setup_params_type;
                    typedef typename policy_type::public_inputs public_inputs_type;
                    typedef typename policy_type::private_inputs private_inputs_type;
                    typedef typename policy_type::proof_type proof_type;
                    typedef typename policy_type::requirements_type requirements_type;

                    virtual public_params_type setup(const setup_params_type &p) override {
                        return {p.sector_size, p.challenge_count, p.sector_count};
                    }

                    std::vector<proof_type> prove_all_partitions(const public_params_type &pub_params,
                                                                 const public_inputs_type &pub_inputs,
                                                                 const private_inputs_type &priv_inputs,
                                                                 std::size_t partition_count) {
                        assert(("inconsistent number of private and public sectors",
                                priv_inputs.sectors.size() == pub_inputs.sectors.size()));

                        std::size_t num_sectors_per_chunk = pub_params.sector_count;
                        std::size_t num_sectors = pub_inputs.sectors.size();

                        assert(("cannot prove the provided number of sectors:",
                                num_sectors <= partition_count * num_sectors_per_chunk));

                        std::vector<proof_type> partition_proofs;

                        for ((j, (pub_sectors_chunk, priv_sectors_chunk)) :
                             pub_inputs.sectors.chunks(num_sectors_per_chunk)
                                 .zip(priv_inputs.sectors.chunks(num_sectors_per_chunk))
                                 .enumerate()) {
                            trace !("proving partition {}", j);

                            std::vector<proof_type> proofs(num_sectors_per_chunk);

                            for ((i, (pub_sector, priv_sector)) :
                                 pub_sectors_chunk.iter().zip(priv_sectors_chunk.iter()).enumerate()) {
                                let tree = priv_sector.tree;
                                let sector_id = pub_sector.id;
                                let tree_leafs = tree.leafs();

                                trace !("Generating proof for tree leafs {} and arity {}", tree_leafs,
                                        Tree::Arity::to_usize(), );

                                let inclusion_proofs =
                                    (0..pub_params.challenge_count)
                                        .into_par_iter()
                                        .map(| n |
                                             {
                                                 let challenge_index =
                                                     ((j * num_sectors_per_chunk + i) * pub_params.challenge_count + n)
                                                         as u64;
                                                 let challenged_leaf_start =
                                                     generate_leaf_challenge(pub_params, pub_inputs.randomness,
                                                                             sector_id.into(), challenge_index, ) ?
                                                     ;

                                                 tree.gen_cached_proof(challenged_leaf_start as usize, None)
                                             })
                                        .collect::<Result<Vec<_>>>() ?
                                    ;

                                proofs.push_back({inclusion_proofs, priv_sector.comm_c, priv_sector.comm_r_last});
                            }

                            // If there were less than the required number of sectors provided, we duplicate the
                            // last one to pad the proof out, such that it works in the circuit part.
                            while (proofs.size() < num_sectors_per_chunk) {
                                proofs.push(proofs[proofs.len() - 1].clone());
                            }

                            partition_proofs.push_back({proofs});
                        }

                        return partition_proofs;
                    }

                    bool verify_all_partitions(const public_params_type &pub_params,
                                               const public_inputs_type &pub_inputs,
                                               const std::vector < proof_type & partition_proofs) {
                        std::size_t challenge_count = pub_params.challenge_count;
                        std::size_t num_sectors_per_chunk = pub_params.sector_count;
                        std::size_t num_sectors = pub_inputs.sectors.size();

                        assert(("inconsistent number of sectors",
                                num_sectors <= num_sectors_per_chunk * partition_proofs.size()));

                        for ((j, (proof, pub_sectors_chunk)) :
                             partition_proofs.iter()
                                 .zip(pub_inputs.sectors.chunks(num_sectors_per_chunk))
                                 .enumerate()) {
                            assert(("inconsistent number of public sectors",
                                    pub_sectors_chunk.size() <= num_sectors_per_chunk));
                            assert(("invalid number of sectors in the partition proof",
                                    proof.sectors.size() == num_sectors_per_chunk));
                            for ((i, (pub_sector, sector_proof)) :
                                 pub_sectors_chunk.iter().zip(proof.sectors.iter()).enumerate()) {
                                let sector_id = pub_sector.id;
                                let comm_r = &pub_sector.comm_r;
                                let comm_c = sector_proof.comm_c;
                                let inclusion_proofs = &sector_proof.inclusion_proofs;

                                // Verify that H(Comm_c || Comm_r_last) == Comm_R

                                // comm_r_last is the root of the proof
                                let comm_r_last = inclusion_proofs[0].root();

                                if AsRef
                                    ::<[u8]>::as_ref(&<Tree::Hasher as Hasher>::Function::hash2(
                                        &comm_c, &comm_r_last, )) != AsRef::<[u8]>::as_ref(comm_r) { return Ok(false); }

                                        ensure !(challenge_count == inclusion_proofs.len(),
                                                 "unexpected umber of inclusion proofs: {} != {}",
                                                 challenge_count,
                                                 inclusion_proofs.len());

                                for ((n, inclusion_proof) : inclusion_proofs.iter().enumerate()) {
                                    let challenge_index =
                                        ((j * num_sectors_per_chunk + i) * pub_params.challenge_count + n) as u64;
                                    let challenged_leaf_start = generate_leaf_challenge(
                                        pub_params, pub_inputs.randomness, sector_id.into(), challenge_index, ) ?
                                        ;

                                    // validate all comm_r_lasts match
                                    if (inclusion_proof.root() != comm_r_last) {
                                        return false;
                                    }

                                    // validate the path length
                                    let expected_path_length =
                                        inclusion_proof.expected_len(pub_params.sector_size as usize / NODE_SIZE);

                                    if (expected_path_length != inclusion_proof.path().size()) {
                                        return false;
                                    }

                                    if (!inclusion_proof.validate(challenged_leaf_start)) {
                                        return false;
                                    }
                                }
                            }
                        }

                        return true;
                    }

                    virtual proof_type prove(const public_params_type &params,
                                             const public_inputs_type &inputs,
                                             const private_inputs_type &pinputs) override {
                        std::vector<proof_type> proofs = prove_all_partitions(params, inputs, pinputs, 1);
                        let k = match pub_inputs.k {
                            None = > 0,
                            Some(k) = > k,
                        };
                        // Because partition proofs require a common setup, the general ProofScheme implementation,
                        // which makes use of `ProofScheme::prove` cannot be used here. Instead, we need to prove all
                        // partitions in one pass, as implemented by `prove_all_partitions` below.
                        assert(("It is a programmer error to call StackedDrg::prove with more than one partition.",
                                k < 1));

                        return proofs[k].to_owned();
                    }

                    bool satisfies_requirements(const public_params_type &public_params,
                                                const requirements_type &requirements, std::size_t partitions) {
                        std::size_t checked = partitions * public_params.sector_count;

                        assert(partitions.checked_mul(public_params.sector_count) == checked);
                        assert(checked.checked_mul(public_params.challenge_count) ==
                               checked * public_params.challenge_count);

                        return checked * public_params.challenge_count >= requirements.minimum_challenge_count;
                    }

                    virtual bool verify(const public_params_type &pub_params,
                                        const public_inputs_type &pub_inputs,
                                        const proof_type &pr) override {
                        return false;
                    }
                };

                template<typename Domain>
                std::vector<std::uint64_t> generate_sector_challenges(Domain randomness, std::size_t challenge_count,
                                                                      std::uint64_t sector_set_len, Domain prover_id) {
                    (0..challenge_count)
                        .map(| n | generate_sector_challenge(randomness, n, sector_set_len, prover_id))
                        .collect();
                }

                /// Generate a single sector challenge.
                template<typename Domain, typename ChallengeHash = crypto3::hashes::sha2<256>>
                std::uint64_t generate_sector_challenge(Domain randomness, std::size_t n, std::uint64_t sector_set_len,
                                                        Domain prover_id) {
                    let mut hasher = Sha256::new ();
                    hasher.input(AsRef::<[u8]>::as_ref(&prover_id));
                    hasher.input(AsRef::<[u8]>::as_ref(&randomness));
                    hasher.input(&n.to_le_bytes()[..]);

                    let hash = hasher.result();

                    let sector_challenge = LittleEndian::read_u64(&hash.as_ref()[..8]);
                    std::uint64_t sector_index = sector_challenge % sector_set_len;

                    return sector_index;
                }

                /// Generates challenge, such that the range fits into the sector.
                template<typename Domain, typename ChallengeHash = crypto3::hashes::sha2<256>>
                std::uint64_t generate_leaf_challenge(const PublicParams &pub_params, const Domain &randomness,
                                                      std::uint64_t sector_id, std::uint64_t leaf_challenge_index) {
                    let mut hasher = Sha256::new ();
                    hasher.input(AsRef::<[u8]>::as_ref(&randomness));
                    hasher.input(&sector_id.to_le_bytes()[..]);
                    hasher.input(&leaf_challenge_index.to_le_bytes()[..]);
                    let hash = hasher.result();

                    let leaf_challenge = LittleEndian::read_u64(&hash.as_ref()[..8]);

                    std::uint64_t challenged_range_index = leaf_challenge % (pub_params.sector_size / NODE_SIZE);

                    return challenged_range_index;
                }

                /// Generate all challenged leaf ranges for a single sector, such that the range fits into the sector.
                template<typename Domain>
                std::vector<std::uint64_t> generate_leaf_challenges(const PublicParams &pub_params,
                                                                    const Domain &randomness, std::uint64_t sector_id,
                                                                    std::size_t challenge_count) {
                    std::vector<std::uint64_t> challenges(challenge_count);

                    for (int leaf_challenge_index = 0; leaf_challenge_index < challenge_count; leaf_challenge_index++) {
                        std::uint64_t challenge =
                            generate_leaf_challenge(pub_params, randomness, sector_id, leaf_challenge_index as u64);
                        challenges.push_back(challenge);
                    }

                    return challenges;
                }
            }    // namespace fallback
        }        // namespace post
    }            // namespace filecoin
}    // namespace nil

#endif
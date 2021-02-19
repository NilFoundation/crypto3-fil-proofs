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

#ifndef FILECOIN_STORAGE_PROOFS_POST_FALLBACK_VANILLA_HPP
#define FILECOIN_STORAGE_PROOFS_POST_FALLBACK_VANILLA_HPP

#include <boost/log/trivial.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/filecoin/storage/proofs/core/parameter_cache.hpp>
#include <nil/filecoin/storage/proofs/core/sector.hpp>
#include <nil/filecoin/storage/proofs/core/proof/proof.hpp>

namespace nil {
    namespace filecoin {
        namespace post {
            namespace fallback {

                /*************************  SetupParams  ***********************************/

                struct SetupParams {
                    /// Size of the sector in bytes.
                    std::uint64_t sector_size;
                    /// Number of challenges per sector.
                    std::size_t challenge_count;
                    /// Number of challenged sectors.
                    std::size_t sector_count;
                };

                /*************************  PublicParams  ***********************************/

                struct PublicParams : public parameter_set_metadata {
                    virtual std::string identifier() const override {
                        return std::string("FallbackPoSt::PublicParams{{sector_size: ") +
                               std::to_string(sector_size()) + ", challenge_count: " + std::to_string(challenge_count) +
                               " , sector_count: " + std::to_string(sector_count) + "}}";
                    }

                    /// Size of the sector in bytes.
                    std::uint64_t sector_size;
                    /// Number of challenges per sector.
                    std::size_t challenge_count;
                    /// Number of challenged sectors.
                    std::size_t sector_count;
                };

                /*************************  ChallengeRequirements  ***********************************/

                struct ChallengeRequirements {
                    /// The sum of challenges across all challenged sectors. (even across partitions)
                    std::size_t minimum_challenge_count;
                };

                /*************************  PublicSector  ***********************************/

                template<typename Domain>
                struct PublicSector {
                    sector_id_type id;
                    Domain comm_r;
                };

                /*************************  PublicInputs  ***********************************/

                template<typename Domain>
                struct PublicInputs {
                    Domain randomness;
                    Domain prover_id;
                    std::vector<PublicSector<Domain>> sectors;
                    /// Partition index
                    std::size_t k;
                };

                /*************************  PrivateSector  ***********************************/

                template<typename MerkleTreeType>
                struct PrivateSector {
                    MerkleTreeWrapper<typename MerkleTreeType::hash_type, MerkleTreeType::Store, MerkleTreeType::base_arity,
                                      MerkleTreeType::sub_tree_arity, MerkleTreeType::top_tree_arity>
                        tree;
                    typename MerkleTreeType::hash_type::digest_type comm_c;
                    typename MerkleTreeType::hash_type::digest_type comm_r_last;
                };

                /*************************  PrivateInputs  ***********************************/

                template<typename MerkleTreeType>
                struct PrivateInputs {
                    std::vector<PrivateSector<MerkleTreeType>> sectors;
                };

                /*************************  SectorProof  ***********************************/

                template<typename MerkleProofType>
                struct SectorProof {
                    std::vector<typename MerkleProofType::hash_type::digest_type> leafs() {
                        return inclusion_proofs.iter().map(BasicMerkleProof::leaf).collect();
                    }

                    typename MerkleProofType::hash_type::digest_type comm_r_last() {
                        return inclusion_proofs[0].root();
                    }

                    std::vector<typename MerkleProofType::hash_type::digest_type> commitments() {
                        return inclusion_proofs.iter().map(BasicMerkleProof::root).collect();
                    }

                    std::vector<std::vector<
                        std::pair<std::vector<typename MerkleProofType::hash_type::digest_type>, std::size_t>>>
                        paths() {
                        return inclusion_proofs.iter().map(BasicMerkleProof::path).collect();
                    }

                    std::vector<std::vector<std::pair<std::vector<Fr>, std::size_t>>> as_options() {
                        return inclusion_proofs.iter().map(BasicMerkleProof::as_options).collect();
                    }

                    std::vector<MerkleProof<typename MerkleProofType::hash_type, MerkleProofType::Arity,
                                            MerkleProofType::SubTreeArity, MerkleProofType::TopTreeArity>>
                        inclusion_proofs;
                    typename MerkleProofType::hash_type::digest_type comm_c;
                    typename MerkleProofType::hash_type::digest_type comm_r_last;
                };

                /*************************  Proof  ***********************************/

                template<typename MerkleProofType>
                struct Proof {
                    std::vector<SectorProof<MerkleProofType>> sectors;
                };

                /*************************  FallbackPoSt  ***********************************/

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

                        BOOST_ASSERT_MSG(priv_inputs.sectors.size() == pub_inputs.sectors.size(), 
                            "inconsistent number of private and public sectors");

                        std::size_t num_sectors_per_chunk = pub_params.sector_count;
                        std::size_t num_sectors = pub_inputs.sectors.size();

                        BOOST_ASSERT_MSG(num_sectors <= partition_count * num_sectors_per_chunk, 
                            "cannot prove the provided number of sectors:");

                        std::vector<proof_type> partition_proofs;

                        for ((j, (pub_sectors_chunk, priv_sectors_chunk)) :
                             pub_inputs.sectors.chunks(num_sectors_per_chunk)
                                 .zip(priv_inputs.sectors.chunks(num_sectors_per_chunk))
                                 .enumerate()) {
                            BOOST_LOG_TRIVIAL(trace) << std::format("proving partition {}", j);

                            std::vector<proof_type> proofs(num_sectors_per_chunk);

                            for ((i, (pub_sector, priv_sector)) :
                                 pub_sectors_chunk.iter().zip(priv_sectors_chunk.iter()).enumerate()) {
                                const auto tree = priv_sector.tree;
                                const auto sector_id = pub_sector.id;
                                const auto tree_leafs = tree.leafs();

                                BOOST_LOG_TRIVIAL(trace) << std::format("Generating proof for tree leafs {} and arity {}", tree_leafs,
                                        MerkleTreeType::base_arity);

                                const auto inclusion_proofs =
                                    (0..pub_params.challenge_count)
                                        .into_par_iter()
                                        .map(| n |
                                             {
                                                 const auto challenge_index =
                                                     ((j * num_sectors_per_chunk + i) * pub_params.challenge_count + n)
                                                         as u64;
                                                 const auto challenged_leaf_start =
                                                     generate_leaf_challenge(pub_params, pub_inputs.randomness,
                                                                             sector_id.into(), challenge_index);

                                                 tree.gen_cached_proof(challenged_leaf_start as usize, None)
                                             })
                                        .collect::<Result<Vec<_>>>();

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
                                               const std::vector < proof_type> & partition_proofs) {
                        std::size_t challenge_count = pub_params.challenge_count;
                        std::size_t num_sectors_per_chunk = pub_params.sector_count;
                        std::size_t num_sectors = pub_inputs.sectors.size();

                        BOOST_ASSERT_MSG(num_sectors <= num_sectors_per_chunk * partition_proofs.size(), 
                            "inconsistent number of sectors");

                        for ((j, (proof, pub_sectors_chunk)) :
                             partition_proofs.iter()
                                 .zip(pub_inputs.sectors.chunks(num_sectors_per_chunk))
                                 .enumerate()) {
                            BOOST_ASSERT_MSG(pub_sectors_chunk.size() <= num_sectors_per_chunk, 
                                "inconsistent number of public sectors");
                            BOOST_ASSERT_MSG(proof.sectors.size() == num_sectors_per_chunk, 
                                "invalid number of sectors in the partition proof");
                            for ((i, (pub_sector, sector_proof)) :
                                 pub_sectors_chunk.iter().zip(proof.sectors.iter()).enumerate()) {
                                const auto sector_id = pub_sector.id;
                                const auto comm_r = &pub_sector.comm_r;
                                const auto comm_c = sector_proof.comm_c;
                                const auto inclusion_proofs = &sector_proof.inclusion_proofs;

                                // Verify that H(Comm_c || Comm_r_last) == Comm_R

                                // comm_r_last is the root of the proof
                                const auto comm_r_last = inclusion_proofs[0].root();

                                if (AsRef ::<[u8]>::as_ref(&<typename MerkleTreeType::hash_type>::Function::hash2(
                                        &comm_c, &comm_r_last, )) != AsRef::<[u8]>::as_ref(comm_r)) {
                                    return false;
                                }

                                ensure !(challenge_count == inclusion_proofs.len(),
                                         "unexpected umber of inclusion proofs: {} != {}",
                                         challenge_count,
                                         inclusion_proofs.len());

                                for (std::size_t n = 0, inclusion_proofs::iterator inclusion_proof = inclusion_proofs.begin(); 
                                    inclusion_proof != inclusion_proofs.end(); ++n, ++inclusion_proof) {

                                    const auto challenge_index =
                                        ((j * num_sectors_per_chunk + i) * pub_params.challenge_count + n) as u64;
                                    const auto challenged_leaf_start = generate_leaf_challenge(
                                        pub_params, pub_inputs.randomness, sector_id.into(), challenge_index);

                                    // validate all comm_r_lasts match
                                    if ((*inclusion_proof).root() != comm_r_last) {
                                        return false;
                                    }

                                    // validate the path length
                                    const auto expected_path_length =
                                        (*inclusion_proof).expected_len(pub_params.sector_size as usize / NODE_SIZE);

                                    if (expected_path_length != (*inclusion_proof).path().size()) {
                                        return false;
                                    }

                                    if (!(*inclusion_proof).validate(challenged_leaf_start)) {
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
                        auto k;
                        switch (pub_inputs.k) {
                            case None:
                                k = 0;
                                break;
                            case Some(k):
                                k = k;
                                break;
                        };
                        // Because partition proofs require a common setup, the general ProofScheme implementation,
                        // which makes use of `ProofScheme::prove` cannot be used here. Instead, we need to prove all
                        // partitions in one pass, as implemented by `prove_all_partitions` below.
                        BOOST_ASSERT_MSG(k < 1, "It is a programmer error to call StackedDrg::prove with more than one partition.");

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

                /*************************  ???  ***********************************/

                template<typename Domain>
                std::vector<std::uint64_t> generate_sector_challenges(Domain randomness, std::size_t challenge_count,
                                                                      std::uint64_t sector_set_len, Domain prover_id) {

                    std::vector<std::uint64_t> result;
                    result.reserve(challenge_count);

                    for (std::size_t n = 0; n < challenge_count; ++n){
                        result.push(generate_sector_challenge(randomness, n, sector_set_len, prover_id));
                    }
                }
                
                /// Generate a single sector challenge.
                template<typename Domain, typename ChallengeHash = crypto3::hashes::sha2<256>>
                std::uint64_t generate_sector_challenge(Domain randomness, std::size_t n, std::uint64_t sector_set_len,
                                                        Domain prover_id) {
                    auto hasher = Sha256();
                    hasher.input(AsRef::<[u8]>::as_ref(&prover_id));
                    hasher.input(AsRef::<[u8]>::as_ref(&randomness));
                    hasher.input(&n.to_le_bytes()[..]);

                    const auto hash = hasher.result();

                    const auto sector_challenge = LittleEndian::read_u64(&hash[..8]);
                    std::uint64_t sector_index = sector_challenge % sector_set_len;

                    return sector_index;
                }

                /// Generates challenge, such that the range fits into the sector.
                template<typename Domain, typename ChallengeHash = crypto3::hashes::sha2<256>>
                std::uint64_t generate_leaf_challenge(const PublicParams &pub_params, const Domain &randomness,
                                                      std::uint64_t sector_id, std::uint64_t leaf_challenge_index) {
                    auto hasher = Sha256();
                    hasher.input(AsRef::<[u8]>::as_ref(&randomness));
                    hasher.input(&sector_id.to_le_bytes()[..]);
                    hasher.input(&leaf_challenge_index.to_le_bytes()[..]);
                    const auto hash = hasher.result();

                    const auto leaf_challenge = LittleEndian::read_u64(&hash[..8]);

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

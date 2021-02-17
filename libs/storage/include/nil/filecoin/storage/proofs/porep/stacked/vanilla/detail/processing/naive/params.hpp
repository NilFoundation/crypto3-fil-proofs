//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_PROCESSING_NAIVE_PARAMS_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_PROCESSING_NAIVE_PARAMS_HPP

#include <array>
#include <string>

#include <boost/filesystem/path.hpp>
#include <boost/log/trivial.hpp>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/challenges.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/column_proof.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/labelling_proof.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/encoding_proof.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/params.hpp>

#include <nil/filecoin/storage/proofs/core/merkle/proof.hpp>
#include <nil/filecoin/storage/proofs/core/merkle/builders.hpp>

namespace nil {
    namespace filecoin {
        namespace stacked {
            namespace vanilla {
                namespace detail {
                    namespace processing {
                        namespace naive {

                            /*************************  Proof naive processing  ***********************************/

                            template<typename MerkleTreeType, typename Hash>
                            typename tree_hash_type::digest_type Proof_comm_r_last(Proof<MerkleTreeType, Hash> &proof) {
                                return proof.comm_r_last_proof.root();
                            }

                            template<typename MerkleTreeType, typename Hash>
                            typename tree_hash_type::digest_type Proof_comm_c(Proof<MerkleTreeType, Hash> &proof) {
                                return proof.replica_column_proofs.c_x.root();
                            }

                            /// Verify the full proof.
                            template<typename MerkleTreeType, typename Hash>
                            bool Proof_verify(Proof<MerkleTreeType, Hash> &proof, const PublicParams<MerkleTreeType> &pub_params,
                                        const PublicInputs<typename tree_hash_type::digest_type,
                                                           typename hash_type::digest_type> &pub_inputs,
                                        std::size_t challenge, const StackedBucketGraph<tree_hash_type> &graph) {

                                typename MerkleTreeType::hash_type::digest_type replica_id = pub_inputs.replica_id;

                                bool result = challenge < graph.size() && pub_inputs.tau.is_some();

                                // Verify initial data layer
                                BOOST_LOG_TRIVIAL(trace) << "verify initial data layer";

                                result |= proof.comm_d_proofs.proves_challenge(challenge);

                                if (pub_inputs.tau) {
                                    assert(proof.comm_d_proofs.root() == pub_inputs.tau.comm_d);
                                } else {
                                    return false;
                                }

                                // Verify replica column openings
                                BOOST_LOG_TRIVIAL(trace) << "verify replica column openings";
                                std::vector<std::uint32_t> parents(graph.degree());
                                graph.parents(challenge, parents);    // FIXME: error handling
                                assert(naive::ReplicaColumnProof_verify(proof.replica_column_proofs, challenge, parents));
                                assert(naive::Proof_verify_final_replica_layer(proof, challenge));
                                assert(naive::Proof_verify_labels(proof, replica_id, pub_params.layer_challenges));

                                BOOST_LOG_TRIVIAL(trace) << "verify encoding";

                                assert(proof.encoding_proof.template verify<Hash>(replica_id, proof.comm_r_last_proof.leaf(),
                                                                            proof.comm_d_proofs.leaf()));

                                return result;
                            }

                            /// Verify all labels.
                            template<typename MerkleTreeType, typename Hash>
                            bool Proof_verify_labels(Proof<MerkleTreeType, Hash> &proof, const typename tree_hash_type::digest_type &replica_id,
                                               const LayerChallenges &layer_challenges) {
                                // Verify Labels Layer 1..layers
                                for (std::size_t layer = 1; layer < layer_challenges.layers; layer++) {
                                    BOOST_LOG_TRIVIAL(trace) << std::format("verify labeling (layer: %d)", layer);

                                    assert(proof.labeling_proofs.get(layer - 1).is_some());
                                    LabellingProof<typename MerkleTreeType::hash_type> labeling_proof =
                                        proof.labeling_proofs.get(layer - 1);
                                    const auto labeled_node = proof.replica_column_proofs.c_x.get_node_at_layer(layer);
                                    assert(naive::LabelingProof_verify(labeling_proof, replica_id, labeled_node));
                                }

                                return true;
                            }

                            /// Verify final replica layer openings
                            template<typename MerkleTreeType, typename Hash>
                            bool Proof_verify_final_replica_layer(Proof<MerkleTreeType, Hash> &proof, std::size_t challenge) {
                                BOOST_LOG_TRIVIAL(trace) << "verify final replica layer openings";
                                assert(proof.comm_r_last_proof.proves_challenge(challenge));

                                return true;
                            }

                            /*************************  ReplicaColumnProof naive processing  ***********************************/

                            template<MerkleProofType, typename InputParentsRange>
                                typename std::enable_if<
                                std::is_same<typename std::iterator_traits<typename InputParentsRange::iterator>::value_type,
                                             std::uint32_t>::value, bool>::type
                                ReplicaColumnProof_verify(ReplicaColumnProof<MerkleTreeType, Hash> &replica_column_proof, 
                                    std::size_t challenge, const InputParentsRange &parents) {

                                typename MerkleProofType::tree_type::hash_type::digest_type expected_comm_c = c_x.root();

                                BOOST_LOG_TRIVIAL(trace) << "  verify c_x";
                                BOOST_ASSERT(naive::???_verify(c_x, challenge, &expected_comm_c));

                                BOOST_LOG_TRIVIAL(trace) << "  verify drg_parents";

                                for (drg_parents::iterator proof = replica_column_proof.drg_parents.begin(), 
                                    parents::iterator parent = parents.begin();
                                    proof != replica_column_proof.drg_parents.end() || parent != parents.end();
                                    ++proof, ++parent) {
                                    BOOST_ASSERT_MSG(naive::???_verify(proof, parent, expected_comm_c));
                                }

                                BOOST_LOG_TRIVIAL(trace) << "  verify exp_parents";

                                for (drg_parents::iterator proof = replica_column_proof.exp_parents.begin() + drg_parents.size(), 
                                    parents::iterator parent = parents.begin() + drg_parents.size();
                                    proof != replica_column_proof.exp_parents.end() || parent != parents.end();
                                    ++proof, ++parent) {
                                    BOOST_ASSERT_MSG(naive::???_verify(proof, parent, expected_comm_c));
                                }
                            }
                        }    // namespace naive
                    }    // namespace processing
                }    // namespace detail
            }    // namespace vanilla
        }        // namespace stacked
    }            // namespace filecoin
}    // namespace nil

#endif // FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_PROCESSING_NAIVE_PARAMS_HPP

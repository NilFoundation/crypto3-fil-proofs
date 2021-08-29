//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nemo@nil.foundation>

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

#ifndef FILECOIN_STORAGE_PROOFS_POST_FALLBACK_CIRCUIT_HPP
#define FILECOIN_STORAGE_PROOFS_POST_FALLBACK_CIRCUIT_HPP

#include <nil/filecoin/storage/proofs/core/components/por.hpp>

#include <nil/filecoin/storage/proofs/post/fallback/vanilla.hpp>

namespace nil {
    namespace filecoin {
        namespace post {
            namespace fallback {
                template<typename MerkleTreeType>
                struct Sector {
                    Sector(const PublicSector<typename MerkleTreeType::hash_type::digest_type> &sector,
                           const SectorProof<typename MerkleTreeType::proof_type> &vanilla_proof) :
                        leafs(vanilla_proof.leafs()),
                        id(sector.id), comm_r(sector.comm_r), comm_c(vanilla_proof.comm_c),
                        comm_r_last(vanilla_proof.comm_r_last) {
                        paths = vanilla_proof.as_options().into_iter().map(Into::into).collect();
                    }

                    Sector(const PublicParams &pub_params) {
                        std::size_t challenges_count = pub_params.challenge_count;
                        std::size_t leaves = pub_params.sector_size / NODE_SIZE;

                        por::PublicParams por_params = {leaves, true};
                        std::vector<Fr> leafs(challenges_count);
                        std::vector<AuthPath<typename MerkleTreeType::hash_type,
                                             MerkleTreeType::base_arity,
                                             MerkleTreeType::sub_tree_arity,
                                             MerkleTreeType::top_tree_arity>>
                            paths(challenges_count,
                                  AuthPath<typename MerkleTreeType::hash_type,
                                           MerkleTreeType::base_arity,
                                           MerkleTreeType::sub_tree_arity,
                                           MerkleTreeType::top_tree_arity>(por_params.leaves));

                        return Sector {
                        id:
                            None, comm_r : None, comm_c : None, comm_r_last : None, leafs, paths,
                        }
                    }

                    Fr comm_r;
                    Fr comm_c;
                    Fr comm_r_last;
                    std::vector<Fr> leafs;
                    std::vector<AuthPath<typename MerkleTreeType::hash_type,
                                         MerkleTreeType::base_arity,
                                         MerkleTreeType::sub_tree_arity,
                                         MerkleTreeType::top_tree_arity>>
                        paths;
                    Fr id;
                };

                template<typename MerkleTreeType>
                struct FallbackPoStCircuit {
                    Fr prover_id;
                    std::vector<Sector<MerkleTreeType>> sectors;
                };
            }    // namespace fallback
        }        // namespace post
    }            // namespace filecoin
}    // namespace nil

#endif

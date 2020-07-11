//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef FILECOIN_STORAGE_PROOFS_POST_FALLBACK_CIRCUIT_HPP
#define FILECOIN_STORAGE_PROOFS_POST_FALLBACK_CIRCUIT_HPP

#include <nil/filecoin/storage/proofs/core/gadgets/por.hpp>

namespace nil {
    namespace filecoin {
        namespace post {
            namespace fallback {
                template<typename MerkleTreeType>
                struct Sector {
                    Fr comm_r;
                    Fr comm_c;
                    Fr comm_r_last std::vector<Fr> leafs;
                    std::vector<AuthPath<typename MerkleTreeType::hash_type, MerkleTreeType::Arity,
                                         MerkleTreeType::SubTreeArity, MerkleTreeType::TopTreeArity>>
                        paths;
                    Fr id;
                }

                template<typename MerkleTreeType>
                struct FallbackPoStCircuit {
                    Fr prover_id;
                    std::vector < Sector<MerkleTreeType> sectors;
                };
            }    // namespace fallback
        }        // namespace post
    }            // namespace filecoin
}    // namespace nil

#endif
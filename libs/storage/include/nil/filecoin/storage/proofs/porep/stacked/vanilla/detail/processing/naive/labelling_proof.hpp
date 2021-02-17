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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_PROCESSING_NAIVE_LABELING_PROOF_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_PROCESSING_NAIVE_LABELING_PROOF_HPP

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/labelling_proof.hpp>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

namespace nil {
    namespace filecoin {
        namespace stacked {
            namespace vanilla {
                namespace detail {

                    /*************************  LabelingProof naive processing  ***********************************/

                    template<ParentsHash, typename LabelHash = hashes::sha2<256>>
                        typename ParentsHash::digest_type LabelingProof_naive_create_label(
                            template<ParentsHash> LabelingProof &labeling_proof, 
                            const typename ParentsHash::digest_type &replica_id) {

                        using namespace nil::crypto3;

                        accumulator_set<LabelHash> acc;

                        hash<LabelHash>(replica_id, acc);
                        hash<LabelHash>(labeling_proof.layer_index, acc);
                        hash<LabelHash>(labeling_proof.node, acc);
                        hash<LabelHash>(labeling_proof.parents, acc);

                        return accumulators::extract::hash<LabelHash>(acc);
                    }

                    template<typename ParentsHash>
                    bool LabelingProof_naive_verify(template<ParentsHash> LabelingProof &labeling_proof, 
                                                    const typename ParentsHash::digest_type &replica_id,
                                                    const typename ParentsHash::digest_type &expected_label) {

                        typename ParentsHash::digest_type label = 
                            LabelingProof_naive_create_label(labeling_proof, replica_id);
                        return (expected_label == label);
                    }

                }    // namespace detail
            }    // namespace vanilla
        }        // namespace stacked
    }            // namespace filecoin
}    // namespace nil

#endif // FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_PROCESSING_NAIVE_LABELING_PROOF_HPP

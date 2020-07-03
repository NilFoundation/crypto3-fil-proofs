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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_LABELING_PROOF_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_LABELING_PROOF_HPP

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

namespace nil {
    namespace filecoin {
        namespace stacked {
            namespace vanilla {
                template<typename Hash>
                struct LabelingProof {
                    typedef Hash hash_type;

                    template<typename LabelHash = crypto3::hash::sha2<256>>
                    typename Hash::digest_type create_label(const typename Hash::digest_type &replica_id) {
                        using namespace nil::crypto3::hash;

                        accumulator_set<LabelHash> acc;

                        hash<LabelHash>(replica_id, acc);
                        hash<LabelHash>({layer_index}, acc);
                        hash<LabelHash>({node}, acc);
                        hash<LabelHash>(parents, acc);

                        return crypto3::accumulators::extract<LabelHash>(acc);
                    }

                    bool verify(const typename Hash::digest_type &replica_id,
                                const typename Hash::digest_type &expected_label) {
                        typename Hash::digest_type label = create_label(replica_id);
                        return expected_label == label;
                    }

                    typename Hash::digest_type parents;
                    std::uint32_t layer_index;
                    std::uint64_t node;
                };
            }    // namespace vanilla
        }        // namespace stacked
    }            // namespace filecoin
}    // namespace nil

#endif
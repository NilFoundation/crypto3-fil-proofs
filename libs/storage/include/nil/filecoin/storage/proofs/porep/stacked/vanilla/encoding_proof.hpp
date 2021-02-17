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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_ENCODING_PROOF_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_ENCODING_PROOF_HPP

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

namespace nil {
    namespace filecoin {
        namespace stacked {
            namespace vanilla {
                template<typename Hash>
                struct EncodingProof {
                    typedef Hash hash_type;

                    template<typename KeyHash = hashes::sha2<256>>
                    typename hash_type::digest_type create_key(const typename hash_type::digest_type &replica_id) {
                        using namespace nil::crypto3;

                        accumulator_set<KeyHash> acc;

                        hash<KeyHash>(replica_id, acc);
                        hash<KeyHash>({layer_index}, acc);
                        hash<KeyHash>({node}, acc);
                        hash<KeyHash>(parents, acc);

                        return accumulators::extract::hash<KeyHash>(acc);
                    }

                    template<typename VerifyingHash>
                    bool verify(const typename hash_type::digest_type &replica_id,
                                const typename hash_type::digest_type &exp_encoded_node,
                                const typename VerifyingHash::digest_type &decoded_node) {
                        const auto key = create_key(replica_id);

                        const auto fr : Fr = (*decoded_node).into();
                        const auto encoded_node = encode(key, fr.into());

                        return exp_encoded_node == encoded_node;
                    }

                    std::vector<typename hash_type::digest_type> parents;
                    std::uint32_t layer_index;
                    std::uint64_t node;
                };
            }    // namespace vanilla
        }        // namespace stacked
    }            // namespace filecoin
}    // namespace nil

#endif

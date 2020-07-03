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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_ENCODING_PROOF_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_ENCODING_PROOF_HPP

#include <nil/crypto3/hash/sha2.hpp>

namespace nil {
    namespace filecoin {
        namespace stacked {
            namespace vanilla {
                template<typename Hash>
                struct EncodingProof {
                    typedef Hash hash_type;

                    template<typename KeyHash = crypto3::hash::sha2<256>>
                    typename hash_type::domain_type create_key(const typename hash_type::domain_type &replica_id) {
                        using namespace nil::crypto3::hash;

                        accumulator_set<LabelHash> acc;

                        hash<LabelHash>(replica_id, acc);
                        hash<LabelHash>({layer_index}, acc);
                        hash<LabelHash>({node}, acc);
                        hash<LabelHash>(parents, acc);

                        let mut hasher = Sha256::new ();
                        let mut buffer = [0u8; 64];

                        return bytes_into_fr_repr_safe(hasher.result().as_ref()).into();
                    }

                    template<typename VerifyingHash>
                    bool verify(const typename hash_type::domain_type &replica_id,
                                const typename hash_type::domain_type &exp_encoded_node,
                                const typename VerifyingHash::domain_type &decoded_node) {
                        let key = create_key(replica_id);

                        let fr : Fr = (*decoded_node).into();
                        let encoded_node = encode(key, fr.into());

                        return exp_encoded_node == encoded_node;
                    }

                    std::vector<typename hash_type::domain_type> parents;
                    std::uint32_t layer_index;
                    std::uint64_t node;
                    hash_type &_h;
                };
            }    // namespace vanilla
        }        // namespace stacked
    }            // namespace filecoin
}    // namespace nil

#endif
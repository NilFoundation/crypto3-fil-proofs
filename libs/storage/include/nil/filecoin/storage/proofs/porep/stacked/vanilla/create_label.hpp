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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_CREATE_LABEL_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_CREATE_LABEL_HPP

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/detail/pack.hpp>

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/cache.hpp>

namespace nil {
    namespace filecoin {
        namespace stacked {
            namespace vanilla {
                template<template<typename> class StackedBucketGraph, typename GraphHash,
                         typename LabelHash = hashes::sha2<256>>
                void create_label(const StackedBucketGraph<GraphHash> &graph, ParentCache &cache,
                                  const typename GraphHash::digest_type &replica_id,
                                  std::vector<std::uint8_t> &layer_labels, std::uint32_t layer_index,
                                  std::uint64_t node) {
                    using namespace nil::crypto3;

                    std::array<std::uint8_t, 12> buffer;
                    buffer.fill(0);

                    crypto3::detail::pack({layer_index}, buffer);
                    crypto3::detail::pack({node}, buffer);

                    accumulator_set<LabelHash> acc;

                    hash<LabelHash>(buffer, acc);
                    hash<LabelHash>(replica_id, acc);

                    // hash parents for all non 0 nodes
                    typename LabelHash::digest_type hash;
                    if (node > 0) {
                        // prefetch previous node, which is always a parent
                        const auto prev = &layer_labels[(node - 1) * NODE_SIZE..node * NODE_SIZE];
                        _mm_prefetch(prev.as_ptr() as *const i8, _MM_HINT_T0);
                        hash = graph.copy_parents_data(node as u32, &*layer_labels, hasher, cache);
                    } else {
                        hash = accumulators::extract::hash<LabelHash>(acc);
                    }

                    // store the newly generated key
                    const auto start = data_at_node_offset(node);
                    const auto end = start + NODE_SIZE;
                    layer_labels[start..end].copy_from_slice(&hash[..]);

                    // strip last two bits, to ensure result is in Fr.
                    layer_labels[end - 1] &= 0b00111111;
                }

                template<template<typename> class StackedBucketGraph, typename GraphHash,
                         typename LabelHash = hashes::sha2<256>>
                void create_label_exp(const StackedBucketGraph<GraphHash> &graph, ParentCache &cache,
                                      const typename GraphHash::digest_type &replica_id,
                                      const std::vector<std::uint8_t> &exp_parents_data,
                                      std::vector<std::uint8_t> &layer_labels, std::uint32_t layer_index,
                                      std::uint64_t node) {
                    using namespace nil::crypto3;

                    std::array<std::uint8_t, 12> buffer;
                    buffer.fill(0);

                    crypto3::detail::pack({layer_index}, buffer);
                    crypto3::detail::pack({node}, buffer);

                    accumulator_set<LabelHash> acc;

                    hash<LabelHash>(buffer, acc);
                    hash<LabelHash>(replica_id, acc);

                    // hash parents for all non 0 nodes
                    typename LabelHash::digest_type hash;
                    if (node > 0) {
                        // prefetch previous node, which is always a parent
                        const auto prev = &layer_labels[(node - 1) * NODE_SIZE..node * NODE_SIZE];
                        unsafe {
                            _mm_prefetch(prev.as_ptr() as *const i8, _MM_HINT_T0);
                        }

                        hash = graph.copy_parents_data_exp(node, layer_labels, exp_parents_data, hasher, cache);
                    } else {
                        hash = accumulators::extract::hash<LabelHash>(acc);
                    }

                    // store the newly generated key
                    const auto start = data_at_node_offset(node);
                    const auto end = start + NODE_SIZE;
                    layer_labels[start..end].copy_from_slice(&hash[..]);

                    // strip last two bits, to ensure result is in Fr.
                    layer_labels[end - 1] &= 0b00111111;
                }
            }    // namespace vanilla
        }        // namespace stacked
    }            // namespace filecoin
}    // namespace nil

#endif

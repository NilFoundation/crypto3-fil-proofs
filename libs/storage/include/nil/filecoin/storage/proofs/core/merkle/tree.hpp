//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef FILECOIN_STORAGE_PROOFS_CORE_MERKLE_TREE_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_MERKLE_TREE_HPP

#include <map>
#include <vector>
#include <algorithm>
#include <cmath>

#include <nil/crypto3/detail/static_digest.hpp>

namespace nil {
    namespace filecoin {
        template<typename Hash, std::size_t Arity = 2>
        typename Hash::digest_type hash_children_to_one(std::array<const typename Hash::digest_type, Arity> &children) {
            
            constexpr static const std::size_t arity = Arity;
            constexpr static const std::size_t digest_size = Hash::digest_size;

            typename static_digest<Hash::digest_bits * arity> new_input;

            for (std::size_t i = 0; i < arity; ++i){
                assert(children[i].size() == digest_size);
                std::copy (children[i].begin(), children[i].end(), new_input.begin() + i * digest_size);
            }

            return hash<Hash>(new_input);
        }

        /**
         * A Merkle tree is maintained as two maps:
         * - a map from addresses to values, and
         * - a map from addresses to hashes.
         *
         * The second map maintains the intermediate hashes of a Merkle tree
         * built atop the values currently stored in the tree (the
         * implementation admits a very efficient support for sparse
         * trees). Besides offering methods to load and store values, the
         * class offers methods to retrieve the root of the Merkle tree and to
         * obtain the authentication paths for (the value at) a given address.
         */

        typedef std::vector<bool> merkle_authentication_node;

        template<typename Hash, std::size_t Arity = 2>
        struct merkle_tree {
            using hash_type = Hash;
            typedef typename hash_type::digest_type digest_type;

            constexpr static const std::size_t arity = Arity;

            std::vector<digest_type> hash_defaults;
            std::map<std::size_t, std::vector<bool>> values;
            std::map<std::size_t, digest_type> hashes;

            std::size_t depth;
            std::size_t value_size;
            std::size_t digest_size;

            merkle_tree(const std::size_t depth, const std::size_t value_size) :
                depth(depth), value_size(value_size) {
                assert(depth < sizeof(std::size_t) * 8);

                digest_size = hash_type::digest_bits;
                assert(value_size <= digest_size);

                digest_type last;
                hash_defaults.reserve(depth + 1);
                hash_defaults.emplace_back(last);
                for (std::size_t i = 0; i < depth; ++i) {
                    std::array<const typename hash_type::digest_type, Arity> childs_input;
                    input.fil(last);
                    last = hash_children_to_one<hash_type, arity>(childs_input);
                    hash_defaults.emplace_back(last);
                }

                std::reverse(hash_defaults.begin(), hash_defaults.end());
            }
            merkle_tree(const std::size_t depth, const std::size_t value_size,
                        const std::vector<std::vector<bool>> &contents_as_vector) :
                merkle_tree(depth, value_size) {

                assert(static_cast<std::size_t>(std::ceil(std::log2(contents_as_vector.size()))) <= depth);
                for (std::size_t address = 0; address < contents_as_vector.size(); ++address) {
                    const std::size_t idx = address + (1ul << depth) - 1;
                    values[idx] = contents_as_vector[address];
                    hashes[idx] = contents_as_vector[address];
                    hashes[idx].resize(digest_size);
                }

                std::size_t idx_begin = (1ul << depth) - 1;
                std::size_t idx_end = contents_as_vector.size() + ((1ul << depth) - 1);

                for (int layer = depth; layer > 0; --layer) {
                    for (std::size_t idx = idx_begin; idx < idx_end; idx += 2) {
                        digest_type l =
                            hashes[idx];    // this is sound, because idx_begin is always a left child
                        digest_type r = (idx + 1 < idx_end ? hashes[idx + 1] : hash_defaults[layer]);

                        digest_type h = hash_children_to_one<hash_type, arity>(l, r);
                        hashes[(idx - 1) / 2] = h;
                    }

                    idx_begin = (idx_begin - 1) / 2;
                    idx_end = (idx_end - 1) / 2;
                }
            }

            merkle_tree(size_t depth, std::size_t value_size,
                        const std::map<std::size_t, std::vector<bool>> &contents) :
                merkle_tree(depth, value_size) {

                if (!contents.empty()) {
                    assert(contents.rbegin()->first < 1ul << depth);

                    for (const auto &content : contents) {
                        const std::size_t address = content.first;
                        const std::vector<bool> value = content.second;
                        const std::size_t idx = address + (1ul << depth) - 1;

                        values[address] = value;
                        hashes[idx] = value;
                        hashes[idx].resize(digest_size);
                    }

                    auto last_it = hashes.end();

                    for (int layer = depth; layer > 0; --layer) {
                        auto next_last_it = hashes.begin();

                        for (auto it = hashes.begin(); it != last_it; ++it) {
                            const std::size_t idx = it->first;
                            const digest_type hash = it->second;

                            if (idx % 2 == 0) {
                                // this is the right child of its parent and by invariant we are missing the
                                // left child
                                hashes[(idx - 1) / 2] = hash_children_to_one<hash_type, arity>(hash_defaults[layer], hash);
                            } else {
                                if (std::next(it) == last_it || std::next(it)->first != idx + 1) {
                                    // this is the left child of its parent and is missing its right child
                                    hashes[(idx - 1) / 2] = hash_children_to_one<hash_type, arity>(hash, hash_defaults[layer]);
                                } else {
                                    // typical case: this is the left child of the parent and adjacent to it
                                    // there is a right child
                                    hashes[(idx - 1) / 2] = hash_children_to_one<hash_type, arity>(hash, std::next(it)->second);
                                    ++it;
                                }
                            }
                        }

                        last_it = next_last_it;
                    }
                }
            }

            std::vector<bool> get_value(const std::size_t address) const {
                assert(static_cast<std::size_t>(std::ceil(std::log2(address))) <= depth);

                auto it = values.find(address);
                std::vector<bool> padded_result =
                    (it == values.end() ? std::vector<bool>(digest_size) : it->second);
                padded_result.resize(value_size);

                return padded_result;
            }
            void set_value(const std::size_t address, const std::vector<bool> &value) {
                assert(static_cast<std::size_t>(std::ceil(std::log2(address))) <= depth);
                std::size_t idx = address + (1ul << depth) - 1;

                assert(value.size() == value_size);
                values[address] = value;
                hashes[idx] = value;
                hashes[idx].resize(digest_size);

                for (int layer = depth - 1; layer >= 0; --layer) {
                    idx = (idx - 1) / 2;

                    auto it = hashes.find(2 * idx + 1);
                    digest_type l = (it == hashes.end() ? hash_defaults[layer + 1] : it->second);

                    it = hashes.find(2 * idx + 2);
                    digest_type r = (it == hashes.end() ? hash_defaults[layer + 1] : it->second);

                    digest_type h = hash_children_to_one<hash_type, arity>(l, r);
                    hashes[idx] = h;
                }
            }

            digest_type get_root() const {
                auto it = hashes.find(0);
                return (it == hashes.end() ? hash_defaults[0] : it->second);
            }
            
        };

        template <typename MerkleTree>
        std::vector<typename MerkleTree::merkle_authentication_node> make_merkle_tree_path(const MerkleTree mt, 
            const std::size_t address) {

            std::size_t depth = MerkleTree::depth;
            std::size_t arity = MerkleTree::arity;

            std::vector<merkle_authentication_node> result(depth);
            assert(static_cast<std::size_t>(std::ceil(std::log2(address))) <= depth);
            std::size_t idx = address + pow(arity, depth) - 1;

            for (std::size_t layer = depth; layer > 0; --layer) {
                for (std::size_t sibling_idx = idx % arity; sibling_idx < idx % arity + (arity - 1); ++sibling_idx){
                    if (sibling_idx != idx){
                        //std::size_t sibling_idx = ((idx + 1) ^ 1) - 1;

                        auto it = mt.hashes.find(sibling_idx);
                        if (layer == depth) {
                            auto it2 = mt.values.find(sibling_idx - ((1ul << depth) - 1));
                            result[layer - 1] =
                                (it2 == mt.values.end() ? std::vector<bool>(value_size, false) : it2->second);
                            result[layer - 1].resize(digest_size);
                        } else {
                            result[layer - 1] = (it == mt.hashes.end() ? hash_defaults[layer] : it->second);
                        }
                    }
                }

                idx = (idx - 1) / 2;
            }

            return result;
        }

        template <typename MerkleTree>
        MerkleProof<typename MerkleTree::Hash, typename MerkleTree::Arity> generate_proof(const MerkleTree mt, 
            const std::size_t i) {

        }
    }            // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_STORAGE_PROOFS_CORE_MERKLE_TREE_HPP

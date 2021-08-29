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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_UTILITIES_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_UTILITIES_HPP

#include <numeric>
#include <cstdint>
#include <vector>

namespace nil {
    namespace filecoin {
        constexpr static const std::size_t NODE_SIZE = 32;

        /// Returns the start position of the data, 0-indexed.
        std::size_t data_at_node_offset(std::size_t v) {
            return v * NODE_SIZE;
        }

        /// Returns the byte slice representing one node (of uniform size, NODE_SIZE) at position v in data.
        std::vector<std::uint8_t> data_at_node(const std::vector<std::uint8_t> &data, std::size_t v) {
            std::size_t offset = data_at_node_offset(v);

            assert(offset + NODE_SIZE <= data.size());

            return std::vector<std::uint8_t>(data.begin() + offset, data.begin() + offset + NODE_SIZE);
        }

        inline std::uint8_t bool_to_u8(bool bit, std::size_t offset) {
            if (bit) {
                return (std::uint8_t)1 << offset;
            } else {
                return (std::uint8_t)0;
            }
        }

        // If the tree is large enough to use the default value (per-arity), use it.  If it's too small to cache
        // anything (i.e. not enough rows), don't discard any.
        std::size_t default_rows_to_discard(std::size_t leafs, std::size_t arity) {
            std::size_t row_count = get_merkle_tree_row_count(leafs, arity);
            if (row_count <= 2) {
                // If a tree only has a root row and/or base, there is
                // nothing to discard.
                return 0;
            } else if (row_count == 3) {
                // If a tree only has 1 row between the base and root,
                // it's all that can be discarded.
                return 1;
            }

            // row_count - 2 discounts the base layer (1) and root (1)
            std::size_t max_rows_to_discard = row_count - 2;

            // This configurable setting is for a default oct-tree
            // rows_to_discard value, which defaults to 2.
            std::size_t rows_to_discard = settings::SETTINGS.lock().rows_to_discard;

            // Discard at most 'constant value' rows (coded below,
            // differing by arity) while respecting the max number that
            // the tree can support discarding.
            if (arity == 2) {
                return std::min(max_rows_to_discard, 7U);
            } else if (arity == 4) {
                return std::min(max_rows_to_discard, 5U);
            } else {
                return std::min(max_rows_to_discard, rows_to_discard);
            }
        }
    }    // namespace filecoin
}    // namespace nil

#endif

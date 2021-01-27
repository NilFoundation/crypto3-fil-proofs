//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020 Wukong Moscow Algorithm Lab
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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_COLUMN_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_COLUMN_HPP

#include <vector>

namespace nil {
    namespace filecoin {
        namespace stacked {
            namespace vanilla {
                template<typename Hash>
                struct Column {
                    typedef Hash hash_type;

                    Column(std::uint32_t index, const std::vector<typename hash_type::digest_type> &rows) :
                        index(index), rows(rows) {
                    }

                    Column(std::uint32_t index, std::size_t capacity) : index(index), rows(capacity) {
                    }

                    /// Calculate the column hashes `C_i = H(E_i, O_i)` for the passed in column.
                    Fr hash() {
                        return hash_single_column(rows.iter().copied().map(Into::into).collect::<Vec<_>>());
                    }

                    typename Hash::digest_type get_node_at_layer(std::size_t layer) {
                        assert(("layer must be greater than 0", layer > 0));
                        std::size_t row_index = layer - 1;

                        return rows[row_index];
                    }

                    std::uint32_t index;
                    std::vector<typename hash_type::digest_type> rows;
                };
            }    // namespace vanilla
        }        // namespace stacked
    }            // namespace filecoin
}    // namespace nil

#endif

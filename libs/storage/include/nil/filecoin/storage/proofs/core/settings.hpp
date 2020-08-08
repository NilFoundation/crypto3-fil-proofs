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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_SETTINGS_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_SETTINGS_HPP

#include <cstdint>

namespace nil {
    namespace filecoin {
        constexpr static const char *settings_path = "config.ini";

        struct configuration {
            bool maximize_caching = true;
            std::uint32_t pedersen_hash_exp_window_size = 16;
            bool use_gpu_column_builder = false;
            std::uint32_t max_gpu_column_batch_size = 400000;
            std::uint32_t column_write_batch_size = 262144;
            bool use_gpu_tree_builder = false;
            std::uint32_t max_gpu_tree_batch_size = 700000;
            std::uint32_t rows_to_discard = 2;
        };

    }    // namespace filecoin
}    // namespace nil

#endif
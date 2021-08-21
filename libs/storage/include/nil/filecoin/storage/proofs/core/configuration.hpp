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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_SETTINGS_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_SETTINGS_HPP

#include <string>

namespace nil {
    namespace filecoin {
        constexpr static const char *settings_path = "config.ini";

        /// All cache files and directories paths should be constructed using this function,
        /// which its base directory from the FIL_PROOFS_CACHE_DIR env var, and defaults to /var/tmp.
        /// Note that FIL_PROOFS_CACHE_DIR is not a first class setting and can only be set by env var.
        std::string cache(const std::string &s) {
            std::string cache_var = actor::format("{}_CACHE_DIR", PREFIX);
            std::string cache_name = std::getenv(cache_var);
            if (!cache_name) {
                cache_name = "var/tmp";
            }
            return cache_name + s;
        }

        struct configuration {
            bool verify_cache = false;
            bool verify_production_params = false;
            bool use_gpu_column_builder = true;
            std::uint32_t max_gpu_column_batch_size = 400000;
            std::uint32_t column_write_batch_size = 262114;
            bool use_gpu_tree_builder = true;
            std::uint32_t gpu_for_parallel_tree_r = 0;
            std::uint32_t max_gpu_tree_batch_size = 700000;
            std::uint32_t rows_to_discard = 2;
            std::uint32_t sdr_parents_cache_size = 2048;
            std::string parameter_cache = "/var/tmp/filecoin-proof-parameters/";
            std::string parent_cache = cache("filecoin-parents");
            bool use_multicore_sdr = true;
            std::uint32_t multicore_sdr_producers = 3;
            std::uint32_t multicore_sdr_producer_stride = 128;
            std::uint32_t multicore_sdr_lookahead = 800;
        };
    }    // namespace filecoin
}    // namespace nil

#endif

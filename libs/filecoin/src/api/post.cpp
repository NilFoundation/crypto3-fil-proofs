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

#include <nil/filecoin/proofs/api/post.hpp>

namespace nil {
    namespace filecoin {
        PublicReplicaInfo::PublicReplicaInfo(const commitment_type &comm_r) {
            assert(("Invalid all zero commitment (comm_r)",
                    !std::accumulate(comm_r.begin(), comm_r.end(), false,
                                     [&](bool state, typename commitment_type::value_type &v) -> bool {
                                         return state * (v != 0);
                                     })));
        }

        boost::optional<std::size_t> get_partitions_for_window_post(std::size_t total_sector_count,
                                                                    const post_config &config) {
            std::size_t partitions = std::ceil(total_sector_count / config.sector_count);

            if (partitions > 1) {
                return boost::optional<std::size_t>(partitions);
            } else {
                return boost::optional<std::size_t>();
            }
        }
    }    // namespace filecoin
}    // namespace nil

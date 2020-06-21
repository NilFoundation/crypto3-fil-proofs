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

#ifndef FILECOIN_CONSTANTS_HPP
#define FILECOIN_CONSTANTS_HPP

#include <cstdint>

namespace nil {
    namespace filecoin {
        constexpr static const std::uint64_t sector_size_2kb = 1ULL << 11;
        constexpr static const std::uint64_t sector_size_4kb = 1ULL << 12;
        constexpr static const std::uint64_t sector_size_16kb = 1ULL << 14;
        constexpr static const std::uint64_t sector_size_32kb = 1ULL << 15;
        constexpr static const std::uint64_t sector_size_8mb = 1ULL << 23;
        constexpr static const std::uint64_t sector_size_16mb = 1ULL << 24;
        constexpr static const std::uint64_t sector_size_512mb = 1ULL << 29;
        constexpr static const std::uint64_t sector_size_1gb = 1ULL << 30;
        constexpr static const std::uint64_t sector_size_32gb = 1ULL << 35;
        constexpr static const std::uint64_t sector_size_64gb = 1ULL << 36;

        constexpr static const std::size_t winning_post_challenge_count = 66;
        constexpr static const std::size_t winning_post_sector_count = 1;

        constexpr static const std::size_t window_post_challenge_count = 10;
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_CONSTANTS_HPP

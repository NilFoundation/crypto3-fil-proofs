//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef FILECOIN_CONSTANTS_HPP
#define FILECOIN_CONSTANTS_HPP

#include <stdint>

namespace filecoin {
    constexpr static const std::uint64_t sector_size_2kb = 1 << 11;
    constexpr static const std::uint64_t sector_size_4kb = 1 << 12;
    constexpr static const std::uint64_t sector_size_16kb = 1 << 14;
    constexpr static const std::uint64_t sector_size_32kb = 1 << 15;
    constexpr static const std::uint64_t sector_size_8mb = 1 << 23;
    constexpr static const std::uint64_t sector_size_16mb = 1 << 24;
    constexpr static const std::uint64_t sector_size_512mb = 1 << 29;
    constexpr static const std::uint64_t sector_size_1gb = 1 << 30;
    constexpr static const std::uint64_t sector_size_32gb = 1 << 35;
    constexpr static const std::uint64_t sector_size_64gb = 1 << 36;

    constexpr static const std::size_t winning_post_challenge_count = 66;
    constexpr static const std::size_t winning_post_sector_count = 1;

    constexpr static const std::size_t window_post_challenge_count = 10;
}    // namespace filecoin

#endif    // FILECOIN_CONSTANTS_HPP

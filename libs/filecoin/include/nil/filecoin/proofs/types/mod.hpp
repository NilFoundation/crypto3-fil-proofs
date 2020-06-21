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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_MOD_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_MOD_HPP

#include <cstdint>

#include <nil/filecoin/storage/proofs/porep/stacked/proof.hpp>

namespace nil {
    namespace filecoin {
        /// Arity for oct trees, used for comm_r_last.
        constexpr static const std::size_t oct_arity = 8;

        /// Arity for binary trees, used for comm_d.
        constexpr static const std::size_t binary_arity = 2;

        typedef std::array<std::uint8_t, 32> commitment;
        typedef std::array<std::uint8_t, 32> challenge_seed;
        typedef std::array<std::uint8_t, 32> proved_id;
        typedef std::array<std::uint8_t, 32> ticket;

        struct seal_pre_commit_output {
            commitment comm_r;
            commitment comm_d;
        };
    }    // namespace filecoin
}    // namespace nil

#endif
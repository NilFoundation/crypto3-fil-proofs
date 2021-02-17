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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_FR32_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_FR32_HPP

#include <array>
#include <cstdint>
#include <vector>

namespace nil {
    namespace filecoin {
        // Contains 32 bytes whose little-endian value represents an Fr.
        // Invariants:
        // - Value MUST represent a valid Fr.
        // - Length must be 32.
        typedef std::uint8_t fr32;

        // Contains one or more 32-byte chunks whose little-endian values represent Frs.
        // Invariants:
        // - Value of each 32-byte chunks MUST represent valid Frs.
        // - Total length must be a multiple of 32.
        // That is to say: each 32-byte chunk taken alone must be a valid Fr32.
        typedef std::vector<fr32> fr32_vector;

        // Array whose little-endian value represents an Fr.
        // Invariants:
        // - Value MUST represent a valid Fr.
        typedef std::array<fr32, 32> fr32_array;

    }    // namespace filecoin
}    // namespace nil

#endif

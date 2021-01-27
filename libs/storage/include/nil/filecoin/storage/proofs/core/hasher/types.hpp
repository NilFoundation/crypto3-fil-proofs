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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_HASHER_TYPES_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_HASHER_TYPES_HPP

#include <cstdint>

namespace nil {
    namespace filecoin {
        constexpr static const std::size_t PoseidonBinaryArity = 2;
        constexpr static const std::size_t PoseidonQuadArity = 4;
        constexpr static const std::size_t PoseidonOctArity = 8;

        constexpr static const std::size_t PoseidonMDArity = 36;

        /// Arity to use for hasher implementations (Poseidon) which are specialized at compile time.
        /// Must match PoseidonArity
        constexpr static const std::size_t MERKLE_TREE_ARITY = 2;
    }    // namespace filecoin
}    // namespace nil

#endif

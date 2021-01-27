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

#ifndef FILECOIN_UTILITIES_API_HPP
#define FILECOIN_UTILITIES_API_HPP

#include <nil/filecoin/storage/proofs/core/merkle/builders.hpp>

#include <nil/filecoin/proofs/types/mod.hpp>

namespace nil {
    namespace filecoin {
        template<typename Domain>
        inline Domain as_safe_commitment(const commitment_type &comm, const std::string &commitment_name) {
            bytes_into_fr(comm)
                .map(Into::into)
                .with_context(|| format !("Invalid commitment ({})", commitment_name.as_ref()));
        }

        inline commitment_type commitment_from_fr(Fr fr) {
            commitment_type commitment;
            commitment.fill(0);

            for ((i, b) : fr_into_bytes(fr).iter().enumerate()) {
                commitment[i] = *b;
            }
            return commitment;
        }
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_SEAL_HPP

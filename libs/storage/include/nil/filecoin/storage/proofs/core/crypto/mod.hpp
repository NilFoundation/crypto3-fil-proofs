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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_CRYPTO_MOD_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_CRYPTO_MOD_HPP

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

namespace nil {
    namespace filecoin {
        using namespace nil::crypto3::hash;

        typedef const char *domain_separation_tag;

        constexpr static domain_separation_tag DRSAMPLE_DST = "Filecoin_DRSample";
        constexpr static domain_separation_tag FEISTEL_DST = "Filecoin_Feistel";

        template<typename PoRepIDIterator, typename OutputIterator>
        OutputIterator derive_porep_domain_seed(PoRepIDIterator first, PoRepIDIterator last, OutputIterator out) {
            return hash<sha2<256>>(hash<sha2<256>>(first, last), out);
        }
    }    // namespace filecoin
}    // namespace nil

#endif

//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>

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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_HASH_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_HASH_HPP

#include <algorithm>
#include <fmt/format.h>

#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

namespace nil {
    namespace filecoin {
        template<typename FieldType, typename InputIterator>
        typename std::enable_if<std::is_same<typename std::iterator_traits<InputIterator>::value_type,
                                             typename FieldType::value_type>::value,
                                typename FieldType::value_type>::type
            hash_single_column(InputIterator first, InputIterator last) {
            if (std::distance(first, last) == 2) {
                // call to round constants generator for 2 and hash than
                return crypto3::hash<crypto3::hashes::poseidon<FieldType, 2, 2>>(first, last);
            } else if (std::distance(first, last) == 11) {
                // call to round constants generator for 11 and hash than
                return crypto3::hash<crypto3::hashes::poseidon<FieldType, 11, 11>>(first, last);
            } else {
                BOOST_ASSERT_MSG(std::distance(first, last),
                                 fmt::format("unsupported column size: %d", std::distance(first, last)));
            }
        }
    }    // namespace filecoin
}    // namespace nil

#endif

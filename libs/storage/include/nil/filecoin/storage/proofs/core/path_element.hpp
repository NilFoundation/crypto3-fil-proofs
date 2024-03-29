//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nemo@nil.foundation>

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

#ifndef FILECOIN_PATH_ELEMENT_HPP
#define FILECOIN_PATH_ELEMENT_HPP

#include <vector>

#include <nil/crypto3/algebra/curves/bls12.hpp>

namespace nil {
    namespace filecoin {
        template<typename Hash, std::size_t BaseArity,
                 typename FieldType = typename crypto3::algebra::curves::bls12<381>::scalar_field_type>
        struct PathElement {
            typedef Hash hash_type;
            typedef FieldType field_type;
            typedef typename field_type::value_type value_type;

            constexpr static const std::size_t arity = BaseArity;

            std::vector<value_type> hashes = std::vector<value_type>(arity);
            size_t index = 0;
        };
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_PATH_ELEMENT_HPP

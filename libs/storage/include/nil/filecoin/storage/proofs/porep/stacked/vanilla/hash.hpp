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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_HASH_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_HASH_HPP

namespace nil {
    namespace filecoin {
        template<typename FrInputIterator>
        Fr hash_single_column(FrInputIterator column_first, FrInputIterator column_last) {
            if (std::distance(column_first, column_last) == 2) {
                //call to round constants generator for 2 and hash than
                auto hasher = Poseidon::new_with_preimage(column, &*POSEIDON_CONSTANTS_2);
                return hasher.hash();
            } else if (std::distance(column_first, column_last) == 11) {
                //call to round constants generator for 11 and hash than
                auto hasher = Poseidon::new_with_preimage(column, &*POSEIDON_CONSTANTS_11);
                return hasher.hash();
            } else {
                BOOST_ASSERT_MSG(std::distance(column_first, column_last), 
                    std::format("unsupported column size: %d", std::distance(column_first, column_last)));
            }
        }
    }    // namespace filecoin
}    // namespace nil

#endif

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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_CIRCUIT_HASH_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_CIRCUIT_HASH_HPP

#include <nil/filecoin/storage/proofs/core/components/variables.hpp>

namespace nil {
    namespace filecoin {
        namespace porep {
            namespace stacked {
                namespace circuit {
                    /// Hash a list of bits.
                    template<template<typename> class ConstraintSystem>
                    AllocatedNumber<algebra::curves::bls12<381>>
                        hash_single_column(ConstraintSystem<algebra::curves::bls12<381>> &cs,
                                           std::vector<AllocatedNumber<algebra::curves::bls12<381>>> &column) {
                        if (column.size() == 2) {
                            poseidon_hash<ConstraintSystem, algebra::curves::bls12<381>, 2>(
                                cs, column, POSEIDON_CONSTANTS_2);
                        } else if (column.size() == 11) {
                            poseidon_hash<ConstraintSystem, algebra::curves::bls12<381>, 11>(
                                cs, column, POSEIDON_CONSTANTS_11);
                        } else {
                            throw "unsupported column size: " + column.size();
                        }
                    }
                }    // namespace circuit
            }        // namespace stacked
        }            // namespace porep
    }                // namespace filecoin
}    // namespace nil

#endif

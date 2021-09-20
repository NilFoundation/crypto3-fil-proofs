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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_HASH_COMPONENT_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_HASH_COMPONENT_HPP

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/filecoin/storage/proofs/core/components/variables.hpp>

namespace nil {
    namespace filecoin {
        namespace porep {
            namespace stacked {
                namespace components {
                    /// Hash a list of bits.
                    template<typename TField>
                    class hash_single_column: public components::component<TField>{

                        components::poseidon_hash<TField> poseidon_hash_component;

                    public:

                        hash_single_column(components::blueprint<TField> &bp, 
                                           components::blueprint_variable<TField> result):
                            components::component<TField>(bp), poseidon_hash_component(bp, result){
                        }

                        void generate_r1cs_constraints() {
                            poseidon_hash_component.generate_r1cs_constraints();
                        }

                        void generate_r1cs_witness(std::vector<typename TField::value_type> &column){

                            assert ((column.size() == 2) || (column.size() == 11), 
                                std::format("Unsupported single column to hash size: {}", column.size()));

                            if (column.size() == 2) {
                                poseidon_hash_component.generate_r1cs_witness(
                                    column, POSEIDON_CONSTANTS_2);
                            } else if (column.size() == 11) {
                                poseidon_hash_component.generate_r1cs_witness(
                                    column, POSEIDON_CONSTANTS_11);
                            }
                        }
                    };
                }    // namespace components
            }        // namespace stacked
        }            // namespace porep
    }                // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_STORAGE_PROOFS_POREP_STACKED_HASH_COMPONENT_HPP

//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>

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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_COMPONENTS_PICK_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_COMPONENTS_PICK_HPP

#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/components/blueprint_variable.hpp>
#include <nil/crypto3/zk/components/component.hpp>

namespace nil {
    namespace filecoin {
        namespace components {

            template<typename TField>
            class pick : public components::component<TField> {
                
            public:
                pick(components::blueprint<TField> &bp,
                     components::blueprint_variable_vector<TField> condition,
                     components::blueprint_variable_vector<TField> a,
                     components::blueprint_variable_vector<TField> b,
                     components::blueprint_variable_vector<TField> picked):
                components::component<TField>(bp){

                }

                void generate_r1cs_constraints() {
                    // Constrain (b - a) * condition = (b - c), ensuring c = a iff
                    // condition is true, otherwise c = b.
                    this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(
                            b - a, condition, b - c));
                }

                void generate_r1cs_witness(){
                    this->bp.val(c) = (this->bp.val(condition))?this->bp.val(a):this->bp.val(b);
                }
            };
            
        }    // namespace components
    }	// namespace filecoin
}    // namespace nil

#endif // FILECOIN_STORAGE_PROOFS_CORE_COMPONENTS_PICK_HPP

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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_COMPONENTS_ENCODING_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_COMPONENTS_ENCODING_HPP

namespace nil {
    namespace filecoin {
        namespace components {
            template<typename TField>
            class encode : public components::component<TField> {
                components::blueprint_variable_vector<TField> a;
                components::blueprint_variable_vector<TField> b;
                components::blueprint_variable_vector<TField> encoded;
            public:
                encode(components::blueprint<TField> &bp,
                     components::blueprint_variable_vector<TField> &a,
                     components::blueprint_variable_vector<TField> &b,
                     components::blueprint_variable_vector<TField> &encoded):
                components::component<TField>(bp), a(a), b(b), encoded(encoded){

                }

                void generate_r1cs_constraints() {
                    
                    this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(
                            a + b, 1, encoded));
                }

                void generate_r1cs_witness(){
                    this->bp.val(encoded) = this->bp.val(a) + this->bp.val(b);
                }
            };

            template<typename TField>
            class decode : public components::component<TField> {
                components::blueprint_variable_vector<TField> a;
                components::blueprint_variable_vector<TField> b;
                components::blueprint_variable_vector<TField> decoded;
            public:
                decode(components::blueprint<TField> &bp,
                     components::blueprint_variable_vector<TField> &a,
                     components::blueprint_variable_vector<TField> &b,
                     components::blueprint_variable_vector<TField> &decoded):
                components::component<TField>(bp), a(a), b(b), decoded(decoded){

                }

                void generate_r1cs_constraints() {
                    
                    this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(
                            decoded + b, 1, a));
                }

                void generate_r1cs_witness(){
                    this->bp.val(decoded) = this->bp.val(a) - this->bp.val(b);
                }
            };
        }   // namespace components
    }	// namespace filecoin
}    // namespace nil

#endif // FILECOIN_STORAGE_PROOFS_CORE_COMPONENTS_ENCODING_HPP

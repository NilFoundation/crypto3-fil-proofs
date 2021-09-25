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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_COMPONENTS_INSERTION_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_COMPONENTS_INSERTION_HPP

#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/components/blueprint_variable.hpp>
#include <nil/crypto3/zk/components/component.hpp>
#include <nil/crypto3/zk/components/logical/nor.hpp>
#include <nil/crypto3/zk/components/logical/conjunction.hpp>
#include <nil/crypto3/zk/components/logical/pick.hpp>

namespace nil {
    namespace filecoin {
        namespace components {

            using namespace nil::crypto3;

            template<typename TField, std::size_t Size>
            class insert;

            // TODO: looks like the input container size is constexpr value -> 
            // instead of an if it the algorithm choice could be done using 
            // specialization
            template<typename TField>
            class runtime_insert : public zk::components::component<TField> {
                std::size_t size;

                std::shared_ptr<insert<TField, 2>> insert_2;
                std::shared_ptr<insert<TField, 4>> insert_4;
                std::shared_ptr<insert<TField, 8>> insert_8;

            public:
                runtime_insert(zk::components::blueprint<TField> &bp,
                       zk::components::blueprint_variable<TField> &element_to_insert,
                       zk::components::boolean_vector<TField> bits,
                       zk::components::blueprint_variable_vector<TField> elements,
                       zk::components::blueprint_variable_vector<TField> inserted):
                zk::components::component<TField>(bp), size(elements.size() + 1) {

                    // For the sizes we know we need, we can take advantage of redundancy in the candidate selection at each position.
                    // This allows us to accomplish insertion with fewer constraints, if we hand-optimize.
                    // We don't need a special case for size 2 because the general algorithm
                    // collapses to `conditionally_reverse` when size = 2.
                    //
                    // If no special cases have been hand-coded, use the general algorithm.
                    // This costs size * (size - 1) constraints.
                    //
                    // Future work: In theory, we could compile arbitrary lookup tables to minimize constraints and avoid
                    // the most general case except when actually required — which it never is for simple insertion.
                    if (size == 2) {
                        insert_2.reset(new insert<TField, 2>(bp, element_to_insert, bits, elements, inserted));
                    } else if (size == 4) {
                        insert_4.reset(new insert<TField, 4>(bp, element_to_insert, bits, elements, inserted));
                    } else if (size == 8) {
                        insert_8.reset(new insert<TField, 8>(bp, element_to_insert, bits, elements, inserted));
                    };
                }

                void generate_r1cs_constraints() {
                    if (size == 2) {
                        insert_2->generate_r1cs_constraints();
                    } else if (size == 4) {
                        insert_4->generate_r1cs_constraints();
                    } else if (size == 8) {
                        insert_8->generate_r1cs_constraints();
                    };
                }

                void generate_r1cs_witness(){
                    if (size == 2) {
                        insert_2->generate_r1cs_witness();
                    } else if (size == 4) {
                        insert_4->generate_r1cs_witness();
                    } else if (size == 8) {
                        insert_8->generate_r1cs_witness();
                    };
                }
            };

            template<typename TField>
            class insert<TField, 2> : public zk::components::component<TField> {
                
                std::shared_ptr<zk::components::pick<TField>> pick_component0;
                std::shared_ptr<zk::components::pick<TField>> pick_component1;
            public:
                insert(zk::components::blueprint<TField> &bp,
                       zk::components::blueprint_variable<TField> &element_to_insert, 
                       zk::components::boolean_vector<TField> bits, 
                       zk::components::blueprint_variable_vector<TField> elements,
                       zk::components::blueprint_variable_vector<TField> inserted):
                zk::components::component<TField>(bp) {
                    assert(bits.size() == 1);

                    pick_component0.reset(new zk::components::pick<TField>(
                        bp,
                        bits[0],
                        elements[0],
                        element_to_insert,
                        inserted[0]
                    ));
                    pick_component1.reset(new zk::components::pick<TField>(
                        bp,
                        bits[0],
                        element_to_insert,
                        elements[0],
                        inserted[1]
                    ));
                }

                void generate_r1cs_constraints() {
                    pick_component0->generate_r1cs_constraints();
                    pick_component1->generate_r1cs_constraints();
                }

                void generate_r1cs_witness(){

                    pick_component0->generate_r1cs_witness();
                    pick_component1->generate_r1cs_witness();
                }
            };

            /*
            To insert A into [b, c, d] at position n of bits, represented by booleans [b0, b1, b2].
            n [b0, b1] pos 0 1 2 3
            0 [0, 0]       A b c d
            1 [1, 0]       b A c d
            2 [0, 1]       b c A d
            3 [1, 1]       b c d A

            A = element
            b = elements[0]
            c = elements[1]
            d = elements[2]
             */
            template<typename TField>
            class insert<TField, 4> : public zk::components::component<TField> {
                
                std::shared_ptr<zk::components::pick<TField>> pick_component0;
                std::shared_ptr<zk::components::pick<TField>> pick_component1;
                std::shared_ptr<zk::components::pick<TField>> pick_component2;
                std::shared_ptr<zk::components::pick<TField>> pick_component3;

                std::shared_ptr<zk::components::pick<TField>> pick_component0_intermediate;
                std::shared_ptr<zk::components::pick<TField>> pick_component1_intermediate;
                std::shared_ptr<zk::components::pick<TField>> pick_component2_intermediate;
                std::shared_ptr<zk::components::pick<TField>> pick_component3_intermediate;

                zk::components::blueprint_variable<TField> p0_x0;
                zk::components::blueprint_variable<TField> p1_x0;
                zk::components::blueprint_variable<TField> p2_x1;
                zk::components::blueprint_variable<TField> p3_x1;

            public:
                insert(zk::components::blueprint<TField> &bp,
                       zk::components::blueprint_variable<TField> &element_to_insert,
                       zk::components::boolean_vector<TField> bits,
                       zk::components::blueprint_variable_vector<TField> elements,
                       zk::components::blueprint_variable_vector<TField> inserted):
                zk::components::component<TField>(bp) {
                    assert(bits.size() == 2);

                    // Witness naming convention:
                    // `p0_x0` means "Output position 0 when b0 is unknown (x) and b1 is 0."

                    zk::components::blueprint_variable<TField> &a = element_to_insert;
                    zk::components::blueprint_variable<TField> &b = elements[0];
                    zk::components::blueprint_variable<TField> &c = elements[1];
                    zk::components::blueprint_variable<TField> &d = elements[2];

                    pick_component0_intermediate.reset(new zk::components::pick<TField>(bp, bits[0], b, a, p0_x0));
                    pick_component0.reset(new zk::components::pick<TField>(bp, bits[1], b, p0_x0, inserted[0]));

                    pick_component1_intermediate.reset(new zk::components::pick<TField>(bp, bits[0], a, b, p1_x0));
                    pick_component1.reset(new zk::components::pick<TField>(bp, bits[1], c, p1_x0, inserted[1]));

                    pick_component2_intermediate.reset(new zk::components::pick<TField>(bp, bits[0], d, a, p2_x1));
                    pick_component2.reset(new zk::components::pick<TField>(bp, bits[1], p2_x1, c, inserted[2]));

                    pick_component3_intermediate.reset(new zk::components::pick<TField>(bp, bits[0], a, d, p3_x1));
                    pick_component3.reset(new zk::components::pick<TField>(bp, bits[1], p3_x1, d, inserted[3]));

                }

                void generate_r1cs_constraints() {

                    pick_component0->generate_r1cs_constraints();
                    pick_component1->generate_r1cs_constraints();
                    pick_component2->generate_r1cs_constraints();
                    pick_component3->generate_r1cs_constraints();

                    pick_component0_intermediate->generate_r1cs_constraints();
                    pick_component1_intermediate->generate_r1cs_constraints();
                    pick_component2_intermediate->generate_r1cs_constraints();
                    pick_component3_intermediate->generate_r1cs_constraints();
                }

                void generate_r1cs_witness(){

                    pick_component0_intermediate->generate_r1cs_witness();
                    pick_component0->generate_r1cs_witness();

                    pick_component1_intermediate->generate_r1cs_witness();
                    pick_component1->generate_r1cs_witness();

                    pick_component2_intermediate->generate_r1cs_witness();
                    pick_component2->generate_r1cs_witness();

                    pick_component3_intermediate->generate_r1cs_witness();
                    pick_component3->generate_r1cs_witness();
                }
            };

            /*
            To insert A into [b, c, d, e, f, g, h] at position n of bits, represented by booleans [b0, b1, b2].
            n [b0, b1, b2] pos 0 1 2 3 4 5 6 7
            0 [0, 0, 0]        A b c d e f g h
            1 [1, 0, 0]        b A c d e f g h
            2 [0, 1, 0]        b c A d e f g h
            3 [1, 1, 0]        b c d A e f g h
            4 [0, 0, 1]        b c d e A f g h
            5 [1, 0, 1]        b c d e f A g h
            6 [0, 1, 1]        b c d e f g A h
            7 [1, 1, 1]        b c d e f g h A


            A = element
            b = elements[0]
            c = elements[1]
            d = elements[2]
            e = elements[3]
            f = elements[4]
            g = elements[5]
            h = elements[6]
             */
            template<typename TField>
            class insert<TField, 8> : public zk::components::component<TField> {
                
                std::shared_ptr<zk::components::nor<TField>> nor_component;
                std::shared_ptr<zk::components::conjunction<TField>> conjunction_component;

                std::shared_ptr<zk::components::pick<TField>> pick_component0;
                std::shared_ptr<zk::components::pick<TField>> pick_component1;
                std::shared_ptr<zk::components::pick<TField>> pick_component2;
                std::shared_ptr<zk::components::pick<TField>> pick_component3;
                std::shared_ptr<zk::components::pick<TField>> pick_component4;
                std::shared_ptr<zk::components::pick<TField>> pick_component5;
                std::shared_ptr<zk::components::pick<TField>> pick_component6;
                std::shared_ptr<zk::components::pick<TField>> pick_component7;

                std::shared_ptr<zk::components::pick<TField>> pick_component0_intermediate;
                std::shared_ptr<zk::components::pick<TField>> pick_component1_intermediate0;
                std::shared_ptr<zk::components::pick<TField>> pick_component1_intermediate1;
                std::shared_ptr<zk::components::pick<TField>> pick_component2_intermediate0;
                std::shared_ptr<zk::components::pick<TField>> pick_component2_intermediate1;
                std::shared_ptr<zk::components::pick<TField>> pick_component3_intermediate;
                std::shared_ptr<zk::components::pick<TField>> pick_component4_intermediate;
                std::shared_ptr<zk::components::pick<TField>> pick_component5_intermediate0;
                std::shared_ptr<zk::components::pick<TField>> pick_component5_intermediate1;
                std::shared_ptr<zk::components::pick<TField>> pick_component6_intermediate0;
                std::shared_ptr<zk::components::pick<TField>> pick_component6_intermediate1;
                std::shared_ptr<zk::components::pick<TField>> pick_component7_intermediate;

                zk::components::boolean<TField> b0_nor_b1;
                zk::components::boolean<TField> b0_and_b1;

                zk::components::blueprint_variable<TField> p0_xx0;
                zk::components::blueprint_variable<TField> p1_x00;
                zk::components::blueprint_variable<TField> p1_xx0;
                zk::components::blueprint_variable<TField> p2_x10;
                zk::components::blueprint_variable<TField> p2_xx0;
                zk::components::blueprint_variable<TField> p3_xx0;
                zk::components::blueprint_variable<TField> p4_xx1;
                zk::components::blueprint_variable<TField> p5_x01;
                zk::components::blueprint_variable<TField> p5_xx1;
                zk::components::blueprint_variable<TField> p6_x11;
                zk::components::blueprint_variable<TField> p6_xx1;
                zk::components::blueprint_variable<TField> p7_xx1;

            public:
                insert(zk::components::blueprint<TField> &bp,
                       zk::components::blueprint_variable<TField> &element_to_insert,
                       zk::components::boolean_vector<TField> bits,
                       zk::components::blueprint_variable_vector<TField> elements,
                       zk::components::blueprint_variable_vector<TField> inserted):
                zk::components::component<TField>(bp) {
                    assert(bits.size() == 3);

                    zk::components::boolean<TField> &b0 = bits[0];
                    zk::components::boolean<TField> &b1 = bits[1];
                    zk::components::boolean<TField> &b2 = bits[2];

                    zk::components::blueprint_variable<TField> &a = element_to_insert;
                    zk::components::blueprint_variable<TField> &b = elements[0];
                    zk::components::blueprint_variable<TField> &c = elements[1];
                    zk::components::blueprint_variable<TField> &d = elements[2];
                    zk::components::blueprint_variable<TField> &e = elements[3];
                    zk::components::blueprint_variable<TField> &f = elements[4];
                    zk::components::blueprint_variable<TField> &g = elements[5];
                    zk::components::blueprint_variable<TField> &h = elements[6];

                    zk::components::boolean_vector<TField> boolean_components_input = 
                        zk::components::boolean_vector<TField>(bits.begin(), bits.begin() + 2);
                    nor_component.reset(new zk::components::nor<TField>(bp, boolean_components_input, b0_nor_b1));
                    conjunction_component.reset(new zk::components::conjunction<TField>(bp, boolean_components_input, b0_and_b1));

                    pick_component0_intermediate.reset(new zk::components::pick<TField>(bp, b0_nor_b1, a, b, p0_xx0));
                    pick_component0.reset(new zk::components::pick<TField>(bp, b2, b, p0_xx0, inserted[0]));

                    pick_component1_intermediate0.reset(new zk::components::pick<TField>(bp, b0, a, b, p1_x00));
                    pick_component1_intermediate1.reset(new zk::components::pick<TField>(bp, b1, c, p1_x00, p1_xx0));
                    pick_component1.reset(new zk::components::pick<TField>(bp, b2, c, p1_xx0, inserted[1]));

                    pick_component2_intermediate0.reset(new zk::components::pick<TField>(bp, b0, d, a, p2_x10));
                    pick_component2_intermediate1.reset(new zk::components::pick<TField>(bp, b1, p2_x10, c, p2_xx0));
                    pick_component2.reset(new zk::components::pick<TField>(bp, b2, d, p2_xx0, inserted[2]));

                    pick_component3_intermediate.reset(new zk::components::pick<TField>(bp, b0_and_b1, a, d, p3_xx0));
                    pick_component3.reset(new zk::components::pick<TField>(bp, b2, e, p3_xx0, inserted[3]));

                    pick_component4_intermediate.reset(new zk::components::pick<TField>(bp, b0_nor_b1, a, f, p4_xx1));
                    pick_component4.reset(new zk::components::pick<TField>(bp, b2, p4_xx1, e, inserted[4]));

                    pick_component5_intermediate0.reset(new zk::components::pick<TField>(bp, b0, a, f, p5_x01));
                    pick_component5_intermediate1.reset(new zk::components::pick<TField>(bp, b1, g, p5_x01, p5_xx1));
                    pick_component5.reset(new zk::components::pick<TField>(bp, b2, p5_xx1, f, inserted[5]));

                    pick_component6_intermediate0.reset(new zk::components::pick<TField>(bp, b0, h, a, p6_x11));
                    pick_component6_intermediate1.reset(new zk::components::pick<TField>(bp, b1, p6_x11, g, p6_xx1));
                    pick_component6.reset(new zk::components::pick<TField>(bp, b2, p6_xx1, g, inserted[6]));

                    pick_component7_intermediate.reset(new zk::components::pick<TField>(bp, b0_and_b1, a, h, p7_xx1));
                    pick_component7.reset(new zk::components::pick<TField>(bp, b2, p7_xx1, h, inserted[7]));

                }

                void generate_r1cs_constraints() {

                    nor_component->generate_r1cs_constraints();
                    conjunction_component->generate_r1cs_constraints();

                    pick_component0->generate_r1cs_constraints();
                    pick_component1->generate_r1cs_constraints();
                    pick_component2->generate_r1cs_constraints();
                    pick_component3->generate_r1cs_constraints();
                    pick_component4->generate_r1cs_constraints();
                    pick_component5->generate_r1cs_constraints();
                    pick_component6->generate_r1cs_constraints();
                    pick_component7->generate_r1cs_constraints();

                    pick_component0_intermediate->generate_r1cs_constraints();
                    pick_component1_intermediate0->generate_r1cs_constraints();
                    pick_component1_intermediate1->generate_r1cs_constraints();
                    pick_component2_intermediate0->generate_r1cs_constraints();
                    pick_component2_intermediate1->generate_r1cs_constraints();
                    pick_component3_intermediate->generate_r1cs_constraints();
                    pick_component4_intermediate->generate_r1cs_constraints();
                    pick_component5_intermediate0->generate_r1cs_constraints();
                    pick_component5_intermediate1->generate_r1cs_constraints();
                    pick_component6_intermediate0->generate_r1cs_constraints();
                    pick_component6_intermediate1->generate_r1cs_constraints();
                    pick_component7_intermediate->generate_r1cs_constraints();
                }

                void generate_r1cs_witness(){

                    nor_component->generate_r1cs_witness();
                    conjunction_component->generate_r1cs_witness();

                    pick_component0_intermediate->generate_r1cs_witness();
                    pick_component0->generate_r1cs_witness();

                    pick_component1_intermediate0->generate_r1cs_witness();
                    pick_component1_intermediate1->generate_r1cs_witness();
                    pick_component1->generate_r1cs_witness();

                    pick_component2_intermediate0->generate_r1cs_witness();
                    pick_component2_intermediate1->generate_r1cs_witness();
                    pick_component2->generate_r1cs_witness();

                    pick_component3_intermediate->generate_r1cs_witness();
                    pick_component3->generate_r1cs_witness();

                    pick_component4_intermediate->generate_r1cs_witness();
                    pick_component4->generate_r1cs_witness();

                    pick_component5_intermediate0->generate_r1cs_witness();
                    pick_component5_intermediate1->generate_r1cs_witness();
                    pick_component5->generate_r1cs_witness();

                    pick_component6_intermediate0->generate_r1cs_witness();
                    pick_component6_intermediate1->generate_r1cs_witness();
                    pick_component6->generate_r1cs_witness();

                    pick_component7_intermediate->generate_r1cs_witness();
                    pick_component7->generate_r1cs_witness();
                }
            };
            
        }    // namespace components
    }	// namespace filecoin
}    // namespace nil

#endif // FILECOIN_STORAGE_PROOFS_CORE_COMPONENTS_INSERTION_HPP

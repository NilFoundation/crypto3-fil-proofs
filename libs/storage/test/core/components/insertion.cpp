//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE insertion_component_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/core/components/insertion.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3;
using namespace nil::filecoin;

BOOST_AUTO_TEST_SUITE(insertion_component_test_suite)

BOOST_AUTO_TEST_CASE(test_insertion) {
    using field_type = typename algebra::curves::bls12<381>::scalar_field_type;

    for (std::size_t log_size=1; log_size<=4; log_size++) {
        std::size_t size = 1<<log_size;
        for (std::size_t index=0; index<size; index++) {

            zk::components::blueprint<field_type> bp;
            zk::components::blueprint_variable_vector<field_type> elements;
            elements.allocate(bp, size-1);
            for (std::size_t i = 0; i < size-1; i++){
                bp.val(elements[i]) = algebra::random_element<field_type>();
            }

            zk::components::blueprint_variable<field_type> element_to_insert;
            bp.val(element_to_insert) = algebra::random_element<field_type>();

            zk::components::boolean_vector<field_type> index_bits;
            index_bits.allocate(bp, log_size);
            for (std::size_t i = 0; i < log_size; i++){
                index_bits[i].val(bp, (index >> i) & 1);
            }

            zk::components::blueprint_variable_vector<field_type> inserted;
            inserted.allocate(bp, size);

            components::runtime_insert<field_type> insert_component(bp, element_to_insert, index_bits, elements, inserted);

            insert_component.generate_r1cs_constraints();

            insert_component.generate_r1cs_witness();

            assert(bp.is_satisfied());

            inserted.erase(inserted.begin() + index);

            for (std::size_t i=0; i < size - 1; i++) {
                assert(bp.val(elements[i]) == bp.val(inserted[i]));
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
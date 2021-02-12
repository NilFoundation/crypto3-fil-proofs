//----------------------------------------------------------------------------
// Copyright (C) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the Server Side Public License, version 1,
// as published by the author.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// Server Side Public License for more details.
//
// You should have received a copy of the Server Side Public License
// along with this program. If not, see
// <https://github.com/NilFoundation/plugin/blob/master/LICENSE_1_0.txt>.
//----------------------------------------------------------------------------

#define BOOST_TEST_MODULE circuit_hash_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/porep/stacked/circuit/hash.hpp>

using namespace nil::filecoin;

BOOST_AUTO_TEST_SUITE(stacked_circuit_hash_test_suite)

BOOST_AUTO_TEST_CASE(test_hash2_circuit) {
    const auto rng = XorShiftRng::from_seed(crate::TEST_SEED);

    for (std::size_t i=0; i < 10; ++i) {
        auto cs = TestConstraintSystem::<Bls12>::new ();

        const auto a = Fr::random(rng);
        const auto b = Fr::random(rng);

        const auto a_num = { auto cs = cs.namespace(|| "a");
        num::AllocatedNumber::alloc(cs, || Ok(a))
    };

    const auto b_num = { auto cs = cs.namespace(|| "b");
    num::AllocatedNumber::alloc(cs, || Ok(b))
};

const auto out = <PedersenHasher>::Function::hash2_circuit(cs.namespace(|| "hash2"), &a_num, &b_num, )
              .expect("hash2 function failed");

BOOST_CHECK(cs.is_satisfied(), "constraints not satisfied");
BOOST_CHECK_EQUAL(cs.num_constraints(), 1371);

const auto expected : Fr = <PedersenHasher>::Function::hash2(&a.into(), &b.into()).into();

BOOST_CHECK_EQUAL(expected, out.get_value(), "circuit and non circuit do not match");
}
}

BOOST_AUTO_TEST_CASE(test_hash_single_column_circuit) {
    const auto rng = XorShiftRng::from_seed(crate::TEST_SEED);

        for (std::size_t i=0; i < 1; ++i) {
                auto cs = TestConstraintSystem::<Bls12>::new ();

                const auto vals = vec ![Fr::random(rng); 11];
                const auto vals_opt =
                    vals.iter()
                        .enumerate()
                        .map(| (i, v) |
                             {num::AllocatedNumber::alloc(cs.namespace(|| std::format("num_{}", i)), || Ok(*v))})
                        .collect::<Vec<_>>();

                const auto out = hash_single_column(cs.namespace(|| "hash_single_column"), &vals_opt)
                              .expect("hash_single_column function failed");

                BOOST_ASSERT_MSG(cs.is_satisfied(), "constraints not satisfied");
                BOOST_ASSERT(cs.num_constraints() == 598);

                const auto expected : Fr = vanilla_hash_single_column(&vals);

                BOOST_ASSERT_MSG(expected == out.get_value(), "circuit and non circuit do not match");
            }
}

BOOST_AUTO_TEST_SUITE_END()
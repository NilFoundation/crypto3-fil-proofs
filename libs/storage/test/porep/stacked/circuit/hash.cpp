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
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    for (_ in 0..10) {
        let mut cs = TestConstraintSystem::<Bls12>::new ();

        let a = Fr::random(rng);
        let b = Fr::random(rng);

        let a_num = { let mut cs = cs.namespace(|| "a");
        num::AllocatedNum::alloc(&mut cs, || Ok(a)).unwrap()
    };

    let b_num = { let mut cs = cs.namespace(|| "b");
    num::AllocatedNum::alloc(&mut cs, || Ok(b)).unwrap()
};

let out = <PedersenHasher as Hasher>::Function::hash2_circuit(cs.namespace(|| "hash2"), &a_num, &b_num, )
              .expect("hash2 function failed");

BOOST_CHECK(cs.is_satisfied(), "constraints not satisfied");
BOOST_CHECK_EQUAL(cs.num_constraints(), 1371);

let expected : Fr = <PedersenHasher as Hasher>::Function::hash2(&a.into(), &b.into()).into();

BOOST_CHECK_EQUAL(expected, out.get_value().unwrap(), "circuit and non circuit do not match");
}
}

BOOST_AUTO_TEST_CASE(test_hash_single_column_circuit) {
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        for
            _ in 0..1 {
                let mut cs = TestConstraintSystem::<Bls12>::new ();

                let vals = vec ![Fr::random(rng); 11];
                let vals_opt =
                    vals.iter()
                        .enumerate()
                        .map(| (i, v) |
                             {num::AllocatedNum::alloc(cs.namespace(|| format !("num_{}", i)), || Ok(*v)).unwrap()})
                        .collect::<Vec<_>>();

                let out = hash_single_column(cs.namespace(|| "hash_single_column"), &vals_opt)
                              .expect("hash_single_column function failed");

                assert !(cs.is_satisfied(), "constraints not satisfied");
                assert_eq !(cs.num_constraints(), 598);

                let expected : Fr = vanilla_hash_single_column(&vals);

                assert_eq !(expected, out.get_value().unwrap(), "circuit and non circuit do not match");
            }
}

BOOST_AUTO_TEST_SUITE_END()
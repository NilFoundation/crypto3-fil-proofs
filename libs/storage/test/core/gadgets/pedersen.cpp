//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020 Gokuyun Moscow Algorithm Lab
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
//
#define BOOST_TEST_MODULE pedersen_gadget_test

#include <unordered_map>

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/core/gadgets/pedersen.hpp>

BOOST_AUTO_TEST_SUITE(pedersen_gadget_test_suite)

BOOST_AUTO_TEST_CASE(test_pedersen_single_input_circut) {
    let mut rng = XorShiftRng::from_seed(crate::TEST_SEED);

    std::unordered_map<std::size_t, std::size_t> cases = { {32, 689}, {64, 1376} };

    for (bytes, constraints)
        in &cases {
            let mut cs = TestConstraintSystem::<Bls12>::new ();
            let data : Vec<u8> = (0.. * bytes).map(| _ | rng.gen()).collect();

            let data_bits : Vec<Boolean> = { let mut cs = cs.namespace(|| "data");
            bytes_into_boolean_vec(&mut cs, Some(data.as_slice()), data.len()).unwrap()
        };
    let out = pedersen_compression_num(&mut cs, &data_bits).expect("pedersen hashing failed");

    BOOST_CHECK(cs.is_satisfied(), "constraints not satisfied");
    BOOST_CHECK_EQUAL(cs.num_constraints(), *constraints, "constraint size changed for {} bytes", *bytes);

    let expected = crypto::pedersen::pedersen(data.as_slice());

    BOOST_CHECK_EQUAL(expected, out.get_value().unwrap(), "circuit and non circuit do not match");
}
}

BOOST_AUTO_TEST_CASE(test_pedersen_md_input_circut) {
    let mut rng = XorShiftRng::from_seed(crate::TEST_SEED);

    let cases = [
        (64, 1376),      // 64 bytes
        (96, 2751),      // 96 bytes
        (128, 4126),     // 128 bytes
        (160, 5501),     // 160 bytes
        (256, 9626),     // 160 bytes
        (512, 20626),    // 512 bytes
    ];

    for (bytes, constraints)
        in &cases {
            let mut cs = TestConstraintSystem::<Bls12>::new ();
            let data : Vec<u8> = (0.. * bytes).map(| _ | rng.gen()).collect();

            let data_bits : Vec<Boolean> = { let mut cs = cs.namespace(|| "data");
            bytes_into_boolean_vec(&mut cs, Some(data.as_slice()), data.len()).unwrap()
        };
    let out = pedersen_md_no_padding(cs.namespace(|| "pedersen"), &data_bits).expect("pedersen hashing failed");

    BOOST_CHECK(cs.is_satisfied(), "constraints not satisfied");
    BOOST_CHECK_EQUAL(cs.num_constraints(), *constraints, "constraint size changed {}", bytes);

    let expected = crypto::pedersen::pedersen_md_no_padding(data.as_slice());

    BOOST_CHECK_EQUAL(expected, out.get_value().unwrap(), "circuit and non circuit do not match {} bytes", bytes);
}
}

BOOST_AUTO_TEST_SUITE_END()

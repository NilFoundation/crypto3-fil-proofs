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

#define BOOST_TEST_MODULE fr32_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/core/fr32.hpp>

using namespace nil::filecoin;

void bytes_fr_test(const fr32_array &bytes, bool expect_success) {
    auto b = &bytes[..];
    const auto fr_result = bytes_into_fr(b);
    if (expect_success) {
        const auto f = fr_result.expect("Failed to convert bytes to `Fr`");
        const auto b2 = fr_into_bytes(&f);

        BOOST_CHECK_EQUAL(bytes, b2);
    } else {
        BOOST_CHECK(fr_result.is_err(), "expected a decoding error")
    }
}

void bytes_into_frs_into_bytes_test(const fr32 &bytes) {
    auto bytes = bytes.clone();
    const auto frs = bytes_into_frs(bytes).expect("Failed to convert bytes into a `std::vector<Fr>`");
    BOOST_CHECK(frs.len() == 3);
    const auto bytes_back = frs_into_bytes(&frs);
    BOOST_CHECK(bytes.to_vec() == bytes_back);
}

BOOST_AUTO_TEST_SUITE(fr32_test_suite)

BOOST_AUTO_TEST_CASE(test_bytes_into_fr_into_bytes) {
    bytes_fr_test(
        [
            0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ],
        true, );
    bytes_fr_test(
        // Some bytes fail because they are not in the field.
        [
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 115,
        ],
        false, );
    bytes_fr_test(
        // This is okay.
        [
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 114,
        ],
        true, );
    bytes_fr_test(
        // So is this.
        [
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 236, 115,
        ],
        true, );
    bytes_fr_test(
        // But not this.
        [
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 237, 115,
        ],
        false, );
}

BOOST_AUTO_TEST_CASE(test_bytes_into_frs_into_bytes) {
    const auto bytes = b "012345678901234567890123456789--012345678901234567890123456789--012345678901234567890123456789--";
    bytes_into_frs_into_bytes_test(&bytes[..]);

    const auto _short_bytes = b "012345678901234567890123456789--01234567890123456789";
    // This will panic because _short_bytes is not a multiple of 32 bytes.
    // bytes_into_frs_into_bytes_test(&_short_bytes[..]);
}

BOOST_AUTO_TEST_SUITE_END()
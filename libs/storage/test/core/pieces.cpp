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

#define BOOST_TEST_MODULE pieces_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/core/pieces.hpp>

BOOST_AUTO_TEST_SUITE(pieces_test_suite)

BOOST_AUTO_TEST_CASE(test_subtree_capacity) {
    BOOST_CHECK_EQUAL(subtree_capacity(0, 16), 16);
    BOOST_CHECK_EQUAL(subtree_capacity(1, 16), 1);
    BOOST_CHECK_EQUAL(subtree_capacity(2, 16), 2);
    BOOST_CHECK_EQUAL(subtree_capacity(3, 16), 1);
    BOOST_CHECK_EQUAL(subtree_capacity(4, 16), 4);
    BOOST_CHECK_EQUAL(subtree_capacity(5, 16), 1);
    BOOST_CHECK_EQUAL(subtree_capacity(6, 16), 2);
    BOOST_CHECK_EQUAL(subtree_capacity(7, 16), 1);
    BOOST_CHECK_EQUAL(subtree_capacity(8, 16), 8);
    BOOST_CHECK_EQUAL(subtree_capacity(9, 16), 1);
    BOOST_CHECK_EQUAL(subtree_capacity(10, 16), 2);
    BOOST_CHECK_EQUAL(subtree_capacity(11, 16), 1);
    BOOST_CHECK_EQUAL(subtree_capacity(12, 16), 4);
    BOOST_CHECK_EQUAL(subtree_capacity(13, 16), 1);
    BOOST_CHECK_EQUAL(subtree_capacity(14, 16), 2);
    BOOST_CHECK_EQUAL(subtree_capacity(15, 16), 1);
}

BOOST_AUTO_TEST_CASE(test_generate_piece_commitment_bytes_from_source) {
    std::vector<std::uint8_t> some_bytes(0, 64);
    let mut some_bytes_slice : &[u8] = &some_bytes;
    generate_piece_commitment_bytes_from_source<PedersenHasher>(&mut some_bytes_slice, 64);

    std::vector<std::uint8_t> not_enough_bytes(0, 7);
    std::vector<std::uint8_t> not_enough_bytes_slice = not_enough_bytes;
    BOOST_CHECK(
        !generate_piece_commitment_bytes_from_source<PedersenHasher>(&mut not_enough_bytes_slice, 7).is_err());
}

BOOST_AUTO_TEST_SUITE_END()
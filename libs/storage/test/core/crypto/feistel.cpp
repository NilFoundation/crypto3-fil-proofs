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

#define BOOST_TEST_MODULE crypto_feistel_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/core/crypto/feistel.hpp>

using namespace nil::filecoin;

BOOST_AUTO_TEST_SUITE(feistel_test_suite)

// Some sample n-values which are not powers of four and also don't coincidentally happen to
// encode/decode correctly.
const BAD_NS : &[Index] = &[ 5, 6, 8, 12, 17 ];    //
//
void encode_decode(n : Index, expect_success : bool) {
    auto failed = false;
    const auto precomputed = precompute(n);
    for (std::size_t i = 0; i < n; i++) {
        const auto p = encode(i, &[ 1, 2, 3, 4 ], precomputed);
        const auto v = decode(p, &[ 1, 2, 3, 4 ], precomputed);
        const auto equal = i == v;
        const auto in_range = p <= n;
        if (expect_success) {
            BOOST_CHECK(equal, "failed to permute (n = {})", n);
            BOOST_CHECK(in_range, "output number is too big (n = {})", n);
        } else {
            if (!equal || !in_range) {
                failed = true;
            }
        }
    }
    if (!expect_success) {
        assert(failed, "expected failure (n = {})", n);
    }
}

BOOST_AUTO_TEST_CASE(test_feistel_power_of_4) {
    // Our implementation is guaranteed to produce a permutation when input size (number of elements)
    // is a power of our.
    auto n = 1;

    // Powers of 4 always succeed.
    for (std::size_t i = 0; i < 4; ++i) {
        n *= 4;
        encode_decode(n, true);
    }

    // Some non-power-of 4 also succeed, but here is a selection of examples values showing
    // that this is not guaranteed.
    for (i in BAD_NS.iter()) {
        encode_decode(*i, false);
    }
}

BOOST_AUTO_TEST_CASE(test_feistel_on_arbitrary_set) {
    for (n in BAD_NS.iter()) {
            const auto precomputed = precompute(*n as Index);
        for (i = 0; i < * n; ++i) {
            const auto p = permute(*n, i, &[ 1, 2, 3, 4 ], precomputed);
            const auto v = invert_permute(*n, p, &[ 1, 2, 3, 4 ], precomputed);
            // Since every element in the set is reversibly mapped to another element also in the set,
            // this is indeed a permutation.
            assert_eq !(i, v, "failed to permute");
            assert !(p <= *n, "output number is too big");
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
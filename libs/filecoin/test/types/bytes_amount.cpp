//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020 Wukong Moscow Algorithm Lab
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

#define BOOST_TEST_MODULE filecoin_bytes_amount_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/proofs/types/bytes_amount.hpp>

BOOST_AUTO_TEST_SUITE(filecoin_bytes_amount_test_suite)

BOOST_AUTO_TEST_CASE(allowed_operations) {
    let a = UnpaddedBytesAmount(1);
    let b = UnpaddedBytesAmount(2);
    let c = UnpaddedBytesAmount(3);

    let d = PaddedBytesAmount(1);
    let e = PaddedBytesAmount(2);
    let f = PaddedBytesAmount(3);

    // Operations between UnpaddedBytesAmounts are allowed
    BOOST_CHECK_EQUAL(a + b, c);
    BOOST_CHECK_EQUAL(c - b, a);

    // Operations between PaddedBytesAmounts are allowed
    BOOST_CHECK_EQUAL(d + e, f);
    BOOST_CHECK_EQUAL(f - e, d);

    // Mixed operations fail at compile time.
    // BOOST_CHECK_EQUAL(a + b, f);

    // Coercion to primitives work
    BOOST_CHECK_EQUAL(1u64 + u64::from(b), 3u64);
    BOOST_CHECK_EQUAL(1usize + usize::from(b), 3usize);
    BOOST_CHECK_EQUAL(1u64 + u64::from(e), 3u64);
    BOOST_CHECK_EQUAL(1usize + usize::from(e), 3usize);

    // But not between BytesAmount types
    // BOOST_CHECK_EQUAL(a + UnpaddedBytesAmount::from(e), c);
    // BOOST_CHECK_EQUAL(d + UnpaddedBytesAmount::from(b), f);

    // But must be explicit or won't compile.
    // BOOST_CHECK_EQUAL(1u64 + b, 3u64);
    // BOOST_CHECK_EQUAL(1usize + b, 3usize);
    // BOOST_CHECK_EQUAL(1u64 + u64::from(e), 3u64);
    // BOOST_CHECK_EQUAL(1usize + usize::from(e), 3usize);
}

BOOST_AUTO_TEST_SUITE_END()

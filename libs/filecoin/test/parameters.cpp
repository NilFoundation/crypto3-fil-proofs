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

#define BOOST_TEST_MODULE filecoin_parameters_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/proofs/parameters.hpp>

BOOST_AUTO_TEST_SUITE(filecoin_parameters_test_suite)

BOOST_AUTO_TEST_CASE(partition_layer_challenges_test) {
    let f = | partitions | {select_challenges(partitions, 12, 11).challenges_count_all()};
    // Update to ensure all supported PoRepProofPartitions options are represented here.
    BOOST_CHECK_EQUAL(6, f(usize::from(crate::PoRepProofPartitions(2))));

    BOOST_CHECK_EQUAL(12, f(1));
    BOOST_CHECK_EQUAL(6, f(2));
    BOOST_CHECK_EQUAL(3, f(4));
}

BOOST_AUTO_TEST_CASE(test_winning_post_params) {
        PoStConfig config = {
        typ : post_type::Winning,
        priority : false,
        challenge_count : 66,
        sector_count : 1,
        sector_size : 2048,
    };

    let params = winning_post_public_params<DefaultOctLCTree>(config);
    BOOST_CHECK_EQUAL(params.sector_count, 66);
    BOOST_CHECK_EQUAL(params.challenge_count, 1);
    BOOST_CHECK_EQUAL(params.sector_size, 2048);
}

BOOST_AUTO_TEST_SUITE_END()

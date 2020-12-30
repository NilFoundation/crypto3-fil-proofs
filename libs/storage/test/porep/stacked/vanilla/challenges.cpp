//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
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

#define BOOST_TEST_MODULE vanilla_challenges_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/challenges.hpp>

using namespace nil::filecoin;

BOOST_AUTO_TEST_SUITE(vanilla_challenges_test_suite)

BOOST_AUTO_TEST_CASE(challenge_derivation) {
    auto n = 200;
    auto layers = 100;

    auto challenges = LayerChallenges::new (layers, n);
    auto leaves = 1 << 30;
    auto rng = &mut thread_rng();
    auto replica_id : PedersenDomain = PedersenDomain::random(rng);
    auto seed : [u8; 32] = rng.gen();
    auto partitions = 5;
    auto total_challenges = partitions * n;

    auto mut layers_with_duplicates = 0;

    for (_layer in 1.. = layers) {
        auto mut histogram = HashMap::new ();
        for (k in 0..partitions) {
            auto challenges = challenges.derive(leaves, &replica_id, &seed, k as u8);

            for (challenge in challenges) {
                auto counter = histogram.entry(challenge).or_insert(0);
                *counter += 1;
            }
        }

        auto unique_challenges = histogram.len();
        
        if (unique_challenges < total_challenges) {
                layers_with_duplicates += 1;
        }
    }

    // If we generate 100 layers with 1,000 challenges in each, at most two layers can contain
    // any duplicates for this assertion to succeed.
    //
    // This test could randomly fail (anything's possible), but if it happens regularly something is wrong.
    assert !(layers_with_duplicates < 3);
}

// This test shows that partitioning (k = 0..partitions) generates the same challenges as
// generating the same number of challenges with only one partition (k = 0).
BOOST_AUTO_TEST_CASE(challenge_partition_equivalence) {
    auto n = 40;
    auto leaves = 1 << 30;
    auto rng = &mut thread_rng();
    auto replica_id : PedersenDomain = PedersenDomain::random(rng);
    auto seed : [u8; 32] = rng.gen();
    auto partitions = 5;
    auto layers = 100;
    auto total_challenges = n * partitions;

    for (_layer in 1.. = layers) {
        auto one_partition_challenges =
            LayerChallenges::new (layers, total_challenges).derive(leaves, &replica_id, &seed, 0, );
        auto many_partition_challenges =
            (0..partitions)
                .flat_map(| k | {LayerChallenges::new (layers, n).derive(leaves, &replica_id, &seed, k as u8)})
                .collect::<Vec<_>>();

        assert_eq !(one_partition_challenges, many_partition_challenges);
    }
}

BOOST_AUTO_TEST_SUITE_END()
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

#define BOOST_TEST_MODULE vanilla_cache_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/cache.hpp>

using namespace nil::filecoin;

BOOST_AUTO_TEST_SUITE(vanilla_cache_test_suite)

BOOST_AUTO_TEST_CASE(test_read_full_range) {
    const std::uint32_t nodes = 24;
    const auto graph = StackedBucketGraph::<PoseidonHasher>::new_stacked(std::uint(nodes), BASE_DEGREE, EXP_DEGREE, [0u8; 32], );

    auto cache = ParentCache::new (nodes, nodes, &graph);

    for (node = 0; node < nodes; ++node) {
            auto expected_parents = [0; DEGREE];
            graph.parents(std::uint(node), expected_parents);
            const auto parents = cache.read(node);

            BOOST_CHECK_EQUAL(expected_parents, parents);
        }
}

BOOST_AUTO_TEST_CASE(test_read_partial_range) {
    const std::uint32_t nodes = 48;
    const auto graph = StackedBucketGraph::<PoseidonHasher>::new_stacked(std::uint(nodes), BASE_DEGREE, EXP_DEGREE, [0u8; 32], );

    auto half_cache = ParentCache::new (nodes / 2, nodes, &graph);
    auto quarter_cache = ParentCache::new (nodes / 4, nodes, &graph);

    for (node = 0; node < nodes; ++node) {
        auto expected_parents = [0; DEGREE];
        graph.parents(std::uint(node), expected_parents);

        const auto parents = half_cache.read(node);
        BOOST_CHECK_EQUAL(expected_parents, parents);

        const auto parents = quarter_cache.read(node);
        BOOST_CHECK_EQUAL(expected_parents, parents);

        // some internal checks to make sure the cache works as expected
        BOOST_CHECK_EQUAL(half_cache.cache.data.len() / DEGREE / NODE_BYTES, std::uint(nodes) / 2);
        BOOST_CHECK_EQUAL(quarter_cache.cache.data.len() / DEGREE / NODE_BYTES, std::uint(nodes) / 4);
    }

    half_cache.reset();
    quarter_cache.reset();

    for (node : nodes) {
        auto expected_parents = [0; DEGREE];
        graph.parents(std::uint(node), expected_parents);

        const auto parents = half_cache.read(node);
        BOOST_CHECK_EQUAL(expected_parents, parents);

        const auto parents = quarter_cache.read(node);
        BOOST_CHECK_EQUAL(expected_parents, parents);
    }
}

BOOST_AUTO_TEST_SUITE_END()
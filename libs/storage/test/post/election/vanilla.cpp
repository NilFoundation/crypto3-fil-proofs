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

#define BOOST_TEST_MODULE post_election_vanilla_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/core/sector.hpp>

#include <nil/filecoin/storage/proofs/post/election/vanilla.hpp>

#include "../../core/merkle/generate_tree.hpp"

using namespace nil::filecoin;

BOOST_AUTO_TEST_SUITE(post_election_vanilla_test_suite)

template<typename MerkleTreeType>
void test_election_post() {
    const auto rng = XorShiftRng::from_seed(crate::TEST_SEED);

    std::size_t leaves = 64 * get_base_tree_count<MerkleTreeType>();
    std::size_t sector_size = leaves * NODE_SIZE;

    PublicParams pub_params = {sector_size, 40, 1};

    const auto randomness = typename MerkleTreeType::hash_type::digest_type::random(rng);
    const auto prover_id = typename MerkleTreeType::hash_type::digest_type::random(rng);

    std::vector<SectorId> sectors;
    auto trees = BTreeMap();

    // Construct and store an MT using a named store.
    const auto temp_dir = tempfile::tempdir();
    const auto temp_path = temp_dir.path();

    for (std::size_t i = 0; i < 5; i++) {

        sectors.push(i.into());
        auto data, tree;
        const std::tie(data, tree) = merkletree::generate_tree<Tree>(rng, leaves, Some(temp_path.to_path_buf()));
        trees.insert(i.into(), tree);
    }

    const auto candidates = generate_candidates<MerkleTreeType>(pub_params, sectors, trees, prover_id, randomness);

    const auto candidate = &candidates[0];
    const auto tree = trees.remove(&candidate.sector_id);
    const auto comm_r_last = tree.root();
    const auto comm_c = typename MerkleTreeType::hash_type::digest_type::random(rng);
    const auto comm_r = <typename MerkleTreeType::hash_type>::Function::hash2(&comm_c, &comm_r_last);

    PublicInputs pub_inputs = {randomness, candidate.sector_id, prover_id, comm_r, candidate.partial_ticket, 0};

    PrivateInputs<MerkleTreeType> priv_inputs = {tree, comm_c, comm_r_last};

    
    const auto proof = ElectionPoSt<MerkleTreeType>::prove(&pub_params, &pub_inputs, &priv_inputs);

    bool is_valid = ElectionPoSt<MerkleTreeType>::verify(&pub_params, &pub_inputs, &proof);

    BOOST_CHECK(is_valid);

}

BOOST_AUTO_TEST_CASE(election_post_pedersen) {
    test_election_post<LCTree<PedersenHasher, U8, U0, U0>>();
}

BOOST_AUTO_TEST_CASE(election_post_poseidon) {
    test_election_post<LCTree<PoseidonHasher, U8, U0, U0>>();
}

BOOST_AUTO_TEST_CASE(election_post_poseidon_8_8) {
    test_election_post<LCTree<PoseidonHasher, U8, U8, U0>>();
}

BOOST_AUTO_TEST_CASE(election_post_poseidon_8_8_2) {
    test_election_post<LCTree<PoseidonHasher, U8, U8, U2>>();
}

BOOST_AUTO_TEST_SUITE_END()
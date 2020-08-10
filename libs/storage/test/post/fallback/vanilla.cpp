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

#define BOOST_TEST_MODULE post_fallback_vanilla_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/core/sector.hpp>

#include <nil/filecoin/storage/proofs/post/fallback/vanilla.hpp>

using namespace nil::filecoin;

BOOST_AUTO_TEST_SUITE(post_fallback_vanilla_test_suite)

template<typename MerkleTreeType>
void test_fallback_post() {
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    std::size_t leaves = 64 * get_base_tree_count<MerkleTreeType>();
    std::size_t sector_size = leaves * NODE_SIZE;

    PublicParams pub_params = {sector_size, 40, 1};

    let randomness = <Tree::Hasher as Hasher>::Domain::random(rng);
    let prover_id = <Tree::Hasher as Hasher>::Domain::random(rng);

    std::vector<sector_id_type> sectors;
    let mut trees = BTreeMap::new ();

    // Construct and store an MT using a named store.
    let temp_dir = tempfile::tempdir();
    let temp_path = temp_dir.path();

    for (int i = 0; i < 5; i++) {
        sectors.push_back(i.into());
        let(_data, tree) = generate_tree<MerkleTreeType>(rng, leaves, Some(temp_path.to_path_buf()));
        trees.insert(i.into(), tree);
    }

    let candidates = generate_candidates<MerkleTreeType>(pub_params, sectors, trees, prover_id, randomness);

    let candidate = &candidates[0];
    let tree = trees.remove(&candidate.sector_id);
    let comm_r_last = tree.root();
    let comm_c = <Tree::Hasher as Hasher>::Domain::random(rng);
    let comm_r = <Tree::Hasher as Hasher>::Function::hash2(&comm_c, &comm_r_last);

    PublicInputs pub_inputs = {randomness, candidate.sector_id, prover_id, comm_r, candidate.partial_ticket, 0};

    PrivateInputs<MerkleTreeType> priv_inputs = {tree, comm_c, comm_r_last};

    let proof = ElectionPoSt<MerkleTreeType>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

    let is_valid = ElectionPoSt<MerkleTreeType>::verify(&pub_params, &pub_inputs, &proof)
                       .expect(
                           "verification "
                           "failed");

    BOOST_CHECK(is_valid);
}

BOOST_AUTO_TEST_CASE(fallback_post_pedersen) {
    test_fallback_post<LCTree<PedersenHasher, U8, U0, U0>>();
}

BOOST_AUTO_TEST_CASE(fallback_post_poseidon) {
    test_fallback_post<LCTree<PoseidonHasher, U8, U0, U0>>();
}

BOOST_AUTO_TEST_CASE(fallback_post_poseidon_8_8) {
    test_fallback_post<LCTree<PoseidonHasher, U8, U8, U0>>();
}

BOOST_AUTO_TEST_CASE(fallback_post_poseidon_8_8_2) {
    test_fallback_post<LCTree<PoseidonHasher, U8, U8, U2>>();
}

BOOST_AUTO_TEST_SUITE_END()
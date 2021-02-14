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

#define BOOST_TEST_MODULE post_rational_vanilla_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/core/sector.hpp>

#include <nil/filecoin/storage/proofs/post/rational/vanilla.hpp>

using namespace nil::filecoin;

BOOST_AUTO_TEST_SUITE(post_rational_vanilla_test_suite)

template<typename MerkleTreeType>
void test_rational_post() {
    const auto rng = XorShiftRng::from_seed(crate::TEST_SEED);

    const std::uint64_t leaves = 64 * get_base_tree_count::<Tree>();
    const std::uint64_t sector_size = leaves * 32;
    const std::size_t challenges_count = 8;

    const auto pub_params = PublicParams {
        sector_size,
        challenges_count,
    };

    // Construct and store an MT using a named store.
    const auto temp_dir = tempfile::tempdir();
    const auto temp_path = temp_dir.path();

    const auto(_data1, tree1) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
    const auto(_data2, tree2) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));

    const auto seed = (0..leaves).map(| _ | rng.gen()).collect::<Vec<u8>>();
    auto faults = OrderedSectorSet();
    faults.insert(139.into());
    faults.insert(1.into());
    faults.insert(32.into());

    auto sectors = OrderedSectorSet();
    sectors.insert(891.into());
    sectors.insert(139.into());
    sectors.insert(32.into());
    sectors.insert(1.into());

    auto trees = BTreeMap();
    trees.insert(139.into(), &tree1);    // faulty with tree
    trees.insert(891.into(), &tree2);
    // other two faults don't have a tree available

    const auto challenges = derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults);

    // the only valid sector to challenge is 891
    BOOST_ASSERT_MSG(challenges.iter().all(| c | c.sector == 891.into()), "invalid challenge generated");

    const auto comm_r_lasts = challenges.iter().map(| c | trees.get(&c.sector).root()).collect::<Vec<_>>();

    std::vector<< typename MerkleTreeType::hash_type > ::Domain > comm_cs
        = challenges.iter().map(| _c | <typename MerkleTreeType::hash_type>::Domain::random(rng)).collect();

    std::vector<< typename MerkleTreeType::hash_type > ::Domain > comm_rs
        = comm_cs.iter()
              .zip(comm_r_lasts.iter())
              .map(| (comm_c, comm_r_last) | {<typename MerkleTreeType::hash_type>::Function::hash2(comm_c, comm_r_last)})
              .collect();

    const auto pub_inputs = PublicInputs {
        challenges : &challenges,
        comm_rs : &comm_rs,
        faults : &faults,
    };

    const auto priv_inputs = PrivateInputs::<Tree> {
        trees : &trees,
        comm_cs : &comm_cs,
        comm_r_lasts : &comm_r_lasts,
    };

    const auto proof = RationalPoSt::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

    const auto is_valid = RationalPoSt::<Tree>::verify(&pub_params, &pub_inputs, &proof).expect("verification failed");

    BOOST_ASSERT (is_valid);
}

BOOST_AUTO_TEST_CASE(rational_post_pedersen) {
    test_rational_post::<LCTree<PedersenHasher, U8, U0, U0>>();
}

BOOST_AUTO_TEST_CASE(rational_post_sha256) {
    test_rational_post::<LCTree<Sha256Hasher, U8, U0, U0>>();
}

BOOST_AUTO_TEST_CASE(rational_post_blake2s) {
    test_rational_post<LCTree<Blake2sHasher, U8, U0, U0>>();
}

BOOST_AUTO_TEST_CASE(rational_post_poseidon) {
    test_rational_post<LCTree<PoseidonHasher, U8, U0, U0>>();
}

BOOST_AUTO_TEST_CASE(rational_post_poseidon_8_8) {
    test_rational_post<LCTree<PoseidonHasher, U8, U8, U0>>();
}

BOOST_AUTO_TEST_CASE(rational_post_poseidon_8_8_2) {
    test_rational_post<LCTree<PoseidonHasher, U8, U8, U2>>();
}

template<typename MerkleTreeType>
void test_rational_post_validates_challenge_identity() {
    const auto rng = XorShiftRng::from_seed(crate::TEST_SEED);

    const std::uint64_t leaves = 64 * get_base_tree_count::<Tree>();
    const std::uint64_t sector_size = leaves * 32;
    const std::size_t challenges_count = 2;

    const auto pub_params = PublicParams {
        sector_size,
        challenges_count,
    };

    // Construct and store an MT using a named store.
    const auto temp_dir = tempfile::tempdir();
    const auto temp_path = temp_dir.path();

    const auto(_data, tree) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
    const auto seed = (0..leaves).map(| _ | rng.gen()).collect::<Vec<u8>>();
    auto faults = OrderedSectorSet();
    faults.insert(1.into());
    auto sectors = OrderedSectorSet();
    sectors.insert(0.into());
    sectors.insert(1.into());

    auto trees = BTreeMap();
    trees.insert(0.into(), &tree);

    const auto challenges = derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults);
    const auto comm_r_lasts = challenges.iter().map(| c | trees.get(&c.sector).root()).collect::<Vec<_>>();

    const std::vector<< typename MerkleTreeType::hash_type > ::Domain > comm_cs
        = challenges.iter().map(| _c | <typename MerkleTreeType::hash_type>::Domain::random(rng)).collect();

    const std::vector<< typename MerkleTreeType::hash_type > ::Domain > comm_rs
        = comm_cs.iter()
              .zip(comm_r_lasts.iter())
              .map(| (comm_c, comm_r_last) | {<typename MerkleTreeType::hash_type>::Function::hash2(comm_c, comm_r_last)})
              .collect();

    const auto pub_inputs = PublicInputs {
        challenges : &challenges,
        faults : &faults,
        comm_rs : &comm_rs,
    };

    const auto priv_inputs = PrivateInputs::<Tree> {
        trees : &trees,
        comm_cs : &comm_cs,
        comm_r_lasts : &comm_r_lasts,
    };

    const auto proof = RationalPoSt::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

    const auto seed = (0..leaves).map(| _ | rng.gen()).collect::<Vec<u8>>();
    const auto challenges = derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults);
    const auto comm_r_lasts = challenges.iter().map(| _c | tree.root()).collect::<Vec<_>>();

    const std::vector << typename MerkleTreeType::hash_type > ::Domain > comm_cs
        = challenges.iter().map(| _c | <typename MerkleTreeType::hash_type>::Domain::random(rng)).collect();

    const std::vector << typename MerkleTreeType::hash_type > ::Domain > comm_rs
        = comm_cs.iter()
              .zip(comm_r_lasts.iter())
              .map(| (comm_c, comm_r_last) | {<typename MerkleTreeType::hash_type>::Function::hash2(comm_c, comm_r_last)})
              .collect();

    const auto different_pub_inputs = PublicInputs {
        challenges : &challenges,
        faults : &faults,
        comm_rs : &comm_rs,
    };

    const auto verified = RationalPoSt::<Tree>::verify(&pub_params, &different_pub_inputs, &proof);

    // A proof created with a the wrong challenge not be verified!
    BOOST_CHECK(!verified);
}

BOOST_AUTO_TEST_CASE(rational_post_actually_validates_challenge_identity_sha256) {
    test_rational_post_validates_challenge_identity<LCTree<Sha256Hasher, U8, U0, U0>>();
}

BOOST_AUTO_TEST_CASE(rational_post_actually_validates_challenge_identity_blake2s) {
    test_rational_post_validates_challenge_identity<LCTree<Blake2sHasher, U8, U0, U0>>();
}

BOOST_AUTO_TEST_CASE(rational_post_actually_validates_challenge_identity_pedersen) {
    test_rational_post_validates_challenge_identity<LCTree<PedersenHasher, U8, U0, U0>>();
}

BOOST_AUTO_TEST_CASE(rational_post_actually_validates_challenge_identity_poseidon) {
    test_rational_post_validates_challenge_identity<LCTree<PoseidonHasher, U8, U0, U0>>();
}

BOOST_AUTO_TEST_CASE(rational_post_actually_validates_challenge_identity_poseidon_8_8) {
    test_rational_post_validates_challenge_identity<LCTree<PoseidonHasher, U8, U8, U0>>();
}

BOOST_AUTO_TEST_CASE(rational_post_actually_validates_challenge_identity_poseidon_8_8_2) {
    test_rational_post_validates_challenge_identity<LCTree<PoseidonHasher, U8, U8, U2>>();
}

BOOST_AUTO_TEST_CASE(test_derive_challenges_fails_on_all_faulty) {
    use std::collections::BTreeSet;

    auto sectors = BTreeSet();
    sectors.insert(SectorId::from(1));
    sectors.insert(SectorId::from(2));

    auto faults = BTreeSet();
    faults.insert(SectorId::from(1));
    faults.insert(SectorId::from(2));

    const std::vector<auto> seed = {0u8};

    BOOST_ASSERT (derive_challenges(10, 1024, &sectors, &seed, &faults).is_err());
}

BOOST_AUTO_TEST_SUITE_END()
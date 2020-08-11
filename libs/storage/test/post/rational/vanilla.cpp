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
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    let leaves = 64 * get_base_tree_count::<Tree>();
    let sector_size = leaves as u64 * 32;
    let challenges_count = 8;

    let pub_params = PublicParams {
        sector_size,
        challenges_count,
    };

    // Construct and store an MT using a named store.
    let temp_dir = tempfile::tempdir();
    let temp_path = temp_dir.path();

    let(_data1, tree1) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
    let(_data2, tree2) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));

    let seed = (0..leaves).map(| _ | rng.gen()).collect::<Vec<u8>>();
    let mut faults = OrderedSectorSet::new ();
    faults.insert(139.into());
    faults.insert(1.into());
    faults.insert(32.into());

    let mut sectors = OrderedSectorSet::new ();
    sectors.insert(891.into());
    sectors.insert(139.into());
    sectors.insert(32.into());
    sectors.insert(1.into());

    let mut trees = BTreeMap::new ();
    trees.insert(139.into(), &tree1);    // faulty with tree
    trees.insert(891.into(), &tree2);
    // other two faults don't have a tree available

    let challenges = derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults);

    // the only valid sector to challenge is 891
    assert !(challenges.iter().all(| c | c.sector == 891.into()), "invalid challenge generated");

    let comm_r_lasts = challenges.iter().map(| c | trees.get(&c.sector).root()).collect::<Vec<_>>();

    let comm_cs : Vec << MerkleTreeType::Hasher as Hasher > ::Domain >
        = challenges.iter().map(| _c | <MerkleTreeType::Hasher as Hasher>::Domain::random(rng)).collect();

    let comm_rs : Vec << MerkleTreeType::Hasher as Hasher > ::Domain >
        = comm_cs.iter()
              .zip(comm_r_lasts.iter())
              .map(| (comm_c, comm_r_last) | {<MerkleTreeType::Hasher as Hasher>::Function::hash2(comm_c, comm_r_last)})
              .collect();

    let pub_inputs = PublicInputs {
        challenges : &challenges,
        comm_rs : &comm_rs,
        faults : &faults,
    };

    let priv_inputs = PrivateInputs::<Tree> {
        trees : &trees,
        comm_cs : &comm_cs,
        comm_r_lasts : &comm_r_lasts,
    };

    let proof = RationalPoSt::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

    let is_valid = RationalPoSt::<Tree>::verify(&pub_params, &pub_inputs, &proof).expect("verification failed");

    assert !(is_valid);
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
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    let leaves = 64 * get_base_tree_count::<Tree>();
    let sector_size = leaves as u64 * 32;
    let challenges_count = 2;

    let pub_params = PublicParams {
        sector_size,
        challenges_count,
    };

    // Construct and store an MT using a named store.
    let temp_dir = tempfile::tempdir();
    let temp_path = temp_dir.path();

    let(_data, tree) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
    let seed = (0..leaves).map(| _ | rng.gen()).collect::<Vec<u8>>();
    let mut faults = OrderedSectorSet::new ();
    faults.insert(1.into());
    let mut sectors = OrderedSectorSet::new ();
    sectors.insert(0.into());
    sectors.insert(1.into());

    let mut trees = BTreeMap::new ();
    trees.insert(0.into(), &tree);

    let challenges = derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults);
    let comm_r_lasts = challenges.iter().map(| c | trees.get(&c.sector).root()).collect::<Vec<_>>();

    let comm_cs : Vec << MerkleTreeType::Hasher as Hasher > ::Domain >
        = challenges.iter().map(| _c | <MerkleTreeType::Hasher as Hasher>::Domain::random(rng)).collect();

    let comm_rs : Vec << MerkleTreeType::Hasher as Hasher > ::Domain >
        = comm_cs.iter()
              .zip(comm_r_lasts.iter())
              .map(| (comm_c, comm_r_last) | {<MerkleTreeType::Hasher as Hasher>::Function::hash2(comm_c, comm_r_last)})
              .collect();

    let pub_inputs = PublicInputs {
        challenges : &challenges,
        faults : &faults,
        comm_rs : &comm_rs,
    };

    let priv_inputs = PrivateInputs::<Tree> {
        trees : &trees,
        comm_cs : &comm_cs,
        comm_r_lasts : &comm_r_lasts,
    };

    let proof = RationalPoSt::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

    let seed = (0..leaves).map(| _ | rng.gen()).collect::<Vec<u8>>();
    let challenges = derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults);
    let comm_r_lasts = challenges.iter().map(| _c | tree.root()).collect::<Vec<_>>();

    let comm_cs : Vec << MerkleTreeType::Hasher as Hasher > ::Domain >
        = challenges.iter().map(| _c | <MerkleTreeType::Hasher as Hasher>::Domain::random(rng)).collect();

    let comm_rs : Vec << MerkleTreeType::Hasher as Hasher > ::Domain >
        = comm_cs.iter()
              .zip(comm_r_lasts.iter())
              .map(| (comm_c, comm_r_last) | {<MerkleTreeType::Hasher as Hasher>::Function::hash2(comm_c, comm_r_last)})
              .collect();

    let different_pub_inputs = PublicInputs {
        challenges : &challenges,
        faults : &faults,
        comm_rs : &comm_rs,
    };

    let verified =
        RationalPoSt::<Tree>::verify(&pub_params, &different_pub_inputs, &proof).expect("verification failed");

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

    let mut sectors = BTreeSet::new ();
    sectors.insert(SectorId::from(1));
    sectors.insert(SectorId::from(2));

    let mut faults = BTreeSet::new ();
    faults.insert(SectorId::from(1));
    faults.insert(SectorId::from(2));

    let seed = vec ![0u8];

    assert !(derive_challenges(10, 1024, &sectors, &seed, &faults).is_err());
}

BOOST_AUTO_TEST_SUITE_END()
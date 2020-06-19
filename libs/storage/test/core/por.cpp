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

#define BOOST_TEST_MODULE por_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/core/por.hpp>

BOOST_AUTO_TEST_SUITE(por_test_suite)

template<typename MerkleTreeType>
void test_merklepor() {
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    let leaves = 16;
    let pub_params = PublicParams {
        leaves,
        private : false,
    };

    let data : Vec<u8> = (0..leaves).flat_map(| _ | fr_into_bytes(&Fr::random(rng))).collect();
    let porep_id = [3; 32];
    let graph = BucketGraph::<Tree::Hasher>::new (leaves, BASE_DEGREE, 0, porep_id).unwrap();
    let tree = create_base_merkle_tree::<Tree>(None, graph.size(), data.as_slice()).unwrap();

    let pub_inputs = PublicInputs {
        challenge : 3,
        commitment : Some(tree.root()),
    };

    let leaf =
        <Tree::Hasher as Hasher>::Domain::try_from_bytes(data_at_node(data.as_slice(), pub_inputs.challenge).unwrap(), )
            .unwrap();

    let priv_inputs = PrivateInputs::new (leaf, &tree);

    let proof = PoR::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

    let is_valid = PoR::<Tree>::verify(&pub_params, &pub_inputs, &proof).expect("verification failed");

    assert !(is_valid);
}

type TestTree<H, U> = MerkleTreeWrapper<H, DiskStore << H as Hasher>::Domain >, U, typenum::U0, typenum::U0 > ;

BOOST_AUTO_TEST_CASE(merklepor_pedersen_binary) {
    test_merklepor::<TestTree<PedersenHasher, typenum::U2>>();
}

BOOST_AUTO_TEST_CASE(merklepor_poseidon_binary) {
    test_merklepor::<TestTree<PoseidonHasher, typenum::U2>>();
}

BOOST_AUTO_TEST_CASE(merklepor_sha256_binary) {
    test_merklepor::<TestTree<Sha256Hasher, typenum::U2>>();
}

BOOST_AUTO_TEST_CASE(merklepor_blake2s_binary) {
    test_merklepor::<TestTree<Blake2sHasher, typenum::U2>>();
}

BOOST_AUTO_TEST_CASE(merklepor_pedersen_quad) {
    test_merklepor::<TestTree<PedersenHasher, typenum::U4>>();
}

BOOST_AUTO_TEST_CASE(merklepor_poseidon_quad) {
    test_merklepor::<TestTree<PoseidonHasher, typenum::U4>>();
}

BOOST_AUTO_TEST_CASE(merklepor_sha256_quad) {
    test_merklepor::<TestTree<Sha256Hasher, typenum::U4>>();
}

BOOST_AUTO_TEST_CASE(merklepor_blake2s_quad) {
    test_merklepor::<TestTree<Blake2sHasher, typenum::U4>>();
}

// Takes a valid proof and breaks it.
fn make_bogus_proof<Proof : MerkleProofTrait>(rng
                                              : &mut XorShiftRng, mut proof
                                              : DataProof<Proof>, )
    ->DataProof<Proof> {
    let bogus_leaf = <Proof::Hasher as Hasher>::Domain::random(rng);
    proof.proof.break_me(bogus_leaf);
    proof
}

fn test_merklepor_validates<Tree : MerkleTreeTrait>() {
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    let leaves = 64;
    let pub_params = PublicParams {
        leaves,
        private : false,
    };

    let data : Vec<u8> = (0..leaves).flat_map(| _ | fr_into_bytes(&Fr::random(rng))).collect();

    let porep_id = [99; 32];

    let graph = BucketGraph::<Tree::Hasher>::new (leaves, BASE_DEGREE, 0, porep_id).unwrap();
    let tree = create_base_merkle_tree::<Tree>(None, graph.size(), data.as_slice()).unwrap();

    let pub_inputs = PublicInputs {
        challenge : 3,
        commitment : Some(tree.root()),
    };

    let leaf =
        <Tree::Hasher as Hasher>::Domain::try_from_bytes(data_at_node(data.as_slice(), pub_inputs.challenge).unwrap(), )
            .unwrap();

    let priv_inputs = PrivateInputs::<Tree>::new (leaf, &tree);

    let good_proof = PoR::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

    let verified = PoR::<Tree>::verify(&pub_params, &pub_inputs, &good_proof).expect("verification failed");
    assert !(verified);

    let bad_proof = make_bogus_proof::<Tree::Proof>(rng, good_proof);

    let verified = PoR::<Tree>::verify(&pub_params, &pub_inputs, &bad_proof).expect("verification failed");

    // A bad proof should not be verified!
    assert !(!verified);
}

BOOST_AUTO_TEST_CASE(merklepor_actually_validates_sha256_binary) {
    test_merklepor_validates::<TestTree<Sha256Hasher, typenum::U2>>();
}

BOOST_AUTO_TEST_CASE(merklepor_actually_validates_blake2s_binary) {
    test_merklepor_validates::<TestTree<Blake2sHasher, typenum::U2>>();
}

BOOST_AUTO_TEST_CASE(merklepor_actually_validates_pedersen_binary) {
    test_merklepor_validates::<TestTree<PedersenHasher, typenum::U2>>();
}

BOOST_AUTO_TEST_CASE(merklepor_actually_validates_poseidon_binary) {
    test_merklepor_validates::<TestTree<PoseidonHasher, typenum::U2>>();
}

BOOST_AUTO_TEST_CASE(merklepor_actually_validates_sha256_quad) {
    test_merklepor_validates::<TestTree<Sha256Hasher, typenum::U4>>();
}

BOOST_AUTO_TEST_CASE(merklepor_actually_validates_blake2s_quad) {
    test_merklepor_validates::<TestTree<Blake2sHasher, typenum::U4>>();
}

BOOST_AUTO_TEST_CASE(merklepor_actually_validates_pedersen_quad) {
    test_merklepor_validates::<TestTree<PedersenHasher, typenum::U4>>();
}

BOOST_AUTO_TEST_CASE(merklepor_actually_validates_poseidon_quad) {
    test_merklepor_validates::<TestTree<PoseidonHasher, typenum::U4>>();
}

template<typename MerkleTreeType>
void test_merklepor_validates_challenge_identity() {
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    let leaves = 64;

    let pub_params = PublicParams {
        leaves,
        private : false,
    };

    let data : Vec<u8> = (0..leaves).flat_map(| _ | fr_into_bytes(&Fr::random(rng))).collect();

    let porep_id = [32; 32];
    let graph = BucketGraph::<Tree::Hasher>::new (leaves, BASE_DEGREE, 0, porep_id).unwrap();
    let tree = create_base_merkle_tree::<Tree>(None, graph.size(), data.as_slice()).unwrap();

    let pub_inputs = PublicInputs {
        challenge : 3,
        commitment : Some(tree.root()),
    };

    let leaf =
        <Tree::Hasher as Hasher>::Domain::try_from_bytes(data_at_node(data.as_slice(), pub_inputs.challenge).unwrap(), )
            .unwrap();

    let priv_inputs = PrivateInputs::<Tree>::new (leaf, &tree);

    let proof = PoR::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

    let different_pub_inputs = PublicInputs {
        challenge : 999,
        commitment : Some(tree.root()),
    };

    let verified = PoR::<Tree>::verify(&pub_params, &different_pub_inputs, &proof).expect("verification failed");

    // A proof created with a the wrong challenge not be verified!
    assert !(!verified);
}

BOOST_AUTO_TEST_CASE(merklepor_actually_validates_challenge_identity_sha256_binary) {
    test_merklepor_validates_challenge_identity::<TestTree<Sha256Hasher, typenum::U2>>();
}

BOOST_AUTO_TEST_CASE(merklepor_actually_validates_challenge_identity_blake2s_binary) {
    test_merklepor_validates_challenge_identity::<TestTree<Blake2sHasher, typenum::U2>>();
}

BOOST_AUTO_TEST_CASE(merklepor_actually_validates_challenge_identity_pedersen_binary) {
    test_merklepor_validates_challenge_identity::<TestTree<PedersenHasher, typenum::U2>>();
}

BOOST_AUTO_TEST_CASE(merklepor_actually_validates_challenge_identity_poseidon_binary) {
    test_merklepor_validates_challenge_identity::<TestTree<PoseidonHasher, typenum::U2>>();
}

BOOST_AUTO_TEST_CASE(merklepor_actually_validates_challenge_identity_sha256_quad) {
    test_merklepor_validates_challenge_identity::<TestTree<Sha256Hasher, typenum::U4>>();
}

BOOST_AUTO_TEST_CASE(merklepor_actually_validates_challenge_identity_blake2s_quad) {
    test_merklepor_validates_challenge_identity::<TestTree<Blake2sHasher, typenum::U4>>();
}

BOOST_AUTO_TEST_CASE(merklepor_actually_validates_challenge_identity_pedersen_quad) {
    test_merklepor_validates_challenge_identity::<TestTree<PedersenHasher, typenum::U4>>();
}

BOOST_AUTO_TEST_CASE(merklepor_actually_validates_challenge_identity_poseidon_quad) {
    test_merklepor_validates_challenge_identity::<TestTree<PoseidonHasher, typenum::U4>>();
}

BOOST_AUTO_TEST_SUITE_END()
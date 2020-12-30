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

#define BOOST_TEST_MODULE por_component_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/core/components/por.hpp>

BOOST_AUTO_TEST_SUITE(por_component_test_suite)

type TestTree<H, A> = MerkleTreeWrapper<H, VecStore << H>::Domain >, A, 0, 0 > ;

type TestTree2<H, A, B> = MerkleTreeWrapper<H, VecStore << H>::Domain >, A, B, 0 > ;

type TestTree3<H, A, B, C> = MerkleTreeWrapper<H, VecStore << H>::Domain >, A, B, C > ;

BOOST_AUTO_TEST_CASE(por_test_compound_poseidon_base_8) {
    por_compound<TestTree<PoseidonHasher, 8>>();
}

template<typename MerkleTreeType>
void por_compound() {
    auto rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    std::size_t leaves = 64 * get_base_tree_count<MerkleTreeType>();

std::vector<std::uint8_t> data = (0..leaves).flat_map(| _ | fr_into_bytes(&Fr::random(rng))).collect();
auto tree = create_base_merkle_tree<MerkleTreeType>(None, leaves, data.as_slice());

auto public_inputs = por::PublicInputs {
    challenge : 2,
    commitment : Some(tree.root()),
};

auto setup_params = compound_proof::SetupParams {
    vanilla_params : por::SetupParams {
        leaves,
        private : false,
    },
    partitions : None,
    priority : false,
};
auto public_params = PoRCompound<MerkleTreeType>::setup(&setup_params).expect("setup failed");

auto private_inputs =
    por::PrivateInputs<MerkleTreeType>::new (bytes_into_fr(data_at_node(data.as_slice(), public_inputs.challenge))
                                         .expect("failed to create Fr from node data")
                                         .into(),
                                     &tree, );

auto gparams = PoRCompound<MerkleTreeType>::groth_params(Some(rng), &public_params.vanilla_params)
                  .expect("failed to generate groth params");

auto proof = PoRCompound<MerkleTreeType>::prove(&public_params, &public_inputs, &private_inputs, &gparams)
                .expect("failed while proving");

auto verified = PoRCompound<MerkleTreeType>::verify(&public_params, &public_inputs, &proof, &NoRequirements)
                   .expect("failed while verifying");
assert !(verified);

auto(circuit, inputs) = PoRCompound<MerkleTreeType>::circuit_for_test(&public_params, &public_inputs, &private_inputs);

auto mut cs = TestConstraintSystem::new ();

circuit.synthesize(&mut cs).expect("failed to synthesize");
assert !(cs.is_satisfied());
assert !(cs.verify(&inputs));
}

    BOOST_AUTO_TEST_CASE(test_por_circuit_pedersen_base_2) {
    test_por_circuit::<TestTree<PedersenHasher, 2>>(3, 8_247);
}

    BOOST_AUTO_TEST_CASE(test_por_circuit_blake2s_base_2) {
    test_por_circuit::<TestTree<Blake2sHasher, 2>>(3, 129_135);
}

    BOOST_AUTO_TEST_CASE(test_por_circuit_sha256_base_2) {
    test_por_circuit::<TestTree<Sha256Hasher, 2>>(3, 272_295);
}

    BOOST_AUTO_TEST_CASE(test_por_circuit_poseidon_base_2) {
    test_por_circuit::<TestTree<PoseidonHasher, 2>>(3, 1887);
}

    BOOST_AUTO_TEST_CASE(test_por_circuit_pedersen_base_4) {
    test_por_circuit::<TestTree<PedersenHasher, 4>>(3, 12399);
}

    BOOST_AUTO_TEST_CASE(test_por_circuit_pedersen_sub_8_2) {
    test_por_circuit::<TestTree2<PedersenHasher, 8, 2>>(3, 20663);
}

    BOOST_AUTO_TEST_CASE(test_por_circuit_pedersen_top_8_4_2) {
    test_por_circuit::<TestTree3<PedersenHasher, 8, 4, 2>>(3, 24795);
}

    BOOST_AUTO_TEST_CASE(test_por_circuit_pedersen_top_8_2_4) {
    // We can handle top-heavy trees with a non-zero subtree arity.
    // These should never be produced, though.
    test_por_circuit::<TestTree3<PedersenHasher, 8, 2, 4>>(3, 24795);
}

    BOOST_AUTO_TEST_CASE(test_por_circuit_blake2s_base_4) {
    test_por_circuit::<TestTree<Blake2sHasher, 4>>(3, 130296);
}

    BOOST_AUTO_TEST_CASE(test_por_circuit_sha256_base_4) {
    test_por_circuit::<TestTree<Sha256Hasher, 4>>(3, 216258);
}

BOOST_AUTO_TEST_CASE(test_por_circuit_poseidon_base_4) {
    test_por_circuit::<TestTree<PoseidonHasher, 4>>(3, 1164);
}

BOOST_AUTO_TEST_CASE(test_por_circuit_pedersen_base_8) {
    test_por_circuit::<TestTree<PedersenHasher, 8>>(3, 19289);
}

BOOST_AUTO_TEST_CASE(test_por_circuit_blake2s_base_8) {
    test_por_circuit::<TestTree<Blake2sHasher, 8>>(3, 174503);
}

BOOST_AUTO_TEST_CASE(test_por_circuit_sha256_base_8) {
    test_por_circuit::<TestTree<Sha256Hasher, 8>>(3, 250987);
}

BOOST_AUTO_TEST_CASE(test_por_circuit_poseidon_base_8) {
    test_por_circuit::<TestTree<PoseidonHasher, 8>>(3, 1063);
}

BOOST_AUTO_TEST_CASE(test_por_circuit_poseidon_sub_8_2) {
    test_por_circuit::<TestTree2<PoseidonHasher, 8, 2>>(3, 1377);
}

BOOST_AUTO_TEST_CASE(test_por_circuit_poseidon_top_8_4_2) {
    test_por_circuit::<TestTree3<PoseidonHasher, 8, 4, 2>>(3, 1764);
}

BOOST_AUTO_TEST_CASE(test_por_circuit_poseidon_top_8_8) {
    // This is the shape we want for 32GiB sectors.
    test_por_circuit::<TestTree2<PoseidonHasher, 8, 8>>(3, 1593);
}
BOOST_AUTO_TEST_CASE(test_por_circuit_poseidon_top_8_8_2) {
    // This is the shape we want for 64GiB secotrs.
    test_por_circuit::<TestTree3<PoseidonHasher, 8, 8, 2>>(3, 1907);
}

BOOST_AUTO_TEST_CASE(test_por_circuit_poseidon_top_8_2_4() {
    // We can handle top-heavy trees with a non-zero subtree arity.
    // These should never be produced, though.
    test_por_circuit::<TestTree3<PoseidonHasher, 8, 2, 4>>(3, 1764);
}

fn test_por_circuit<Tree: static + MerkleTreeTrait>(std::uint num_inputs, std::uint num_constraints) {
    auto rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    // Ensure arity will evenly fill tree.
    auto leaves = 64 * get_base_tree_count<MerkleTreeType>();

    // -- Basic Setup
    auto(data, tree) = generate_tree::<Tree, _>(rng, leaves, None);

    for (auto i = 0; i < leaves; ++i) {
        // println!("challenge: {}, ({})", i, leaves);

        // -- PoR
        auto pub_params = por::PublicParams {
            leaves,
            private : false,
        };
        auto pub_inputs = por::PublicInputs:: << typename MerkleTreeType::hash_type > ::Domain > {
            challenge : i,
            commitment : Some(tree.root()),
        };
        auto leaf = data_at_node(data.as_slice(), pub_inputs.challenge);
        auto leaf_element = <typename MerkleTreeType::hash_type>::Domain::try_from_bytes(leaf);
        auto priv_inputs = por::PrivateInputs::<ResTree<MerkleTreeType>>::new (leaf_element, &tree);
        auto p = tree.gen_proof(i);
        assert !(p.verify());

        // create a non circuit proof
        auto proof = por::PoR::<ResTree<MerkleTreeType>>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

        // make sure it verifies
        auto is_valid =
            por::PoR::<ResTree<MerkleTreeType>>::verify(&pub_params, &pub_inputs, &proof).expect("verification failed");
        assert !(is_valid, "failed to verify por proof");

        // -- Circuit

        auto mut cs = TestConstraintSystem<algebra::curves::bls12<381>>::new ();
        auto por = PoRCircuit::<ResTree<MerkleTreeType>> {
            value : Root::Val(Some(proof.data.into())),
            auth_path : proof.proof.as_options().into(),
            root : Root::Val(Some(pub_inputs.commitment.into())),
            private : false,
            _tree : PhantomData,
        };

        por.synthesize(&mut cs).expect("circuit synthesis failed");
        assert !(cs.is_satisfied(), "constraints not satisfied");

        assert_eq !(cs.num_inputs(), num_inputs, "wrong number of inputs");
        assert_eq !(cs.num_constraints(), num_constraints, "wrong number of constraints");

        auto generated_inputs =
            PoRCompound::<ResTree<MerkleTreeType>>::generate_public_inputs(&pub_inputs, &pub_params, None, );

        auto expected_inputs = cs.get_inputs();

        for ((input, label), generated_input)
            in expected_inputs.iter().skip(1).zip(generated_inputs.iter()) {
                assert_eq !(input, generated_input, "{}", label);
            }

        assert_eq !(generated_inputs.len(), expected_inputs.len() - 1, "inputs are not the same length");

        assert !(cs.verify(&generated_inputs), "failed to verify inputs");
    }
}

#[ignore] // Slow test – run only when compiled for release.
BOOST_AUTO_TEST_CASE(test_private_por_compound_pedersen_base_2() {
    private_por_test_compound::<TestTree<PedersenHasher, 2>>();
}

#[ignore] // Slow test – run only when compiled for release.
BOOST_AUTO_TEST_CASE(test_private_por_compound_pedersen_base_4() {
    private_por_test_compound::<TestTree<PedersenHasher, 4>>();
}

#[ignore] // Slow test – run only when compiled for release.
BOOST_AUTO_TEST_CASE(test_private_por_compound_poseidon_base_2() {
    private_por_test_compound::<TestTree<PoseidonHasher, 2>>();
}

#[ignore] // Slow test – run only when compiled for release.
BOOST_AUTO_TEST_CASE(test_private_por_compound_poseidon_base_4() {
    private_por_test_compound::<TestTree<PoseidonHasher, 4>>();
}

#[ignore] // Slow test – run only when compiled for release.
BOOST_AUTO_TEST_CASE(test_private_por_compound_poseidon_sub_8_2() {
    private_por_test_compound::<TestTree2<PoseidonHasher, 8, 2>>();
}

#[ignore] // Slow test – run only when compiled for release.
BOOST_AUTO_TEST_CASE(test_private_por_compound_poseidon_top_8_4_2() {
    private_por_test_compound::<TestTree3<PoseidonHasher, 8, 4, 2>>();
}

#[ignore] // Slow test – run only when compiled for release.
BOOST_AUTO_TEST_CASE(test_private_por_compound_poseidon_top_8_8() {
    private_por_test_compound::<TestTree2<PoseidonHasher, 8, 8>>();
}

#[ignore] // Slow test – run only when compiled for release.
BOOST_AUTO_TEST_CASE(test_private_por_compound_poseidon_top_8_8_2() {
    private_por_test_compound::<TestTree3<PoseidonHasher, 8, 8, 2>>();
}

#[ignore] // Slow test – run only when compiled for release.
BOOST_AUTO_TEST_CASE(test_private_por_compound_poseidon_top_8_2_4() {
    private_por_test_compound::<TestTree3<PoseidonHasher, 8, 2, 4>>();
}

fn private_por_test_compound < Tree
    : static + MerkleTreeTrait>() { auto rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    // Ensure arity will evenly fill tree.
    auto leaves = 64 * get_base_tree_count<MerkleTreeType>();

    // -- Basic Setup
    auto(data, tree) = generate_tree::<Tree, _>(rng, leaves, None);

    for (std::size_t i = 0; i < 3; ++i) {
        auto public_inputs = por::PublicInputs {
            challenge : i,
            commitment : None,
        };

        auto setup_params = compound_proof::SetupParams {
            vanilla_params : por::SetupParams {
                leaves,
                private : true,
            },
            partitions : None,
            priority : false,
        };
        auto public_params = PoRCompound::<ResTree<MerkleTreeType>>::setup(&setup_params).expect("setup failed");

        auto private_inputs = por::PrivateInputs::<ResTree<MerkleTreeType>>::new (
            bytes_into_fr(data_at_node(data.as_slice(), public_inputs.challenge))
                .expect("failed to create Fr from node data")
                .into(),
            &tree, );

        auto(circuit, inputs) =
            PoRCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs);

        auto mut cs = TestConstraintSystem::new ();

        circuit.synthesize(&mut cs).expect("failed to synthesize");

        if (!cs.is_satisfied()) {
                panic !("failed to satisfy: {:?}", cs.which_is_unsatisfied());
            }
        assert !(cs.verify(&inputs), "verification failed with TestContraintSystem and generated inputs");

        // NOTE: This diagnostic code currently fails, even though the proof generated from the blank circuit verifies.
        // Use this to debug differences between blank and regular circuit generation.
        auto(circuit1, _inputs) =
            PoRCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs);
        auto blank_circuit = PoRCompound::<ResTree<MerkleTreeType>>::blank_circuit(&public_params.vanilla_params);

        auto mut cs_blank = MetricCS::new ();
        blank_circuit.synthesize(&mut cs_blank).expect("failed to synthesize");

        auto a = cs_blank.pretty_print_list();

        auto mut cs1 = TestConstraintSystem::new ();
        circuit1.synthesize(&mut cs1).expect("failed to synthesize");
        auto b = cs1.pretty_print_list();

        for (i, (a, b)) in a.chunks(100).zip(b.chunks(100)).enumerate() {
            assert_eq !(a, b, "failed at chunk {}", i);
        }

        auto blank_groth_params = PoRCompound::<ResTree<MerkleTreeType>>::groth_params(Some(rng), &public_params.vanilla_params, )
                                     .expect("failed to generate groth params");

        auto proof = PoRCompound::prove(&public_params, &public_inputs, &private_inputs, &blank_groth_params, )
                        .expect("failed while proving");

        auto verified = PoRCompound::verify(&public_params, &public_inputs, &proof, &NoRequirements)
                           .expect("failed while verifying");

        assert !(verified);
    }
}

BOOST_AUTO_TEST_CASE(test_private_por_input_circuit_pedersen_binary() {
    test_private_por_input_circuit::<TestTree<PedersenHasher, 2>>(8_246);
}

BOOST_AUTO_TEST_CASE(test_private_por_input_circuit_poseidon_binary() {
    test_private_por_input_circuit::<TestTree<PoseidonHasher, 2>>(1_886);
}

BOOST_AUTO_TEST_CASE(test_private_por_input_circuit_pedersen_quad() {
    test_private_por_input_circuit::<TestTree<PedersenHasher, 4>>(12_398);
}

BOOST_AUTO_TEST_CASE(test_private_por_input_circuit_poseidon_quad() {
    test_private_por_input_circuit::<TestTree<PoseidonHasher, 4>>(1_163);
}

BOOST_AUTO_TEST_CASE(test_private_por_input_circuit_poseidon_oct() {
    test_private_por_input_circuit::<TestTree<PoseidonHasher, 8>>(1_062);
}

fn test_private_por_input_circuit<Tree : MerkleTreeTrait>(num_constraints : usize) {
    auto rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    std::size_t leaves = 64 * get_base_tree_count<MerkleTreeType>();
    for (std::size_t i = 0; i < leaves; ++i) {
        // -- Basic Setup

        auto data : Vec<u8> = (0..leaves).flat_map(| _ | fr_into_bytes(&Fr::random(rng))).collect();

        auto tree = create_base_merkle_tree<MerkleTreeType>(None, leaves, data.as_slice());

        // -- PoR

        auto pub_params = por::PublicParams {
            leaves,
            private : true,
        };
        auto pub_inputs = por::PublicInputs {
            challenge : i,
            commitment : None,
        };

        auto priv_inputs = por::PrivateInputs<MerkleTreeType>::new (
            bytes_into_fr(data_at_node(data.as_slice(), pub_inputs.challenge)).into(), &tree, );

        // create a non circuit proof
        auto proof = por::PoR<MerkleTreeType>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

        // make sure it verifies
        auto is_valid = por::PoR<MerkleTreeType>::verify(&pub_params, &pub_inputs, &proof).expect("verification failed");
        assert !(is_valid, "failed to verify por proof");

        // -- Circuit

        auto mut cs = TestConstraintSystem::<algebra::curves::bls12<381>>::new ();

        auto por = PoRCircuit<MerkleTreeType> {
            value : Root::Val(Some(proof.data.into())),
            auth_path : proof.proof.as_options().into(),
            root : Root::Val(Some(tree.root().into())),
            private : true,
            _tree : PhantomData,
        };

        por.synthesize(&mut cs).expect("circuit synthesis failed");
        assert !(cs.is_satisfied(), "constraints not satisfied");

        assert_eq !(cs.num_inputs(), 2, "wrong number of inputs");
        assert_eq !(cs.num_constraints(), num_constraints, "wrong number of constraints");

        auto auth_path_bits = challenge_into_auth_path_bits(pub_inputs.challenge, pub_params.leaves);
        auto packed_auth_path = multipack::compute_multipacking::<algebra::curves::bls12<381>>(&auth_path_bits);

        auto mut expected_inputs = Vec::new ();
        expected_inputs.extend(packed_auth_path);

        assert_eq !(cs.get_input(0, "ONE"), Fr::one(), "wrong input 0");

        assert_eq !(cs.get_input(1, "path/input 0"), expected_inputs[0], "wrong packed_auth_path");

        assert !(cs.is_satisfied(), "constraints are not all satisfied");
        assert !(cs.verify(&expected_inputs), "failed to verify inputs");
    }
}
}

BOOST_AUTO_TEST_SUITE_END()
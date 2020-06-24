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

#define BOOST_TEST_MODULE por_gadget_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/core/gadgets/por.hpp>

BOOST_AUTO_TEST_SUITE(por_gadget_test_suite)

type TestTree<H, A> = MerkleTreeWrapper<H, VecStore << H as Hasher>::Domain >, A, typenum::U0, typenum::U0 > ;

type TestTree2<H, A, B> = MerkleTreeWrapper<H, VecStore << H as Hasher>::Domain >, A, B, typenum::U0 > ;

type TestTree3<H, A, B, C> = MerkleTreeWrapper<H, VecStore << H as Hasher>::Domain >, A, B, C > ;

#[test]
#[ignore] // Slow test – run only when compiled for release.
fn por_test_compound_poseidon_base_8() {
    por_compound::<TestTree<PoseidonHasher, typenum::U8>>();
}

fn por_compound < Tree : 'static + MerkleTreeTrait>() { let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    let leaves = 64 * get_base_tree_count::<Tree>();

let data : Vec<u8> = (0..leaves).flat_map(| _ | fr_into_bytes(&Fr::random(rng))).collect();
let tree = create_base_merkle_tree::<Tree>(None, leaves, data.as_slice()).unwrap();

let public_inputs = por::PublicInputs {
    challenge : 2,
    commitment : Some(tree.root()),
};

let setup_params = compound_proof::SetupParams {
    vanilla_params : por::SetupParams {
        leaves,
        private : false,
    },
    partitions : None,
    priority : false,
};
let public_params = PoRCompound::<Tree>::setup(&setup_params).expect("setup failed");

let private_inputs =
    por::PrivateInputs::<Tree>::new (bytes_into_fr(data_at_node(data.as_slice(), public_inputs.challenge).unwrap())
                                         .expect("failed to create Fr from node data")
                                         .into(),
                                     &tree, );

let gparams = PoRCompound::<Tree>::groth_params(Some(rng), &public_params.vanilla_params)
                  .expect("failed to generate groth params");

let proof = PoRCompound::<Tree>::prove(&public_params, &public_inputs, &private_inputs, &gparams)
                .expect("failed while proving");

let verified = PoRCompound::<Tree>::verify(&public_params, &public_inputs, &proof, &NoRequirements)
                   .expect("failed while verifying");
assert !(verified);

let(circuit, inputs) = PoRCompound::<Tree>::circuit_for_test(&public_params, &public_inputs, &private_inputs).unwrap();

let mut cs = TestConstraintSystem::new ();

circuit.synthesize(&mut cs).expect("failed to synthesize");
assert !(cs.is_satisfied());
assert !(cs.verify(&inputs));
}

#[test]
fn test_por_circuit_pedersen_base_2() {
    test_por_circuit::<TestTree<PedersenHasher, typenum::U2>>(3, 8_247);
}

#[test]
fn test_por_circuit_blake2s_base_2() {
    test_por_circuit::<TestTree<Blake2sHasher, typenum::U2>>(3, 129_135);
}

#[test]
fn test_por_circuit_sha256_base_2() {
    test_por_circuit::<TestTree<Sha256Hasher, typenum::U2>>(3, 272_295);
}

#[test]
fn test_por_circuit_poseidon_base_2() {
    test_por_circuit::<TestTree<PoseidonHasher, typenum::U2>>(3, 1_887);
}

#[test]
fn test_por_circuit_pedersen_base_4() {
    test_por_circuit::<TestTree<PedersenHasher, typenum::U4>>(3, 12_399);
}

#[test]
fn test_por_circuit_pedersen_sub_8_2() {
    test_por_circuit::<TestTree2<PedersenHasher, typenum::U8, typenum::U2>>(3, 20_663);
}

#[test]
fn test_por_circuit_pedersen_top_8_4_2() {
    test_por_circuit::<TestTree3<PedersenHasher, typenum::U8, typenum::U4, typenum::U2>>(3, 24_795, );
}

#[test]
fn test_por_circuit_pedersen_top_8_2_4() {
    // We can handle top-heavy trees with a non-zero subtree arity.
    // These should never be produced, though.
    test_por_circuit::<TestTree3<PedersenHasher, typenum::U8, typenum::U2, typenum::U4>>(3, 24_795, );
}

#[test]
fn test_por_circuit_blake2s_base_4() {
    test_por_circuit::<TestTree<Blake2sHasher, typenum::U4>>(3, 130_296);
}

#[test]
fn test_por_circuit_sha256_base_4() {
    test_por_circuit::<TestTree<Sha256Hasher, typenum::U4>>(3, 216_258);
}

#[test]
fn test_por_circuit_poseidon_base_4() {
    test_por_circuit::<TestTree<PoseidonHasher, typenum::U4>>(3, 1_164);
}

#[test]
fn test_por_circuit_pedersen_base_8() {
    test_por_circuit::<TestTree<PedersenHasher, typenum::U8>>(3, 19_289);
}

#[test]
fn test_por_circuit_blake2s_base_8() {
    test_por_circuit::<TestTree<Blake2sHasher, typenum::U8>>(3, 174_503);
}

#[test]
fn test_por_circuit_sha256_base_8() {
    test_por_circuit::<TestTree<Sha256Hasher, typenum::U8>>(3, 250_987);
}

#[test]
fn test_por_circuit_poseidon_base_8() {
    test_por_circuit::<TestTree<PoseidonHasher, typenum::U8>>(3, 1_063);
}

#[test]
fn test_por_circuit_poseidon_sub_8_2() {
    test_por_circuit::<TestTree2<PoseidonHasher, typenum::U8, typenum::U2>>(3, 1_377);
}

#[test]
fn test_por_circuit_poseidon_top_8_4_2() {
    test_por_circuit::<TestTree3<PoseidonHasher, typenum::U8, typenum::U4, typenum::U2>>(3, 1_764, );
}

#[test]
fn test_por_circuit_poseidon_top_8_8() {
    // This is the shape we want for 32GiB sectors.
    test_por_circuit::<TestTree2<PoseidonHasher, typenum::U8, typenum::U8>>(3, 1_593);
}
#[test]
fn test_por_circuit_poseidon_top_8_8_2() {
    // This is the shape we want for 64GiB secotrs.
    test_por_circuit::<TestTree3<PoseidonHasher, typenum::U8, typenum::U8, typenum::U2>>(3, 1_907, );
}

#[test]
fn test_por_circuit_poseidon_top_8_2_4() {
    // We can handle top-heavy trees with a non-zero subtree arity.
    // These should never be produced, though.
    test_por_circuit::<TestTree3<PoseidonHasher, typenum::U8, typenum::U2, typenum::U4>>(3, 1_764, );
}

fn test_por_circuit<Tree: 'static + MerkleTreeTrait>(
num_inputs: usize,
num_constraints: usize,
) {
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    // Ensure arity will evenly fill tree.
    let leaves = 64 * get_base_tree_count::<Tree>();

    // -- Basic Setup
    let(data, tree) = generate_tree::<Tree, _>(rng, leaves, None);

for
    i in 0..leaves {
        // println!("challenge: {}, ({})", i, leaves);

        // -- PoR
        let pub_params = por::PublicParams {
            leaves,
            private : false,
        };
        let pub_inputs = por::PublicInputs:: << Tree::Hasher as Hasher > ::Domain > {
            challenge : i,
            commitment : Some(tree.root()),
        };
        let leaf = data_at_node(data.as_slice(), pub_inputs.challenge).unwrap();
        let leaf_element = <Tree::Hasher as Hasher>::Domain::try_from_bytes(leaf).unwrap();
        let priv_inputs = por::PrivateInputs::<ResTree<Tree>>::new (leaf_element, &tree);
        let p = tree.gen_proof(i).unwrap();
        assert !(p.verify());

        // create a non circuit proof
        let proof = por::PoR::<ResTree<Tree>>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

        // make sure it verifies
        let is_valid =
            por::PoR::<ResTree<Tree>>::verify(&pub_params, &pub_inputs, &proof).expect("verification failed");
        assert !(is_valid, "failed to verify por proof");

        // -- Circuit

        let mut cs = TestConstraintSystem::<Bls12>::new ();
        let por = PoRCircuit::<ResTree<Tree>> {
            value : Root::Val(Some(proof.data.into())),
            auth_path : proof.proof.as_options().into(),
            root : Root::Val(Some(pub_inputs.commitment.unwrap().into())),
            private : false,
            _tree : PhantomData,
        };

        por.synthesize(&mut cs).expect("circuit synthesis failed");
        assert !(cs.is_satisfied(), "constraints not satisfied");

        assert_eq !(cs.num_inputs(), num_inputs, "wrong number of inputs");
        assert_eq !(cs.num_constraints(), num_constraints, "wrong number of constraints");

        let generated_inputs =
            PoRCompound::<ResTree<Tree>>::generate_public_inputs(&pub_inputs, &pub_params, None, ).unwrap();

        let expected_inputs = cs.get_inputs();

        for ((input, label), generated_input)
            in expected_inputs.iter().skip(1).zip(generated_inputs.iter()) {
                assert_eq !(input, generated_input, "{}", label);
            }

        assert_eq !(generated_inputs.len(), expected_inputs.len() - 1, "inputs are not the same length");

        assert !(cs.verify(&generated_inputs), "failed to verify inputs");
    }
}

#[ignore] // Slow test – run only when compiled for release.
#[test]
fn test_private_por_compound_pedersen_base_2() {
    private_por_test_compound::<TestTree<PedersenHasher, typenum::U2>>();
}

#[ignore] // Slow test – run only when compiled for release.
#[test]
fn test_private_por_compound_pedersen_base_4() {
    private_por_test_compound::<TestTree<PedersenHasher, typenum::U4>>();
}

#[ignore] // Slow test – run only when compiled for release.
#[test]
fn test_private_por_compound_poseidon_base_2() {
    private_por_test_compound::<TestTree<PoseidonHasher, typenum::U2>>();
}

#[ignore] // Slow test – run only when compiled for release.
#[test]
fn test_private_por_compound_poseidon_base_4() {
    private_por_test_compound::<TestTree<PoseidonHasher, typenum::U4>>();
}

#[ignore] // Slow test – run only when compiled for release.
#[test]
fn test_private_por_compound_poseidon_sub_8_2() {
    private_por_test_compound::<TestTree2<PoseidonHasher, typenum::U8, typenum::U2>>();
}

#[ignore] // Slow test – run only when compiled for release.
#[test]
fn test_private_por_compound_poseidon_top_8_4_2() {
    private_por_test_compound::<TestTree3<PoseidonHasher, typenum::U8, typenum::U4, typenum::U2>>();
}

#[ignore] // Slow test – run only when compiled for release.
#[test]
fn test_private_por_compound_poseidon_top_8_8() {
    private_por_test_compound::<TestTree2<PoseidonHasher, typenum::U8, typenum::U8>>();
}

#[ignore] // Slow test – run only when compiled for release.
#[test]
fn test_private_por_compound_poseidon_top_8_8_2() {
    private_por_test_compound::<TestTree3<PoseidonHasher, typenum::U8, typenum::U8, typenum::U2>>();
}

#[ignore] // Slow test – run only when compiled for release.
#[test]
fn test_private_por_compound_poseidon_top_8_2_4() {
    private_por_test_compound::<TestTree3<PoseidonHasher, typenum::U8, typenum::U2, typenum::U4>>();
}

fn private_por_test_compound < Tree
    : 'static + MerkleTreeTrait>() { let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

// Ensure arity will evenly fill tree.
let leaves = 64 * get_base_tree_count::<Tree>();

// -- Basic Setup
let(data, tree) = generate_tree::<Tree, _>(rng, leaves, None);

for
    i in 0..3 {
        let public_inputs = por::PublicInputs {
            challenge : i,
            commitment : None,
        };

        let setup_params = compound_proof::SetupParams {
            vanilla_params : por::SetupParams {
                leaves,
                private : true,
            },
            partitions : None,
            priority : false,
        };
        let public_params = PoRCompound::<ResTree<Tree>>::setup(&setup_params).expect("setup failed");

        let private_inputs = por::PrivateInputs::<ResTree<Tree>>::new (
            bytes_into_fr(data_at_node(data.as_slice(), public_inputs.challenge).unwrap())
                .expect("failed to create Fr from node data")
                .into(),
            &tree, );

        {
            let(circuit, inputs) =
                PoRCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs).unwrap();

            let mut cs = TestConstraintSystem::new ();

            circuit.synthesize(&mut cs).expect("failed to synthesize");

            if
                !cs.is_satisfied() {
                    panic !("failed to satisfy: {:?}", cs.which_is_unsatisfied().unwrap());
                }
            assert !(cs.verify(&inputs), "verification failed with TestContraintSystem and generated inputs");
        }
        // NOTE: This diagnostic code currently fails, even though the proof generated from the blank circuit verifies.
        // Use this to debug differences between blank and regular circuit generation.
        {
            let(circuit1, _inputs) =
                PoRCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs).unwrap();
            let blank_circuit = PoRCompound::<ResTree<Tree>>::blank_circuit(&public_params.vanilla_params);

            let mut cs_blank = MetricCS::new ();
            blank_circuit.synthesize(&mut cs_blank).expect("failed to synthesize");

            let a = cs_blank.pretty_print_list();

            let mut cs1 = TestConstraintSystem::new ();
            circuit1.synthesize(&mut cs1).expect("failed to synthesize");
            let b = cs1.pretty_print_list();

            for (i, (a, b))
                in a.chunks(100).zip(b.chunks(100)).enumerate() {
                    assert_eq !(a, b, "failed at chunk {}", i);
                }
        }

        let blank_groth_params = PoRCompound::<ResTree<Tree>>::groth_params(Some(rng), &public_params.vanilla_params, )
                                     .expect("failed to generate groth params");

        let proof = PoRCompound::prove(&public_params, &public_inputs, &private_inputs, &blank_groth_params, )
                        .expect("failed while proving");

        let verified = PoRCompound::verify(&public_params, &public_inputs, &proof, &NoRequirements)
                           .expect("failed while verifying");

        assert !(verified);
    }
}

#[test]
fn test_private_por_input_circuit_pedersen_binary() {
    test_private_por_input_circuit::<TestTree<PedersenHasher, typenum::U2>>(8_246);
}

#[test]
fn test_private_por_input_circuit_poseidon_binary() {
    test_private_por_input_circuit::<TestTree<PoseidonHasher, typenum::U2>>(1_886);
}

#[test]
fn test_private_por_input_circuit_pedersen_quad() {
    test_private_por_input_circuit::<TestTree<PedersenHasher, typenum::U4>>(12_398);
}

#[test]
fn test_private_por_input_circuit_poseidon_quad() {
    test_private_por_input_circuit::<TestTree<PoseidonHasher, typenum::U4>>(1_163);
}

#[test]
fn test_private_por_input_circuit_poseidon_oct() {
    test_private_por_input_circuit::<TestTree<PoseidonHasher, typenum::U8>>(1_062);
}

fn test_private_por_input_circuit<Tree : MerkleTreeTrait>(num_constraints : usize) {
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    let leaves = 64 * get_base_tree_count::<Tree>();
for
    i in 0..leaves {
        // -- Basic Setup

        let data : Vec<u8> = (0..leaves).flat_map(| _ | fr_into_bytes(&Fr::random(rng))).collect();

        let tree = create_base_merkle_tree::<Tree>(None, leaves, data.as_slice()).unwrap();

        // -- PoR

        let pub_params = por::PublicParams {
            leaves,
            private : true,
        };
        let pub_inputs = por::PublicInputs {
            challenge : i,
            commitment : None,
        };

        let priv_inputs = por::PrivateInputs::<Tree>::new (
            bytes_into_fr(data_at_node(data.as_slice(), pub_inputs.challenge).unwrap()).unwrap().into(), &tree, );

        // create a non circuit proof
        let proof = por::PoR::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

        // make sure it verifies
        let is_valid = por::PoR::<Tree>::verify(&pub_params, &pub_inputs, &proof).expect("verification failed");
        assert !(is_valid, "failed to verify por proof");

        // -- Circuit

        let mut cs = TestConstraintSystem::<Bls12>::new ();

        let por = PoRCircuit::<Tree> {
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

        let auth_path_bits = challenge_into_auth_path_bits(pub_inputs.challenge, pub_params.leaves);
        let packed_auth_path = multipack::compute_multipacking::<Bls12>(&auth_path_bits);

        let mut expected_inputs = Vec::new ();
        expected_inputs.extend(packed_auth_path);

        assert_eq !(cs.get_input(0, "ONE"), Fr::one(), "wrong input 0");

        assert_eq !(cs.get_input(1, "path/input 0"), expected_inputs[0], "wrong packed_auth_path");

        assert !(cs.is_satisfied(), "constraints are not all satisfied");
        assert !(cs.verify(&expected_inputs), "failed to verify inputs");
    }
}
}

BOOST_AUTO_TEST_SUITE_END()
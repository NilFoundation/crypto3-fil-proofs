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

#define BOOST_TEST_MODULE circuit_proof_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/porep/stacked/circuit/proof.hpp>

using namespace nil::filecoin;

BOOST_AUTO_TEST_SUITE(stacked_circuit_test_suite)

template<typename MerkleTreeType>
void stacked_input_circuit(std::size_t expected_inputs, std::size_t expected_constraints) {
    let nodes = 8 * get_base_tree_count::<Tree>();
    let degree = BASE_DEGREE;
    let expansion_degree = EXP_DEGREE;
    let num_layers = 2;
    let layer_challenges = LayerChallenges::new (num_layers, 1);

    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    let replica_id : Fr = Fr::random(rng);
    let data : Vec<u8> = (0..nodes).flat_map(| _ | fr_into_bytes(&Fr::random(rng))).collect();

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    let cache_dir = tempfile::tempdir();
    let config = StoreConfig::new (cache_dir.path(), cache_key::CommDTree.to_string(),
                                   default_rows_to_discard(nodes, BINARY_ARITY), );

    // Generate a replica path.
    let replica_path = cache_dir.path().join("replica-path");
    let mut mmapped_data = setup_replica(&data, &replica_path);

    let arbitrary_porep_id = [44; 32];
    let sp = SetupParams {
        nodes,
        degree,
        expansion_degree,
        porep_id : arbitrary_porep_id,
        layer_challenges,
    };

    let pp = StackedDrg<Tree, Sha256Hasher>::setup(&sp).expect("setup failed");
    let(tau, (p_aux, t_aux)) =
        StackedDrg<Tree, Sha256Hasher>::replicate(&pp, &replica_id.into(), (mmapped_data.as_mut()).into(), None, config,
                                                  replica_path.clone(), )
            .expect("replication failed");

    let mut copied = vec ![0; data.len()];
    copied.copy_from_slice(&mmapped_data);
    assert_ne !(data, copied, "replication did not change data");

    let seed = rng.gen();
    let pub_inputs = PublicInputs:: << MerkleTreeType::Hasher as Hasher > ::Domain, <Sha256Hasher as Hasher>::Domain > {
        replica_id : replica_id.into(),
        seed,
        tau : Some(tau),
        k : None,
    };

    // Store copy of original t_aux for later resource deletion.
    let t_aux_orig = t_aux.clone();

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
    // elements based on the configs stored in TemporaryAux.
    let t_aux = TemporaryAuxCache::<Tree, Sha256Hasher>::new (&t_aux, replica_path)
                    .expect("failed to restore contents of t_aux");

    let priv_inputs = PrivateInputs::<Tree, Sha256Hasher> {p_aux, t_aux};

    let proofs = StackedDrg::<Tree, Sha256Hasher>::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, 1, )
                     .expect("failed to generate partition proofs");

    let proofs_are_valid = StackedDrg::<Tree, Sha256Hasher>::verify_all_partitions(&pp, &pub_inputs, &proofs)
                               .expect("failed while trying to verify partition proofs");

    assert !(proofs_are_valid);

    // Discard cached MTs that are no longer needed.
    TemporaryAux::<Tree, Sha256Hasher>::clear_temp(t_aux_orig).expect("t_aux delete failed");

    {
        // Verify that MetricCS returns the same metrics as TestConstraintSystem.
        let mut cs = MetricCS::<Bls12>::new ();

        StackedCompound::<Tree, Sha256Hasher>::circuit(&pub_inputs, (), &proofs[0], &pp, None)
            .expect("circuit failed")
            .synthesize(&mut cs.namespace(|| "stacked drgporep"))
            .expect("failed to synthesize circuit");

        BOOST_CHECK_EQUAL(cs.num_inputs(), expected_inputs, "wrong number of inputs");
        BOOST_CHECK_EQUAL(cs.num_constraints(), expected_constraints, "wrong number of constraints");
    }
    let mut cs = TestConstraintSystem::<Bls12>::new ();

    StackedCompound::<Tree, Sha256Hasher>::circuit(&pub_inputs, (), &proofs[0], &pp, None)
        .expect("circuit failed")
        .synthesize(&mut cs.namespace(|| "stacked drgporep"))
        .expect("failed to synthesize circuit");

    assert !(cs.is_satisfied(), "constraints not satisfied");
    BOOST_CHECK_EQUAL(cs.num_inputs(), expected_inputs, "wrong number of inputs");
    BOOST_CHECK_EQUAL(cs.num_constraints(), expected_constraints, "wrong number of constraints");

    BOOST_CHECK_EQUAL(cs.get_input(0, "ONE"), Fr::one());

    let generated_inputs =
        <StackedCompound<Tree, Sha256Hasher>
             as CompoundProof<StackedDrg<Tree, Sha256Hasher>, _, >>::generate_public_inputs(&pub_inputs, &pp, None)
            .expect("failed to generate public inputs");
    let expected_inputs = cs.get_inputs();

    for (((input, label), generated_input) : expected_inputs.iter().skip(1).zip(generated_inputs.iter())) {
        BOOST_CHECK_EQUAL(input, generated_input, "{}", label);
    }

    BOOST_CHECK_EQUAL(generated_inputs.len(), expected_inputs.len() - 1, "inputs are not the same length");

    cache_dir.close().expect("Failed to remove cache dir");
}

BOOST_AUTO_TEST_CASE(stacked_input_circuit_pedersen_base_2) {
    stacked_input_circuit::<DiskTree<PedersenHasher, U2, U0, U0>>(22, 1_258_152);
}

BOOST_AUTO_TEST_CASE(stacked_input_circuit_poseidon_base_2) {
    stacked_input_circuit::<DiskTree<PoseidonHasher, U2, U0, U0>>(22, 1_206_212);
}

BOOST_AUTO_TEST_CASE(stacked_input_circuit_poseidon_base_8) {
    stacked_input_circuit::<DiskTree<PoseidonHasher, U8, U0, U0>>(22, 1_199_620);
}

BOOST_AUTO_TEST_CASE(stacked_input_circuit_poseidon_sub_8_4) {
    stacked_input_circuit::<DiskTree<PoseidonHasher, U8, U4, U0>>(22, 1_296_576);
}

BOOST_AUTO_TEST_CASE(stacked_input_circuit_poseidon_top_8_4_2) {
    stacked_input_circuit::<DiskTree<PoseidonHasher, U8, U4, U2>>(22, 1_346_982);
}

template<typename MerkleTreeType>
void stacked_test_compound() {
    let nodes = 8 * get_base_tree_count::<Tree>();

    let degree = BASE_DEGREE;
    let expansion_degree = EXP_DEGREE;
    let num_layers = 2;
    let layer_challenges = LayerChallenges::new (num_layers, 1);
    let partition_count = 1;

    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    let replica_id : Fr = Fr::random(rng);
    let data : Vec<u8> = (0..nodes).flat_map(| _ | fr_into_bytes(&Fr::random(rng))).collect();

    let arbitrary_porep_id = [55; 32];
    let setup_params = compound_proof::SetupParams {
        vanilla_params : SetupParams {
            nodes,
            degree,
            expansion_degree,
            porep_id : arbitrary_porep_id,
            layer_challenges,
        },
        partitions : Some(partition_count),
        priority : false,
    };

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    let cache_dir = tempfile::tempdir();
    let config = StoreConfig::new (cache_dir.path(), cache_key::CommDTree.to_string(),
                                   default_rows_to_discard(nodes, BINARY_ARITY), );

    // Generate a replica path.
    let replica_path = cache_dir.path().join("replica-path");
    let mut mmapped_data = setup_replica(&data, &replica_path);

    let public_params = StackedCompound::setup(&setup_params).expect("setup failed");
    let(tau, (p_aux, t_aux)) =
        StackedDrg::<Tree, _>::replicate(&public_params.vanilla_params, &replica_id.into(),
                                         (mmapped_data.as_mut()).into(), None, config, replica_path.clone(), )
            .expect("replication failed");

    let mut copied = vec ![0; data.len()];
    copied.copy_from_slice(&mmapped_data);
    assert_ne !(data, copied, "replication did not change data");

    let seed = rng.gen();
    let public_inputs = PublicInputs:: << MerkleTreeType::Hasher as Hasher > ::Domain, <Sha256Hasher as Hasher>::Domain > {
        replica_id : replica_id.into(),
        seed,
        tau : Some(tau),
        k : None,
    };

    // Store a copy of the t_aux for later resource deletion.
    let t_aux_orig = t_aux.clone();

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
    // elements based on the configs stored in TemporaryAux.
    let t_aux = TemporaryAuxCache::<Tree, _>::new (&t_aux, replica_path).expect("failed to restore contents of t_aux");

    let private_inputs = PrivateInputs::<Tree, Sha256Hasher> {p_aux, t_aux};

    {
        let(circuit, inputs) =
            StackedCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs);

        let mut cs = TestConstraintSystem::new ();

        circuit.synthesize(&mut cs).expect("failed to synthesize");

        if
            !cs.is_satisfied() {
                panic !("failed to satisfy: {:?}", cs.which_is_unsatisfied());
            }
        assert !(cs.verify(&inputs), "verification failed with TestContraintSystem and generated inputs");
    }

    // Use this to debug differences between blank and regular circuit generation.
    {
        let(circuit1, _inputs) =
            StackedCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs);
        let blank_circuit =
            <StackedCompound<Tree, Sha256Hasher> as CompoundProof<StackedDrg<Tree, Sha256Hasher>, _, >>::blank_circuit(
                &public_params.vanilla_params);

        let mut cs_blank = MetricCS::new ();
        blank_circuit.synthesize(&mut cs_blank).expect("failed to synthesize");

        let a = cs_blank.pretty_print_list();

        let mut cs1 = TestConstraintSystem::new ();
        circuit1.synthesize(&mut cs1).expect("failed to synthesize");
        let b = cs1.pretty_print_list();

        for (i, (a, b))
            in a.chunks(100).zip(b.chunks(100)).enumerate() {
                BOOST_CHECK_EQUAL(a, b, "failed at chunk {}", i);
            }
    }

    let blank_groth_params =
        <StackedCompound<Tree, Sha256Hasher> as CompoundProof<StackedDrg<Tree, Sha256Hasher>, _, >>::groth_params(
            Some(rng), &public_params.vanilla_params)
            .expect("failed to generate groth params");

    // Discard cached MTs that are no longer needed.
    TemporaryAux::<Tree, Sha256Hasher>::clear_temp(t_aux_orig).expect("t_aux delete failed");

    let proof = StackedCompound::prove(&public_params, &public_inputs, &private_inputs, &blank_groth_params, )
                    .expect("failed while proving");

    let verified = StackedCompound::verify(&public_params, &public_inputs, &proof, &ChallengeRequirements {
                       minimum_challenges : 1,
                   }, )
                       .expect("failed while verifying");

    assert !(verified);

    cache_dir.close().expect("Failed to remove cache dir");
}

BOOST_AUTO_TEST_CASE(test_stacked_compound_pedersen) {
    stacked_test_compound::<DiskTree<PedersenHasher, U2, U0, U0>>();
}

BOOST_AUTO_TEST_CASE(test_stacked_compound_poseidon_base_8) {
    stacked_test_compound::<DiskTree<PoseidonHasher, U8, U0, U0>>();
}

BOOST_AUTO_TEST_CASE(test_stacked_compound_poseidon_sub_8_4) {
    stacked_test_compound::<DiskTree<PoseidonHasher, U8, U4, U0>>();
}

BOOST_AUTO_TEST_CASE(test_stacked_compound_poseidon_top_8_4_2) {
    stacked_test_compound::<DiskTree<PoseidonHasher, U8, U4, U2>>();
}

BOOST_AUTO_TEST_SUITE_END()
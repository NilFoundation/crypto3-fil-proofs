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

#define BOOST_TEST_MODULE drg_circuit_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/porep/drg/circuit.hpp>

using namespace nil::filecoin;

BOOST_AUTO_TEST_SUITE(drg_circuit_test_suite)

BOOST_AUTO_TEST_CASE(drgporep_input_circuit_with_bls12_381) {
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    let nodes = 16;
    let degree = BASE_DEGREE;
    let challenge = 2;

    let replica_id : Fr = Fr::random(rng);

    let data : Vec<u8> = (0..nodes).flat_map(| _ | fr_into_bytes(&Fr::random(rng))).collect();

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    let cache_dir = tempfile::tempdir().unwrap();
    let config = StoreConfig::new (cache_dir.path(), CacheKey::CommDTree.to_string(),
                                   default_rows_to_discard(nodes, BINARY_ARITY), );

    // Generate a replica path.
    let replica_path = cache_dir.path().join("replica-path");
    let mut mmapped_data = setup_replica(&data, &replica_path);

    let data_node
        : Option<Fr> =
              Some(bytes_into_fr(data_at_node(&mmapped_data, challenge).expect("failed to read original data"), )
                       .unwrap(), );

    let sp = drg::SetupParams {
        drg : drg::DrgParams {
            nodes,
            degree,
            expansion_degree : 0,
            porep_id : [32; 32],
        },
        private : false,
        challenges_count : 1,
    };

    let pp = drg::DrgPoRep::<PedersenHasher, BucketGraph<_>>::setup(&sp).expect("failed to create drgporep setup");
    let(tau, aux) = drg::DrgPoRep::<PedersenHasher, _>::replicate(
                        &pp, &replica_id.into(), (mmapped_data.as_mut()).into(), None, config, replica_path.clone(), )
                        .expect("failed to replicate");

    let pub_inputs = drg::PublicInputs {
        replica_id : Some(replica_id.into()),
        challenges : vec ![challenge],
        tau : Some(tau.into()),
    };

    let priv_inputs = drg::PrivateInputs::<PedersenHasher> {
        tree_d : &aux.tree_d,
        tree_r : &aux.tree_r,
        tree_r_config_rows_to_discard : default_rows_to_discard(nodes, BINARY_ARITY),
    };

    let proof_nc = drg::DrgPoRep::<PedersenHasher, _>::prove(&pp, &pub_inputs, &priv_inputs).expect("failed to prove");

    assert !(drg::DrgPoRep::<PedersenHasher, _>::verify(&pp, &pub_inputs, &proof_nc).expect("failed to verify"),
             "failed to verify (non circuit)");

    let replica_node : Option<Fr> = Some(proof_nc.replica_nodes[0].data.into());

    let replica_node_path = proof_nc.replica_nodes[0].proof.as_options();
    let replica_root = Root::Val(Some(proof_nc.replica_root.into()));
    let replica_parents = proof_nc.replica_parents.iter()
                              .map(| v | {v.iter().map(| (_, parent) | Some(parent.data.into())).collect()})
                              .collect();
    let replica_parents_paths : Vec<_> =
                                    proof_nc.replica_parents.iter()
                                        .map(| v | {v.iter().map(| (_, parent) | parent.proof.as_options()).collect()})
                                        .collect();

    let data_node_path = proof_nc.nodes[0].proof.as_options();
    let data_root = Root::Val(Some(proof_nc.data_root.into()));
    let replica_id = Some(replica_id);

    assert !(proof_nc.nodes[0].proof.validate(challenge), "failed to verify data commitment");
    assert !(proof_nc.nodes[0].proof.validate_data(data_node.unwrap().into()),
             "failed to verify data commitment with data");

    let mut cs = TestConstraintSystem::<Bls12>::new ();
    DrgPoRepCircuit::<PedersenHasher>::synthesize(
        cs.namespace(|| "drgporep"), vec ![replica_node], vec ![replica_node_path], replica_root, replica_parents,
        replica_parents_paths, vec ![data_node], vec ![data_node_path], data_root, replica_id, false, )
        .expect("failed to synthesize circuit");

    if
        !cs.is_satisfied() {
            println !("failed to satisfy: {:?}", cs.which_is_unsatisfied().unwrap());
        }

    assert !(cs.is_satisfied(), "constraints not satisfied");
    BOOST_CHECK_EQUAL(cs.num_inputs(), 18, "wrong number of inputs");
    BOOST_CHECK_EQUAL(cs.num_constraints(), 149_580, "wrong number of constraints");

    BOOST_CHECK_EQUAL(cs.get_input(0, "ONE"), Fr::one());

    BOOST_CHECK_EQUAL(cs.get_input(1, "drgporep/replica_id/input variable"), replica_id.unwrap());

    let generated_inputs = <drg_porep_compound<_, _> as compound_proof::CompoundProof<_, _>>::generate_public_inputs(
                               &pub_inputs, &pp, None, )
                               .unwrap();
    let expected_inputs = cs.get_inputs();

    for ((input, label), generated_input)
        in expected_inputs.iter().skip(1).zip(generated_inputs.iter()) {
            BOOST_CHECK_EQUAL(input, generated_input, "{}", label);
        }

    BOOST_CHECK_EQUAL(generated_inputs.len(), expected_inputs.len() - 1, "inputs are not the same length");

    cache_dir.close().expect("Failed to remove cache dir");
}

BOOST_AUTO_TEST_CASE(drgporep_input_circuit_num_constraints) {
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    // 1 GB
    let n = (1 << 30) / 32;
    let m = BASE_DEGREE;
    let tree_depth = graph_height::<typenum::U2>(n);

    let mut cs = TestConstraintSystem::<Bls12>::new ();
    DrgPoRepCircuit::<PedersenHasher>::synthesize(
        cs.namespace(|| "drgporep"), vec ![Some(Fr::random(rng)); 1],
        vec ![vec ![(vec ![Some(Fr::random(rng))], Some(0)); tree_depth]; 1], Root::Val(Some(Fr::random(rng))),
        vec ![vec ![Some(Fr::random(rng)); m]; 1],
        vec ![vec ![vec ![(vec ![Some(Fr::random(rng))], Some(0)); tree_depth]; m]; 1], vec ![Some(Fr::random(rng)); 1],
        vec ![vec ![(vec ![Some(Fr::random(rng))], Some(0)); tree_depth]; 1], Root::Val(Some(Fr::random(rng))),
        Some(Fr::random(rng)), false, )
        .expect("failed to synthesize circuit");

    BOOST_CHECK_EQUAL(cs.num_inputs(), 18, "wrong number of inputs");
    BOOST_CHECK_EQUAL(cs.num_constraints(), 391_404, "wrong number of constraints");
}

BOOST_AUTO_TEST_SUITE_END()
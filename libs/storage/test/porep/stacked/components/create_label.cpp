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

#define BOOST_TEST_MODULE circuit_create_label_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/porep/stacked/circuit/create_label.hpp>

using namespace nil::filecoin;

BOOST_AUTO_TEST_SUITE(stacked_circuit_test_suite)

BOOST_AUTO_TEST_CASE(drgporep_input_circuit_with_bls12_381) {
    const auto rng = XorShiftRng::from_seed(crate::TEST_SEED);

    const auto nodes = 16;
    const auto degree = BASE_DEGREE;
    const auto challenge = 2;

    const auto replica_id : Fr = Fr::random(rng);

    const std::vector<std::uint8_t> data  = (0..nodes).flat_map(| _ | fr_into_bytes(&Fr::random(rng))).collect();

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    const auto cache_dir = tempfile::tempdir();
    const auto config = StoreConfig(cache_dir.path(), cache_key::CommDTree.to_string(),
                                   default_rows_to_discard(nodes, BINARY_ARITY));

    // Generate a replica path.
    const auto replica_path = cache_dir.path().join("replica-path");
    auto mmapped_data = setup_replica(&data, &replica_path);

    const Option<Fr> data_node = Some(bytes_into_fr(data_at_node(&mmapped_data, challenge)));

    const auto sp = drg::SetupParams {
        drg : drg::DrgParams {
            nodes,
            degree,
            expansion_degree : 0,
            porep_id : [32; 32],
        },
        private : false,
        challenges_count : 1,
    };

    const auto pp = drg::DrgPoRep::<PedersenHasher, BucketGraph<_>>::setup(&sp);
    const auto(tau, aux) = drg::DrgPoRep::<PedersenHasher, _>::replicate(
                        &pp, &replica_id.into(), (mmapped_data).into(), None, config, replica_path.clone());

    const drg::PublicInputs pub_inputs = {
        .replica_id = Some(replica_id.into()),
        .challenges = vec ![challenge],
        .tau = Some(tau.into())
    };

    const drg::PrivateInputs::<PedersenHasher> priv_inputs = {
        .tree_d = &aux.tree_d,
        .tree_r = &aux.tree_r,
        .tree_r_config_rows_to_discard = default_rows_to_discard(nodes, BINARY_ARITY),
    };

    const auto proof_nc = drg::DrgPoRep::<PedersenHasher, _>::prove(&pp, &pub_inputs, &priv_inputs);

    BOOST_ASSERT_MSG(drg::DrgPoRep::<PedersenHasher, _>::verify(&pp, &pub_inputs, &proof_nc),
             "failed to verify (non circuit)");

    const auto replica_node : Option<Fr> = Some(proof_nc.replica_nodes[0].data.into());

    const auto replica_node_path = proof_nc.replica_nodes[0].proof.as_options();
    const auto replica_root = Root::Val(Some(proof_nc.replica_root.into()));
    const auto replica_parents = proof_nc.replica_parents.iter()
                              .map(| v | {v.iter().map(| (_, parent) | Some(parent.data.into())).collect()})
                              .collect();
    std::vector<std::uint8_t> replica_parents_paths =
                                    proof_nc.replica_parents.iter()
                                        .map(| v | {v.iter().map(| (_, parent) | parent.proof.as_options()).collect()})
                                        .collect();

    const auto data_node_path = proof_nc.nodes[0].proof.as_options();
    const auto data_root = Root::Val(Some(proof_nc.data_root.into()));
    const auto replica_id = Some(replica_id);

    BOOST_ASSERT_MSG(proof_nc.nodes[0].proof.validate(challenge), "failed to verify data commitment");
    BOOST_ASSERT_MSG(proof_nc.nodes[0].proof.validate_data(data_node.into()),
             "failed to verify data commitment with data");

    auto cs = TestConstraintSystem<algebra::curves::bls12<381>>();
    DrgPoRepCircuit::<PedersenHasher>::synthesize(
        cs.namespace(|| "drgporep"), vec ![replica_node], vec ![replica_node_path], replica_root, replica_parents,
        replica_parents_paths, vec ![data_node], vec ![data_node_path], data_root, replica_id, false);

    if (!cs.is_satisfied()) {
        std::cout << std::format("failed to satisfy: {:?}", cs.which_is_unsatisfied()) << std::endl;
    }

    BOOST_ASSERT_MSG(cs.is_satisfied(), "constraints not satisfied");
    BOOST_CHECK_EQUAL(cs.num_inputs(), 18, "wrong number of inputs");
    BOOST_CHECK_EQUAL(cs.num_constraints(), 149_580, "wrong number of constraints");

    BOOST_CHECK_EQUAL(cs.get_input(0, "ONE"), Fr::one());

    BOOST_CHECK_EQUAL(cs.get_input(1, "drgporep/replica_id/input variable"), replica_id);

    const auto generated_inputs = <drg_porep_compound<_, _> as compound_proof::CompoundProof<_, _>>::generate_public_inputs(
                               &pub_inputs, &pp, None, )
                               ;
    const auto expected_inputs = cs.get_inputs();

    for ((input, label), generated_input)
        in expected_inputs.iter().skip(1).zip(generated_inputs.iter()) {
            BOOST_CHECK_EQUAL(input, generated_input, "{}", label);
        }

    BOOST_CHECK_EQUAL(generated_inputs.len(), expected_inputs.len() - 1, "inputs are not the same length");

    cache_dir.close();
}

BOOST_AUTO_TEST_CASE(drgporep_input_circuit_num_constraints) {
    const auto rng = XorShiftRng::from_seed(crate::TEST_SEED);

    // 1 GB
    const auto n = (1 << 30) / 32;
    const auto m = BASE_DEGREE;
    const auto tree_depth = graph_height<2>(n);

    auto cs = TestConstraintSystem::<algebra::curves::bls12<381>>();
    DrgPoRepCircuit<PedersenHasher>::synthesize(
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
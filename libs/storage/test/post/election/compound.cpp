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

#define BOOST_TEST_MODULE post_election_compound_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/core/sector.hpp>

#include <nil/filecoin/storage/proofs/post/election/compound.hpp>

using namespace nil::filecoin;

BOOST_AUTO_TEST_SUITE(post_election_compound_test_suite)

template<typename MerkleTreeType>
void election_post_test_compound() {
    const auto rng = XorShiftRng::from_seed(crate::TEST_SEED);

    std::size_t leaves = 64 * get_base_tree_count<MerkleTreeType>();
    std::uint64_t sector_size = (leaves * NODE_SIZE);
    const auto randomness = typename MerkleTreeType::hash_type::digest_type::random(rng);
    const auto prover_id = typename MerkleTreeType::hash_type::digest_type::random(rng);

    compound_proof::SetupParams setup_params =
        {election::SetupParams {sector_size, 20, 1}, partitions : None, priority : true};

    std::vector<sector_id_type> sectors;
    auto trees = BTreeMap();

    // Construct and store an MT using a named store.
    const auto temp_dir = tempfile::tempdir();
    const auto temp_path = temp_dir.path();

    for (std::size_t i = 0; i < 5; i++) {
        sectors.push_back(i.into());
        const auto(_data, tree) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
        trees.insert(i.into(), tree);
    }

    const auto pub_params = ElectionPoStCompound<MerkleTreeType>::setup(&setup_params).expect("setup failed");

    const auto candidates = election::generate_candidates<MerkleTreeType>(&pub_params.vanilla_params, &sectors, &trees,
                                                                   prover_id, randomness)
                         ;

    const auto candidate = &candidates[0];
    const auto tree = trees.remove(&candidate.sector_id);
    const auto comm_r_last = tree.root();
    const auto comm_c = typename MerkleTreeType::hash_type::digest_type::random(rng);
    const auto comm_r = <typename MerkleTreeType::hash_type>::Function::hash2(&comm_c, &comm_r_last);

    election::PublicInputs pub_inputs = {randomness, candidate.sector_id,      prover_id,
                                         comm_r,     candidate.partial_ticket, 0};

    election::PrivateInputs::<MerkleTreeType>priv_inputs = {tree, comm_c, comm_r_last};

    const auto(circuit, inputs) = ElectionPoStCompound::circuit_for_test(&pub_params, &pub_inputs, &priv_inputs);

    auto cs = TestConstraintSystem();

    circuit.synthesize(cs).expect("failed to synthesize");

    if (!cs.is_satisfied()) {
        panic !("failed to satisfy: {:?}", cs.which_is_unsatisfied());
    }
    BOOST_CHECK(cs.verify(&inputs), "verification failed with TestContraintSystem and generated inputs");

    // Use this to debug differences between blank and regular circuit generation.
    const auto(circuit1, _inputs) =
        ElectionPoStCompound::circuit_for_test(&pub_params, &pub_inputs, &priv_inputs);
    const auto blank_circuit = ElectionPoStCompound::<Tree>::blank_circuit(&pub_params.vanilla_params);

    auto cs_blank = MetricCS();
    blank_circuit.synthesize(cs_blank).expect("failed to synthesize");

    const auto a = cs_blank.pretty_print_list();

    auto cs1 = TestConstraintSystem();
    circuit1.synthesize(cs1).expect("failed to synthesize");
    const auto b = cs1.pretty_print_list();

    for ((i, (a, b)) : a.chunks(100).zip(b.chunks(100)).enumerate()) {
        BOOST_ASSERT_MSG(a == b, std::format("failed at chunk %d", i));
    }

    const auto blank_groth_params = ElectionPoStCompound<MerkleTreeType>::groth_params(Some(rng), &pub_params.vanilla_params)
                                 .expect("failed to generate groth params");

    const auto proof = ElectionPoStCompound::prove(&pub_params, &pub_inputs, &priv_inputs, &blank_groth_params, )
                    .expect("failed while proving");

    const auto verified = ElectionPoStCompound::verify(&pub_params, &pub_inputs, &proof, &NoRequirements)
                       .expect("failed while verifying");

    BOOST_CHECK(verified);
}

BOOST_AUTO_TEST_CASE(election_post_test_compound_pedersen) {
    election_post_test_compound::<LCTree<PedersenHasher, U8, U0, U0>>();
}

BOOST_AUTO_TEST_CASE(election_post_test_compound_poseidon) {
    election_post_test_compound::<LCTree<PoseidonHasher, U8, U0, U0>>();
}

BOOST_AUTO_TEST_SUITE_END()
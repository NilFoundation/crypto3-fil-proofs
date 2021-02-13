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

#define BOOST_TEST_MODULE post_fallback_circuit_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/post/fallback/circuit.hpp>

using namespace nil::filecoin;

BOOST_AUTO_TEST_SUITE(post_fallback_circuit_test_suite)

template<typename MerkleTreeType>
void test_fallback_post_circuit(std::size_t expected_constraints) {
    const auto rng = XorShiftRng::from_seed(crate::TEST_SEED);

    std::size_t leaves = 64 * get_base_tree_count<Tree>();
    std::size_t sector_size = leaves * NODE_SIZE;

    const auto randomness = <typename MerkleTreeType::hash_type>::Domain::random(rng);
    const auto prover_id = <typename MerkleTreeType::hash_type>::Domain::random(rng);

    const auto pub_params = fallback::PublicParams {
        sector_size : sector_size as u64,
        challenge_count : 20,
        challenged_nodes : 1,
    };

    std::vector<SectorId> sectors;
    auto trees = BTreeMap();

    // Construct and store an MT using a named store.
    const auto temp_dir = tempfile::tempdir();
    const auto temp_path = temp_dir.path();

    for (std::size_t i = 0; i < 5; i++) {
        sectors.push(i.into());
        const auto(_data, tree) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
        trees.insert(i.into(), tree);
    }

    const auto candidates =
        fallback::generate_candidates::<Tree>(&pub_params, &sectors, &trees, prover_id, randomness, );

    const auto candidate = &candidates[0];
    const auto tree = trees.remove(&candidate.sector_id);
    const auto comm_r_last = tree.root();
    const auto comm_c = <typename MerkleTreeType::hash_type>::Domain::random(rng);
    const auto comm_r = <typename MerkleTreeType::hash_type>::Function::hash2(&comm_c, &comm_r_last);

    const auto pub_inputs = fallback::PublicInputs {
        randomness,
        sector_id : candidate.sector_id,
        prover_id,
        comm_r,
        partial_ticket : candidate.partial_ticket,
        sector_challenge_index : 0,
    };

    const auto priv_inputs = fallback::PrivateInputs::<Tree> {
        tree,
        comm_c,
        comm_r_last,
    };

    const auto proof = ElectionPoSt::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

    const auto is_valid = ElectionPoSt::<Tree>::verify(&pub_params, &pub_inputs, &proof).expect("verification failed");
    BOOST_CHECK(is_valid);

    // actual circuit test

    const auto paths = proof.paths()
                    .iter()
                    .map(| p |
                         {p.iter()
                              .map(| v | {(v .0.iter().copied().map(Into::into).map(Some).collect(), Some(v .1), )})
                              .collect::<Vec<_>>()})
                    .collect();
    std::vector<_> leafs = proof.leafs().iter().map(| l | Some((*l).into())).collect();

    auto cs = TestConstraintSystem<algebra::curves::bls12<381>>();

    const auto instance = ElectionPoStCircuit::<Tree> {
        leafs,
        paths,
        comm_r : Some(comm_r.into()),
        comm_c : Some(comm_c.into()),
        comm_r_last : Some(comm_r_last.into()),
        partial_ticket : Some(candidate.partial_ticket),
        randomness : Some(randomness.into()),
        prover_id : Some(prover_id.into()),
        sector_id : Some(candidate.sector_id.into()),
        _t : PhantomData,
    };

    instance.synthesize(cs).expect("failed to synthesize circuit");

    BOOST_CHECK(cs.is_satisfied(), "constraints not satisfied");

    BOOST_ASSERT_MSG(cs.num_inputs() == 23, "wrong number of inputs");
    BOOST_ASSERT_MSG(cs.num_constraints() == expected_constraints, "wrong number of constraints");
    BOOST_CHECK_EQUAL(cs.get_input(0, "ONE"), Fr::one());

    const auto generated_inputs =
        ElectionPoStCompound::<Tree>::generate_public_inputs(&pub_inputs, &pub_params, None);
    const auto expected_inputs = cs.get_inputs();

    for (((input, label), generated_input) : expected_inputs.iter().skip(1).zip(generated_inputs.iter())) {
        BOOST_ASSERT_MSG(input == generated_input, std::string(label));
    }

    BOOST_ASSERT_MSG(generated_inputs.len() == expected_inputs.len() - 1, "inputs are not the same length");
}

BOOST_AUTO_TEST_CASE(test_fallback_post_circuit_pedersen) {
    test_fallback_post_circuit<LCTree<PedersenHasher, U8, U0, U0>>(388520);
}

BOOST_AUTO_TEST_CASE(test_fallback_post_circuit_poseidon) {
    test_fallback_post_circuit<LCTree<PoseidonHasher, U8, U0, U0>>(22940);
}

BOOST_AUTO_TEST_SUITE_END()
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

#define BOOST_TEST_MODULE post_rational_circuit_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/post/rational/circuit.hpp>

using namespace nil::filecoin;

BOOST_AUTO_TEST_SUITE(post_rational_circuit_test_suite)

template<typename MerkleTreeType>
void test_rational_post_circuit(std::size_t expected_constraints) {
    auto rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    std::uint64_t leaves = 32 * get_base_tree_count<Tree>();
    std::uint64_t sector_size = (leaves * NODE_SIZE);
    std::size_t challenges_count = 2;

    auto pub_params = rational::PublicParams {
        sector_size,
        challenges_count,
    };

    // Construct and store an MT using a named DiskStore.
    auto temp_dir = tempfile::tempdir();
    auto temp_path = temp_dir.path();

    auto(_data1, tree1) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
    auto(_data2, tree2) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));

    auto faults = OrderedSectorSet::new ();
    auto mut sectors = OrderedSectorSet::new ();
    sectors.insert(0.into());
    sectors.insert(1.into());

    auto seed = (0..leaves).map(| _ | rng.gen()).collect::<Vec<u8>>();
    auto challenges = derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults);
    auto comm_r_lasts_raw = vec ![ tree1.root(), tree2.root() ];
    auto comm_r_lasts : Vec<_> = challenges.iter().map(| c | comm_r_lasts_raw[u64::from(c.sector) as usize]).collect();

    auto comm_cs : Vec << typename MerkleTreeType::hash_type > ::Domain >
        = challenges.iter().map(| _c | <typename MerkleTreeType::hash_type>::Domain::random(rng)).collect();

    auto comm_rs
        : Vec<_> = comm_cs.iter()
                       .zip(comm_r_lasts.iter())
                       .map(| (comm_c, comm_r_last) | {<typename MerkleTreeType::hash_type>::Function::hash2(comm_c, comm_r_last)})
                       .collect();

    auto pub_inputs = rational::PublicInputs {
        challenges : &challenges,
        faults : &faults,
        comm_rs : &comm_rs,
    };

    auto mut trees = BTreeMap::new ();
    trees.insert(0.into(), &tree1);
    trees.insert(1.into(), &tree2);

    auto priv_inputs = rational::PrivateInputs::<Tree> {
        trees : &trees,
        comm_cs : &comm_cs,
        comm_r_lasts : &comm_r_lasts,
    };

    auto proof = RationalPoSt::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

    auto is_valid = RationalPoSt::<Tree>::verify(&pub_params, &pub_inputs, &proof).expect("verification failed");
    assert !(is_valid);

    // actual circuit test

    auto paths : Vec<_> =
                    proof.paths()
                        .iter()
                        .map(| p |
                             {p.iter()
                                  .map(| v | {(v .0.iter().copied().map(Into::into).map(Some).collect(), Some(v .1), )})
                                  .collect::<Vec<_>>()})
                        .collect();
    auto leafs : Vec<_> = proof.leafs().iter().map(| l | Some((*l).into())).collect();

    auto mut cs = TestConstraintSystem<algebra::curves::bls12<381>>::new ();

    auto instance = RationalPoStCircuit::<Tree> {
        leafs,
        paths,
        comm_rs : comm_rs.iter().copied().map(| c | Some(c.into())).collect(),
        comm_cs : comm_cs.into_iter().map(| c | Some(c.into())).collect(),
        comm_r_lasts : comm_r_lasts.into_iter().map(| c | Some(c.into())).collect(),
        _t : PhantomData,
    };

    instance.synthesize(&mut cs).expect("failed to synthesize circuit");

    assert !(cs.is_satisfied(), "constraints not satisfied");

    assert_eq !(cs.num_inputs(), 5, "wrong number of inputs");
    assert_eq !(cs.num_constraints(), expected_constraints, "wrong number of constraints");
    assert_eq !(cs.get_input(0, "ONE"), Fr::one());

    auto generated_inputs = RationalPoStCompound<Tree>::generate_public_inputs(&pub_inputs, &pub_params, None);
    auto expected_inputs = cs.get_inputs();

    for (((input, label), generated_input) : expected_inputs.iter().skip(1).zip(generated_inputs.iter())) {
        assert_eq !(input, generated_input, "{}", label);
    }

    assert_eq !(generated_inputs.len(), expected_inputs.len() - 1, "inputs are not the same length");
}

BOOST_AUTO_TEST_CASE(test_rational_post_circuit_pedersen) {
    test_rational_post_circuit<BinaryMerkleTree<PedersenHasher>>(16490);
}

BOOST_AUTO_TEST_CASE(test_rational_post_circuit_poseidon) {
    test_rational_post_circuit<BinaryMerkleTree<PoseidonHasher>>(3770);
}

BOOST_AUTO_TEST_SUITE_END()
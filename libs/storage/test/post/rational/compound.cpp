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

#define BOOST_TEST_MODULE post_rational_compound_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/core/sector.hpp>

#include <nil/filecoin/storage/proofs/post/rational/compound.hpp>

using namespace nil::filecoin;

BOOST_AUTO_TEST_SUITE(post_rational_compound_test_suite)

template<typename MerkleTreeType>
void rational_post_test_compound() {
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    let leaves = 32 * get_base_tree_count::<Tree>();
    let sector_size = (leaves * NODE_SIZE) as u64;
    let challenges_count = 2;

    let setup_params = compound_proof::SetupParams {
        vanilla_params : rational::SetupParams {
            sector_size,
            challenges_count,
        },
        partitions : None,
        priority : true,
    };

    let pub_params = RationalPoStCompound::<Tree>::setup(&setup_params).expect("setup failed");

    // Construct and store an MT using a named DiskStore.
    let temp_dir = tempfile::tempdir();
    let temp_path = temp_dir.path();

    let(_data1, tree1) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
    let(_data2, tree2) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));

    let faults = OrderedSectorSet::new ();
    let mut sectors = OrderedSectorSet::new ();
    sectors.insert(0.into());
    sectors.insert(1.into());

    let seed = (0..leaves).map(| _ | rng.gen()).collect::<Vec<u8>>();
    let challenges = derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults);

    let comm_r_lasts_raw = vec ![ tree1.root(), tree2.root() ];
    let comm_r_lasts : Vec<_> = challenges.iter().map(| c | comm_r_lasts_raw[u64::from(c.sector) as usize]).collect();

    let comm_cs : Vec << typename MerkleTreeType::hash_type as Hasher > ::Domain >
        = challenges.iter().map(| _c | <typename MerkleTreeType::hash_type as Hasher>::Domain::random(rng)).collect();

    let comm_rs
        : Vec<_> = comm_cs.iter()
                       .zip(comm_r_lasts.iter())
                       .map(| (comm_c, comm_r_last) | {<typename MerkleTreeType::hash_type as Hasher>::Function::hash2(comm_c, comm_r_last)})
                       .collect();

    let pub_inputs = rational::PublicInputs {
        challenges : &challenges,
        faults : &faults,
        comm_rs : &comm_rs,
    };

    let mut trees = BTreeMap::new ();
    trees.insert(0.into(), &tree1);
    trees.insert(1.into(), &tree2);

    let priv_inputs = rational::PrivateInputs::<Tree> {
        trees : &trees,
        comm_r_lasts : &comm_r_lasts,
        comm_cs : &comm_cs,
    };

    let gparams = RationalPoStCompound::<Tree>::groth_params(Some(rng), &pub_params.vanilla_params)
                      .expect("failed to create groth params");

    let proof =
        RationalPoStCompound::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs, &gparams).expect("proving failed");

    let(circuit, inputs) =
        RationalPoStCompound::<Tree>::circuit_for_test(&pub_params, &pub_inputs, &priv_inputs);

    {
        let mut cs = TestConstraintSystem::new ();

        circuit.synthesize(&mut cs).expect("failed to synthesize");
        assert !(cs.is_satisfied());
        assert !(cs.verify(&inputs));
    }

    let verified = RationalPoStCompound::<Tree>::verify(&pub_params, &pub_inputs, &proof, &NoRequirements)
                       .expect("failed while verifying");

    assert !(verified);
}

BOOST_AUTO_TEST_CASE(rational_post_test_compound_pedersen) {
    rational_post_test_compound<BinaryMerkleTree<PedersenHasher>>();
}

BOOST_AUTO_TEST_CASE(rational_post_test_compound_poseidon) {
    rational_post_test_compound<BinaryMerkleTree<PoseidonHasher>>();
}

BOOST_AUTO_TEST_SUITE_END()
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

#define BOOST_TEST_MODULE drg_compound_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/porep/drg/compound.hpp>

using namespace nil::filecoin;

template<typename MerkleTreeType>
void drgporep_test_compound() {
    // femme::pretty::Logger::new()
    //     .start(log::LevelFilter::Trace)
    //     .ok();

    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    let nodes = 8;
    let degree = BASE_DEGREE;
    let challenges = vec ![ 1, 3 ];

    let replica_id : Fr = Fr::random(rng);
    std::vector<std::uint8_t> data = (0..nodes).flat_map(| _ | fr_into_bytes(&Fr::random(rng))).collect();

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    let cache_dir = tempfile::tempdir();
    let config = StoreConfig::new (cache_dir.path(), cache_key::CommDTree.to_string(),
                                   default_rows_to_discard(nodes, BINARY_ARITY), );

    // Generate a replica path.
    let replica_path = cache_dir.path().join("replica-path");
    let mut mmapped_data = setup_replica(&data, &replica_path);

    let setup_params = compound_proof::SetupParams {
        vanilla_params : drg::SetupParams {
            drg : drg::DrgParams {
                nodes,
                degree,
                expansion_degree : 0,
                porep_id : [32; 32],
            },
            private : false,
            challenges_count : 2,
        },
        partitions : None,
        priority : false,
    };

    let public_params =
        drg_porep_compound<Tree::Hasher, BucketGraph<Tree::Hasher>>::setup(&setup_params).expect("setup failed");

    let data_tree : Option<BinaryMerkleTree<Tree::Hasher>> = None;
    let(tau, aux) = drg::DrgPoRep::<Tree::Hasher, BucketGraph<_>>::replicate(
                        &public_params.vanilla_params, &replica_id.into(), (mmapped_data.as_mut()).into(), data_tree,
                        config, replica_path.clone(), )
                        .expect("failed to replicate");

    let public_inputs = drg::PublicInputs:: << Tree::Hasher as Hasher > ::Domain > {
        replica_id : Some(replica_id.into()),
        challenges,
        tau : Some(tau),
    };
    let private_inputs = drg::PrivateInputs {
        tree_d : &aux.tree_d,
        tree_r : &aux.tree_r,
        tree_r_config_rows_to_discard : default_rows_to_discard(nodes, BINARY_ARITY),
    };

    // This duplication is necessary so public_params don't outlive public_inputs and private_inputs.
    let setup_params = compound_proof::SetupParams {
        vanilla_params : drg::SetupParams {
            drg : drg::DrgParams {
                nodes,
                degree,
                expansion_degree : 0,
                porep_id : [32; 32],
            },
            private : false,
            challenges_count : 2,
        },
        partitions : None,
        priority : false,
    };

    let public_params =
        drg_porep_compound<Tree::Hasher, BucketGraph<Tree::Hasher>>::setup(&setup_params).expect("setup failed");

    {
        let(circuit, inputs) =
            drg_porep_compound<Tree::Hasher, _>::circuit_for_test(&public_params, &public_inputs, &private_inputs, )
                ;

        let mut cs = TestConstraintSystem::new ();

        circuit.synthesize(&mut cs).expect("failed to synthesize test circuit");
        assert(cs.is_satisfied());
        assert(cs.verify(&inputs));

        let blank_circuit =
            <drg_porep_compound<_, _> as CompoundProof<_, _>>::blank_circuit(&public_params.vanilla_params, );

        let mut cs_blank = MetricCS::new ();
        blank_circuit.synthesize(&mut cs_blank).expect("failed to synthesize blank circuit");

        let a = cs_blank.pretty_print_list();
        let b = cs.pretty_print_list();

        for (i, (a, b))
            in a.chunks(100).zip(b.chunks(100)).enumerate() {
                assert_eq !(a, b, "failed at chunk {}", i);
            }
    }

    {
        let gparams = drg_porep_compound<Tree::Hasher>::groth_params(Some(rng), &public_params.vanilla_params, )
                          .expect("failed to get groth params");

        let proof = drg_porep_compound<Tree::Hasher>::prove(&public_params, &public_inputs, &private_inputs, &gparams, )
                        .expect("failed while proving");

        let verified = drg_porep_compound<Tree::Hasher>::verify(&public_params, &public_inputs, &proof, &NoRequirements, )
                           .expect("failed while verifying");

        assert(verified);
    }

    cache_dir.close().expect("Failed to remove cache dir");
}

BOOST_AUTO_TEST_SUITE(drg_compound_test_suite)

BOOST_AUTO_TEST_CASE(test_drgporep_compound_pedersen) {
    drgporep_test_compound<BinaryMerkleTree<PedersenHasher>>();
}

BOOST_AUTO_TEST_CASE(test_drgporep_compound_poseidon) {
    drgporep_test_compound<BinaryMerkleTree<PoseidonHasher>>();
}

BOOST_AUTO_TEST_SUITE_END()
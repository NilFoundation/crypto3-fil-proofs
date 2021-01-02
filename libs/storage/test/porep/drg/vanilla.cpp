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

#define BOOST_TEST_MODULE drg_vanilla_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/porep/drg/vanilla.hpp>

using namespace nil::filecoin;

BOOST_AUTO_TEST_SUITE(drg_vanilla_test_suite)

template<typename MerkleTreeType>
void test_extract_all() {
    auto rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    auto replica_id : <typename MerkleTreeType::hash_type>::Domain = <typename MerkleTreeType::hash_type>::Domain::random(rng);
    auto nodes = 4;
    auto data = vec ![2u8; 32 * nodes];

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    auto cache_dir = tempfile::tempdir();
    auto config = StoreConfig::new (cache_dir.path(), cache_key::CommDTree.to_string(),
                                   default_rows_to_discard(nodes, BINARY_ARITY), );

    // Generate a replica path.
    auto replica_path = cache_dir.path().join("replica-path");
    auto mut mmapped_data = setup_replica(&data, &replica_path);

    auto sp = SetupParams {
        drg : DrgParams {
            nodes,
            degree : BASE_DEGREE,
            expansion_degree : 0,
            porep_id : [32; 32],
        },
        private : false,
        challenges_count : 1,
    };

    auto pp : PublicParams<typename MerkleTreeType::hash_type, BucketGraph<typename MerkleTreeType::hash_type>> = DrgPoRep::setup(&sp).expect("setup failed");

    DrgPoRep::replicate(&pp, &replica_id, (mmapped_data.as_mut()).into(), None, config.clone(), replica_path.clone(), )
        .expect("replication failed");

    auto mut copied = vec ![0; data.len()];
    copied.copy_from_slice(&mmapped_data);
    assert_ne !(data, copied, "replication did not change data");

    auto decoded_data =
        DrgPoRep::<typename MerkleTreeType::hash_type, _>::extract_all(&pp, &replica_id, mmapped_data.as_mut(), Some(config.clone()), )
            .unwrap_or_else(| e | { panic !("Failed to extract data from `DrgPoRep`: {}", e); });

    assert_eq !(data, decoded_data.as_slice(), "failed to extract data");

    cache_dir.close().expect("Failed to remove cache dir");
}

BOOST_AUTO_TEST_CASE(extract_all_pedersen) {
    test_extract_all::<BinaryMerkleTree<PedersenHasher>>();
}

BOOST_AUTO_TEST_CASE(extract_all_sha256) {
    test_extract_all::<BinaryMerkleTree<Sha256Hasher>>();
}

BOOST_AUTO_TEST_CASE(extract_all_blake2s) {
    test_extract_all::<BinaryMerkleTree<Blake2sHasher>>();
}

BOOST_AUTO_TEST_CASE(test_extract<Tree : MerkleTreeTrait>) {
    auto rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    auto replica_id : <typename MerkleTreeType::hash_type>::Domain = <typename MerkleTreeType::hash_type>::Domain::random(rng);
    auto nodes = 4;
    auto data = vec ![2u8; 32 * nodes];

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    auto cache_dir = tempfile::tempdir();
    auto config = StoreConfig::new (cache_dir.path(), cache_key::CommDTree.to_string(),
                                   default_rows_to_discard(nodes, BINARY_ARITY), );

    // Generate a replica path.
    auto replica_path = cache_dir.path().join("replica-path");
    auto mut mmapped_data = setup_replica(&data, &replica_path);

    auto sp = SetupParams {
        drg : DrgParams {
            nodes : data.len() / 32,
            degree : BASE_DEGREE,
            expansion_degree : 0,
            porep_id : [32; 32],
        },
        private : false,
        challenges_count : 1,
    };

    auto pp = DrgPoRep::<typename MerkleTreeType::hash_type, BucketGraph<typename MerkleTreeType::hash_type>>::setup(&sp).expect("setup failed");

    DrgPoRep::replicate(&pp, &replica_id, (mmapped_data.as_mut()).into(), None, config.clone(), replica_path.clone(), )
        .expect("replication failed");

    auto mut copied = vec ![0; data.len()];
    copied.copy_from_slice(&mmapped_data);
    assert_ne !(data, copied, "replication did not change data");

    for (i = 0; i < nodes; ++i) {
        auto decoded_data = DrgPoRep::extract(&pp, &replica_id, &mmapped_data, i, Some(config.clone()))
                               .expect("failed to extract node data from PoRep");

        auto original_data = data_at_node(&data, i);

        assert_eq !(original_data, decoded_data.as_slice(), "failed to extract data");
    }
}

BOOST_AUTO_TEST_CASE(extract_pedersen) {
    test_extract::<BinaryMerkleTree<PedersenHasher>>();
}

BOOST_AUTO_TEST_CASE(extract_sha256) {
    test_extract::<BinaryMerkleTree<Sha256Hasher>>();
}

BOOST_AUTO_TEST_CASE(extract_blake2s) {
    test_extract::<BinaryMerkleTree<Blake2sHasher>>();
}

template<typename MerkleTreeType>
void prove_verify_aux(std::size_t nodes, std::size_t i, bool use_wrong_challenge, bool use_wrong_parents) {
    assert !(i < nodes);

    // The loop is here in case we need to retry because of an edge case in the test design.
    while (true) {
        auto rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
        auto degree = BASE_DEGREE;
        auto expansion_degree = 0;

        auto replica_id : <typename MerkleTreeType::hash_type>::Domain = <typename MerkleTreeType::hash_type>::Domain::random(rng);
        auto data : Vec<u8> = (0..nodes).flat_map(| _ | fr_into_bytes(&Fr::random(rng))).collect();

        // MT for original data is always named tree-d, and it will be
        // referenced later in the process as such.
        auto cache_dir = tempfile::tempdir();
        auto config = StoreConfig::new (cache_dir.path(), cache_key::CommDTree.to_string(),
                                       default_rows_to_discard(nodes, BINARY_ARITY), );

        // Generate a replica path.
        auto replica_path = cache_dir.path().join("replica-path");
        auto mut mmapped_data = setup_replica(&data, &replica_path);

        auto challenge = i;

        auto sp = SetupParams {
            drg : DrgParams {
                nodes,
                degree,
                expansion_degree,
                porep_id : [32; 32],
            },
            private : false,
            challenges_count : 2,
        };

        auto pp = DrgPoRep::<typename MerkleTreeType::hash_type, BucketGraph<_>>::setup(&sp).expect("setup failed");

        auto(tau, aux) = DrgPoRep::<typename MerkleTreeType::hash_type, _>::replicate(&pp, &replica_id, (mmapped_data.as_mut()).into(), None,
                                                               config, replica_path.clone(), )
                            .expect("replication failed");

        auto mut copied = vec ![0; data.len()];
        copied.copy_from_slice(&mmapped_data);
        assert_ne !(data, copied, "replication did not change data");

        auto pub_inputs = PublicInputs:: << typename MerkleTreeType::hash_type > ::Domain > {
            replica_id : Some(replica_id),
            challenges : vec ![ challenge, challenge ],
            tau : Some(tau.clone().into()),
        };

        auto priv_inputs = PrivateInputs::<typename MerkleTreeType::hash_type> {
            tree_d : &aux.tree_d,
            tree_r : &aux.tree_r,
            tree_r_config_rows_to_discard : default_rows_to_discard(nodes, BINARY_ARITY),
        };

        auto real_proof = DrgPoRep::<typename MerkleTreeType::hash_type, _>::prove(&pp, &pub_inputs, &priv_inputs).expect("proving failed");

        if (use_wrong_parents) {
            // Only one 'wrong' option will be tested at a time.
            assert !(!use_wrong_challenge);
            auto real_parents = real_proof.replica_parents;

            // Parent vector claiming the wrong parents.
            auto fake_parents = vec ![real_parents[0]
                                         .iter()
                                         // Incrementing each parent node will give us a different parent set.
                                         // It's fine to be out of range, since this only needs to fail.
                                         .map(| (i, data_proof) | (i + 1, data_proof.clone()))
                                         .collect::<Vec<_>>()];

            auto proof = Proof::new (real_proof.replica_nodes.clone(), fake_parents, real_proof.nodes.clone().into(), );

            auto is_valid = DrgPoRep::verify(&pp, &pub_inputs, &proof).expect("verification failed");

            assert !(!is_valid, "verified in error -- with wrong parents");

            auto mut all_same = true;
            for ((p, _) in &real_parents[0]) {
                if (*p != real_parents[0][0] .0) {
                    all_same = false;
                }
            }

            if (all_same) {
                println !("invalid test data can't scramble proofs with all same parents.");

                // If for some reason, we hit this condition because of the data passed in,
                // try again.
                continue;
            }

            // Parent vector claiming the right parents but providing valid proofs for different
            // parents.
            auto fake_proof_parents = vec ![real_parents[0]
                                               .iter()
                                               .enumerate()
                                               .map(| (i, (p, _)) |
                                                    {
                                                        // Rotate the real parent proofs.
                                                        auto x = (i + 1) % real_parents[0].len();
                                                        auto j = real_parents[0][x] .0;
                                                        (*p, real_parents[0][j as usize] .1.clone())
                                                    })
                                               .collect::<Vec<_>>()];

            auto proof2 = Proof::new (real_proof.replica_nodes, fake_proof_parents, real_proof.nodes.into(), );

            assert !(!DrgPoRep::<typename MerkleTreeType::hash_type, _>::verify(&pp, &pub_inputs, &proof2)
                          .unwrap_or_else(| e | { panic !("Verification failed: {}", e); }),
                     "verified in error -- with wrong parent proofs");

            return ();
        }

        auto proof = real_proof;

        if use_wrong_challenge {
            auto pub_inputs_with_wrong_challenge_for_proof = PublicInputs:: << typename MerkleTreeType::hash_type > ::Domain > {
            replica_id:
                Some(replica_id), challenges : vec ![if challenge == 1 { 2 } else {1}], tau : Some(tau.into()),
            };
            auto verified =
                DrgPoRep::<typename MerkleTreeType::hash_type, _>::verify(&pp, &pub_inputs_with_wrong_challenge_for_proof, &proof, )
                    .expect("Verification failed");
            assert !(!verified, "wrongly verified proof which does not match challenge in public input");
        } else {
            assert !(DrgPoRep::<typename MerkleTreeType::hash_type, _>::verify(&pp, &pub_inputs, &proof).expect("verification failed"),
                     "failed to verify");
        }

        cache_dir.close().expect("Failed to remove cache dir");

        // Normally, just run once.
        break;
    }
}

void prove_verify(std::size_t n, std::size_t i) {
    prove_verify_aux::<BinaryMerkleTree<PedersenHasher>>(n, i, false, false);
    prove_verify_aux::<BinaryMerkleTree<Sha256Hasher>>(n, i, false, false);
    prove_verify_aux::<BinaryMerkleTree<Blake2sHasher>>(n, i, false, false);
}

void prove_verify_wrong_challenge(std::size_t n, std::size_t i) {
    prove_verify_aux::<BinaryMerkleTree<PedersenHasher>>(n, i, true, false);
    prove_verify_aux::<BinaryMerkleTree<Sha256Hasher>>(n, i, true, false);
    prove_verify_aux::<BinaryMerkleTree<Blake2sHasher>>(n, i, true, false);
}

void prove_verify_wrong_parents(std::size_t n, std::size_t i) {
    prove_verify_aux::<BinaryMerkleTree<PedersenHasher>>(n, i, false, true);
    prove_verify_aux::<BinaryMerkleTree<Sha256Hasher>>(n, i, false, true);
    prove_verify_aux::<BinaryMerkleTree<Blake2sHasher>>(n, i, false, true);
}

table_tests !{
    prove_verify {
        prove_verify_32_16_1(16, 1);

        prove_verify_32_64_1(64, 1);
        prove_verify_32_64_2(64, 2);

        prove_verify_32_256_1(256, 1);
        prove_verify_32_256_2(256, 2);
        prove_verify_32_256_3(256, 3);
        prove_verify_32_256_4(256, 4);
        prove_verify_32_256_5(256, 5);
    }
}

BOOST_AUTO_TEST_CASE(test_drgporep_verifies_using_challenge) {
    prove_verify_wrong_challenge(8, 1);
}

BOOST_AUTO_TEST_CASE(test_drgporep_verifies_parents) {
    // Challenge a node (3) that doesn't have all the same parents.
    prove_verify_wrong_parents(8, 5);
}

BOOST_AUTO_TEST_SUITE_END()
//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020 Wukong Moscow Algorithm Lab
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE vanilla_proof_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/proof.hpp>

using namespace nil::filecoin;

BOOST_AUTO_TEST_SUITE(vanilla_proof_test_suite)

BOOST_AUTO_TEST_CASE(test_calculate_fixed_challenges) {
    const auto layer_challenges = LayerChallenges(10, 333);
    const auto expected = 333;

    const auto calculated_count = layer_challenges.challenges_count_all();
    BOOST_ASSERT(expected as usize, calculated_count);
}

BOOST_AUTO_TEST_CASE(extract_all_pedersen_8) {
    test_extract_all::<DiskTree<PedersenHasher, 8, 0, 0>>();
}

BOOST_AUTO_TEST_CASE(extract_all_pedersen_8_2) {
    test_extract_all::<DiskTree<PedersenHasher, 8, 2, 0>>();
}

BOOST_AUTO_TEST_CASE(extract_all_pedersen_8_8_2) {
    test_extract_all::<DiskTree<PedersenHasher, 8, 8, 2>>();
}

BOOST_AUTO_TEST_CASE(extract_all_sha256_8) {
    test_extract_all::<DiskTree<Sha256Hasher, 8, 0, 0>>();
}

BOOST_AUTO_TEST_CASE(extract_all_sha256_8_8) {
    test_extract_all::<DiskTree<Sha256Hasher, 8, 8, 0>>();
}

BOOST_AUTO_TEST_CASE(extract_all_sha256_8_8_2) {
    test_extract_all::<DiskTree<Sha256Hasher, 8, 8, 2>>();
}

BOOST_AUTO_TEST_CASE(extract_all_blake2s_8) {
    test_extract_all::<DiskTree<Blake2sHasher, 8, 0, 0>>();
}

BOOST_AUTO_TEST_CASE(extract_all_blake2s_8_8) {
    test_extract_all::<DiskTree<Blake2sHasher, 8, 8, 0>>();
}

BOOST_AUTO_TEST_CASE(extract_all_blake2s_8_8_2) {
    test_extract_all::<DiskTree<Blake2sHasher, 8, 8, 2>>();
}

BOOST_AUTO_TEST_CASE(extract_all_poseidon_8) {
    test_extract_all::<DiskTree<PoseidonHasher, 8, 0, 0>>();
}

BOOST_AUTO_TEST_CASE(extract_all_poseidon_8_2) {
    test_extract_all::<DiskTree<PoseidonHasher, 8, 2, 0>>();
}

BOOST_AUTO_TEST_CASE(extract_all_poseidon_8_8_2) {
    test_extract_all::<DiskTree<PoseidonHasher, 8, 8, 2>>();
}

template<typename MerkleTreeType>
void test_extract_all() {

    const auto rng = XorShiftRng::from_seed(crate::TEST_SEED);
    const auto replica_id : <typename MerkleTreeType::hash_type>::Domain = <typename MerkleTreeType::hash_type>::Domain::random(rng);
    const std::size_t nodes = 64 * get_base_tree_count::<Tree>();

    std::vector<std::uint8_t> data = (0..nodes)
                             .flat_map(| _ |
                                       {
                                           const auto v : <typename MerkleTreeType::hash_type>::Domain =
                                                       <typename MerkleTreeType::hash_type>::Domain::random(rng);
                                           v.into_bytes()
                                       })
                             .collect();

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    const auto cache_dir = tempfile::tempdir();
    const auto config = StoreConfig(cache_dir.path(), cache_key::CommDTree.to_string(),
                                   default_rows_to_discard(nodes, BINARY_ARITY), );

    // Generate a replica path.
    const auto replica_path = cache_dir.path().join("replica-path");
    auto mmapped_data = setup_replica(&data, &replica_path);

    const auto layer_challenges = LayerChallenges (DEFAULT_STACKED_LAYERS, 5);

    const auto sp = SetupParams {
        nodes, degree : BASE_DEGREE, expansion_degree : EXP_DEGREE, porep_id : [32; 32], layer_challenges,
    };

    const auto pp = StackedDrg<Tree, Blake2sHasher>::setup(&sp);

    StackedDrg<Tree, Blake2sHasher>::replicate(&pp, &replica_id, (mmapped_data.as_mut()).into(), None, config.clone(),
                                                 replica_path);

    auto copied = vec ![0; data.len()];
    copied.copy_from_slice(&mmapped_data);
    assert_ne !(data, copied, "replication did not change data");

    const auto decoded_data =
        StackedDrg::<Tree, Blake2sHasher>::extract_all(&pp, &replica_id, mmapped_data.as_mut(), Some(config), )
            .expect("failed to extract data");

    BOOST_ASSERT(data, decoded_data);

    try {
        cache_dir.close();
    } catch ("Failed to remove cache dir"){

    }
}

void prove_verify_fixed(std::size_t n) {
    const auto challenges = LayerChallenges(DEFAULT_STACKED_LAYERS, 5);

    test_prove_verify<DiskTree<PedersenHasher, 4, 0, 0>>(n, challenges);
    test_prove_verify<DiskTree<PedersenHasher, 4, 2, 0>>(n, challenges);
    test_prove_verify<DiskTree<PedersenHasher, 4, 8, 2>>(n, challenges);

    test_prove_verify<DiskTree<PedersenHasher, 8, 0, 0>>(n, challenges);
    test_prove_verify<DiskTree<PedersenHasher, 8, 2, 0>>(n, challenges);
    test_prove_verify<DiskTree<PedersenHasher, 8, 8, 2>>(n, challenges);

    test_prove_verify<DiskTree<Sha256Hasher, 8, 0, 0>>(n, challenges);
    test_prove_verify<DiskTree<Sha256Hasher, 8, 2, 0>>(n, challenges);
    test_prove_verify<DiskTree<Sha256Hasher, 8, 8, 2>>(n, challenges);

    test_prove_verify<DiskTree<Sha256Hasher, 4, 0, 0>>(n, challenges);
    test_prove_verify<DiskTree<Sha256Hasher, 4, 2, 0>>(n, challenges);
    test_prove_verify<DiskTree<Sha256Hasher, 4, 8, 2>>(n, challenges);

    test_prove_verify<DiskTree<Blake2sHasher, 4, 0, 0>>(n, challenges);
    test_prove_verify<DiskTree<Blake2sHasher, 4, 2, 0>>(n, challenges);
    test_prove_verify<DiskTree<Blake2sHasher, 4, 8, 2>>(n, challenges);

    test_prove_verify<DiskTree<Blake2sHasher, 8, 0, 0>>(n, challenges);
    test_prove_verify<DiskTree<Blake2sHasher, 8, 2, 0>>(n, challenges);
    test_prove_verify<DiskTree<Blake2sHasher, 8, 8, 2>>(n, challenges);

    test_prove_verify<DiskTree<PoseidonHasher, 4, 0, 0>>(n, challenges);
    test_prove_verify<DiskTree<PoseidonHasher, 4, 2, 0>>(n, challenges);
    test_prove_verify<DiskTree<PoseidonHasher, 4, 8, 2>>(n, challenges);

    test_prove_verify<DiskTree<PoseidonHasher, 8, 0, 0>>(n, challenges);
    test_prove_verify<DiskTree<PoseidonHasher, 8, 2, 0>>(n, challenges);
    test_prove_verify<DiskTree<PoseidonHasher, 8, 8, 2>>(n, challenges);
}

template<typename MerkleTreeType>
void test_prove_verify(std::size_t n, const LayerChallenges &challenges) {
    // This will be called multiple times, only the first one succeeds, and that is ok.

    const std::size_t nodes = n * get_base_tree_count::<Tree>();
    const auto rng = XorShiftRng::from_seed(crate::TEST_SEED);

    const auto degree = BASE_DEGREE;
    const auto expansion_degree = EXP_DEGREE;
    const auto replica_id : <typename MerkleTreeType::hash_type>::Domain = <typename MerkleTreeType::hash_type>::Domain::random(rng);
    std::vector<std::uint8_t> data = (0..nodes).flat_map(| _ | fr_into_bytes(&Fr::random(rng))).collect();

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    const auto cache_dir = tempfile::tempdir();
    const auto config = StoreConfig(cache_dir.path(), cache_key::CommDTree.to_string(),
                                   default_rows_to_discard(nodes, BINARY_ARITY), );

    // Generate a replica path.
    const auto replica_path = cache_dir.path().join("replica-path");
    auto mmapped_data = setup_replica(&data, &replica_path);

    const std::size_t partitions = 2;

    const auto arbitrary_porep_id = [92; 32];
    const auto sp = SetupParams {
        nodes,
        degree,
        expansion_degree,
        porep_id : arbitrary_porep_id,
        layer_challenges : challenges,
    };

    const auto pp = StackedDrg::<Tree, Blake2sHasher>::setup(&sp).expect("setup failed");
    const auto(tau, (p_aux, t_aux)) =
        StackedDrg::<Tree, Blake2sHasher>::replicate(&pp, &replica_id, (mmapped_data.as_mut()).into(), None, config,
                                                     replica_path.clone(), )
            .expect("replication failed");

    auto copied = vec ![0; data.len()];
    copied.copy_from_slice(&mmapped_data);
    assert_ne !(data, copied, "replication did not change data");

    const auto seed = rng.gen();
    const auto pub_inputs = PublicInputs:: << typename MerkleTreeType::hash_type > ::Domain, <Blake2sHasher>::Domain > {
        replica_id,
        seed,
        tau : Some(tau),
        k : None,
    };

    // Store a copy of the t_aux for later resource deletion.
    const auto t_aux_orig = t_aux.clone();

    try {
        // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
        // elements based on the configs stored in TemporaryAux.
        const auto t_aux = TemporaryAuxCache::<Tree, Blake2sHasher>(&t_aux, replica_path);
    } catch("failed to restore contents of t_aux"){

    }

    const auto priv_inputs = PrivateInputs {p_aux, t_aux};

    try {
        const auto all_partition_proofs =
            &StackedDrg::<Tree, Blake2sHasher>::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, partitions);
    } catch("failed to generate partition proofs"){

    }

    try {
        const auto proofs_are_valid =
            StackedDrg::<Tree, Blake2sHasher>::verify_all_partitions(&pp, &pub_inputs, all_partition_proofs);
    } catch("failed to verify partition proofs"){

    }

    try {
        // Discard cached MTs that are no longer needed.
        TemporaryAux::<Tree, Blake2sHasher>::clear_temp(t_aux_orig);
    } catch("t_aux delete failed"){

    }

    BOOST_ASSERT (proofs_are_valid);

    try {
        cache_dir.close();
    } catch("Failed to remove cache dir"){

    }
}

// We are seeing a bug, in which setup never terminates for some sector sizes.
// This test is to debug that and should remain as a regression teset.
BOOST_AUTO_TEST_CASE(setup_terminates) {
    std::size_t degree = BASE_DEGREE;
    std::size_t expansion_degree = EXP_DEGREE;
    std::size_t nodes = 1024 * 1024 * 32 * 8;    // This corresponds to 8GiB sectors (32-byte nodes)
    LayerChallenges layer_challenges(10, 333);
    SetupParams sp = {
        nodes, degree, expansion_degree, porep_id : [32; 32], layer_challenges,
    };

    // When this fails, the call to setup should panic, but seems to actually hang (i.e. neither return nor panic) for
    // some reason. When working as designed, the call to setup returns without error.
    const auto _pp = StackedDrg<DiskTree<PedersenHasher, 8, 0, 0>, Blake2sHasher>::setup(sp);
}

BOOST_AUTO_TEST_SUITE_END()

//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
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
    let layer_challenges = LayerChallenges::new (10, 333);
    let expected = 333;

    let calculated_count = layer_challenges.challenges_count_all();
    assert_eq !(expected as usize, calculated_count);
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
    // femme::pretty::Logger::new()
    //     .start(log::LevelFilter::Trace)
    //     .ok();

    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
    let replica_id : <MerkleTreeType::Hasher as Hasher>::Domain = <MerkleTreeType::Hasher as Hasher>::Domain::random(rng);
    let nodes = 64 * get_base_tree_count::<Tree>();

    std::vector<std::uint8_t> data = (0..nodes)
                             .flat_map(| _ |
                                       {
                                           let v : <MerkleTreeType::Hasher as Hasher>::Domain =
                                                       <MerkleTreeType::Hasher as Hasher>::Domain::random(rng);
                                           v.into_bytes()
                                       })
                             .collect();

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    let cache_dir = tempfile::tempdir();
    let config = StoreConfig::new (cache_dir.path(), cache_key::CommDTree.to_string(),
                                   default_rows_to_discard(nodes, BINARY_ARITY), );

    // Generate a replica path.
    let replica_path = cache_dir.path().join("replica-path");
    let mut mmapped_data = setup_replica(&data, &replica_path);

    let layer_challenges = LayerChallenges::new (DEFAULT_STACKED_LAYERS, 5);

    let sp = SetupParams {
        nodes, degree : BASE_DEGREE, expansion_degree : EXP_DEGREE, porep_id : [32; 32], layer_challenges,
    };

    let pp = StackedDrg<Tree, Blake2sHasher>::setup(&sp);

    StackedDrg<Tree, Blake2sHasher>::replicate(&pp, &replica_id, (mmapped_data.as_mut()).into(), None, config.clone(),
                                                 replica_path);

    let mut copied = vec ![0; data.len()];
    copied.copy_from_slice(&mmapped_data);
    assert_ne !(data, copied, "replication did not change data");

    let decoded_data =
        StackedDrg::<Tree, Blake2sHasher>::extract_all(&pp, &replica_id, mmapped_data.as_mut(), Some(config), )
            .expect("failed to extract data");

    assert_eq !(data, decoded_data);

    cache_dir.close().expect("Failed to remove cache dir");
}

void prove_verify_fixed(std::size_t n) {
    let challenges = LayerChallenges::new (DEFAULT_STACKED_LAYERS, 5);

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
    // femme::pretty::Logger::new()
    //     .start(log::LevelFilter::Trace)
    //     .ok();

    let nodes = n * get_base_tree_count::<Tree>();
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    let degree = BASE_DEGREE;
    let expansion_degree = EXP_DEGREE;
    let replica_id : <MerkleTreeType::Hasher as Hasher>::Domain = <MerkleTreeType::Hasher as Hasher>::Domain::random(rng);
    let data : Vec<u8> = (0..nodes).flat_map(| _ | fr_into_bytes(&Fr::random(rng))).collect();

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    let cache_dir = tempfile::tempdir();
    let config = StoreConfig::new (cache_dir.path(), cache_key::CommDTree.to_string(),
                                   default_rows_to_discard(nodes, BINARY_ARITY), );

    // Generate a replica path.
    let replica_path = cache_dir.path().join("replica-path");
    let mut mmapped_data = setup_replica(&data, &replica_path);

    let partitions = 2;

    let arbitrary_porep_id = [92; 32];
    let sp = SetupParams {
        nodes,
        degree,
        expansion_degree,
        porep_id : arbitrary_porep_id,
        layer_challenges : challenges,
    };

    let pp = StackedDrg::<Tree, Blake2sHasher>::setup(&sp).expect("setup failed");
    let(tau, (p_aux, t_aux)) =
        StackedDrg::<Tree, Blake2sHasher>::replicate(&pp, &replica_id, (mmapped_data.as_mut()).into(), None, config,
                                                     replica_path.clone(), )
            .expect("replication failed");

    let mut copied = vec ![0; data.len()];
    copied.copy_from_slice(&mmapped_data);
    assert_ne !(data, copied, "replication did not change data");

    let seed = rng.gen();
    let pub_inputs = PublicInputs:: << MerkleTreeType::Hasher as Hasher > ::Domain, <Blake2sHasher as Hasher>::Domain > {
        replica_id,
        seed,
        tau : Some(tau),
        k : None,
    };

    // Store a copy of the t_aux for later resource deletion.
    let t_aux_orig = t_aux.clone();

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
    // elements based on the configs stored in TemporaryAux.
    let t_aux = TemporaryAuxCache::<Tree, Blake2sHasher>::new (&t_aux, replica_path)
                    .expect("failed to restore contents of t_aux");

    let priv_inputs = PrivateInputs {p_aux, t_aux};

    let all_partition_proofs =
        &StackedDrg::<Tree, Blake2sHasher>::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, partitions, )
             .expect("failed to generate partition proofs");

    let proofs_are_valid =
        StackedDrg::<Tree, Blake2sHasher>::verify_all_partitions(&pp, &pub_inputs, all_partition_proofs, )
            .expect("failed to verify partition proofs");

    // Discard cached MTs that are no longer needed.
    TemporaryAux::<Tree, Blake2sHasher>::clear_temp(t_aux_orig).expect("t_aux delete failed");

    assert !(proofs_are_valid);

    cache_dir.close().expect("Failed to remove cache dir");
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
    let _pp = StackedDrg<DiskTree<PedersenHasher, 8, 0, 0>, Blake2sHasher>::setup(sp);
}

BOOST_AUTO_TEST_SUITE_END()
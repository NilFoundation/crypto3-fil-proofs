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

#define BOOST_TEST_MODULE merkle_proof_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/crypto3/hash/blake2s.hpp>
#include <nil/crypto3/hash/pedersen.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/filecoin/storage/proofs/core/merkle/proof.hpp>

using namespace nil::filecoin;

BOOST_AUTO_TEST_SUITE(merkle_proof_test_suite)

template<typename MerkleTreeType>
void merklepath() {
    std::size_t node_size = 32;
    std::size_t nodes = 64 * get_base_tree_count<MerkleTreeType>();

    let mut rng = rand::thread_rng();
    let(data, tree) = generate_tree<MerkleTreeType>(&mut rng, nodes, None);

    for (std::size_t i = 0; i < nodes; i++) {
        let proof = tree.gen_proof(i).unwrap();

        assert !(proof.verify(), "failed to validate");

        assert !(proof.validate(i), "failed to validate valid merkle path");
        let data_slice = &data[i * node_size..(i + 1) * node_size].to_vec();
        assert !(proof.validate_data(<Tree::Hasher as Hasher>::Domain::try_from_bytes(data_slice).unwrap()),
                 "failed to validate valid data");
    }
}

BOOST_AUTO_TEST_CASE(merklepath_pedersen_2) {
    merklepath::<MerkleTreeWrapper<PedersenHasher, DiskStore << PedersenHasher as Hasher>::Domain>, typenum::U2,
        typenum::U0, typenum::U0, >, > ();
}

BOOST_AUTO_TEST_CASE(merklepath_pedersen_4) {
    merklepath::<MerkleTreeWrapper<PedersenHasher, DiskStore << PedersenHasher as Hasher>::Domain>, typenum::U4,
        typenum::U0, typenum::U0, >, > ();
}

BOOST_AUTO_TEST_CASE(merklepath_pedersen_8) {
    merklepath::<MerkleTreeWrapper<PedersenHasher, DiskStore << PedersenHasher as Hasher>::Domain>, typenum::U8,
        typenum::U0, typenum::U0, >, > ();
}

BOOST_AUTO_TEST_CASE(merklepath_pedersen_2_2) {
    merklepath::<MerkleTreeWrapper<PedersenHasher, DiskStore << PedersenHasher as Hasher>::Domain>, typenum::U2,
        typenum::U2, typenum::U0, >, > ();
}

BOOST_AUTO_TEST_CASE(merklepath_pedersen_2_2_2) {
    merklepath::<MerkleTreeWrapper<PedersenHasher, DiskStore << PedersenHasher as Hasher>::Domain>, typenum::U2,
        typenum::U2, typenum::U2, >, > ();
}

BOOST_AUTO_TEST_CASE(merklepath_poseidon_2) {
    merklepath::<MerkleTreeWrapper<PoseidonHasher, DiskStore << PoseidonHasher as Hasher>::Domain>, typenum::U2,
        typenum::U0, typenum::U0, >, > ();
}

BOOST_AUTO_TEST_CASE(merklepath_poseidon_4) {
    merklepath::<MerkleTreeWrapper<PoseidonHasher, DiskStore << PoseidonHasher as Hasher>::Domain>, typenum::U4,
        typenum::U0, typenum::U0, >, > ();
}

BOOST_AUTO_TEST_CASE(merklepath_poseidon_8) {
    merklepath::<MerkleTreeWrapper<PoseidonHasher, DiskStore << PoseidonHasher as Hasher>::Domain>, typenum::U8,
        typenum::U0, typenum::U0, >, > ();
}

BOOST_AUTO_TEST_CASE(merklepath_poseidon_8_2) {
    merklepath::<MerkleTreeWrapper<PoseidonHasher, DiskStore << PoseidonHasher as Hasher>::Domain>, typenum::U8,
        typenum::U2, typenum::U0, >, > ();
}

BOOST_AUTO_TEST_CASE(merklepath_poseidon_8_4) {
    merklepath::<MerkleTreeWrapper<PoseidonHasher, DiskStore << PoseidonHasher as Hasher>::Domain>, typenum::U8,
        typenum::U4, typenum::U0, >, > ();
}

BOOST_AUTO_TEST_CASE(merklepath_poseidon_8_4_2) {
    merklepath::<MerkleTreeWrapper<PoseidonHasher, DiskStore << PoseidonHasher as Hasher>::Domain>, typenum::U8,
        typenum::U4, typenum::U2, >, > ();
}

BOOST_AUTO_TEST_CASE(merklepath_sha256_2) {
    merklepath::<MerkleTreeWrapper<Sha256Hasher, DiskStore << Sha256Hasher as Hasher>::Domain>, typenum::U2,
        typenum::U0, typenum::U0, >, > ();
}

BOOST_AUTO_TEST_CASE(merklepath_sha256_4) {
    merklepath::<MerkleTreeWrapper<Sha256Hasher, DiskStore << Sha256Hasher as Hasher>::Domain>, typenum::U4,
        typenum::U0, typenum::U0, >, > ();
}

BOOST_AUTO_TEST_CASE(merklepath_sha256_2_4) {
    merklepath::<MerkleTreeWrapper<Sha256Hasher, DiskStore << Sha256Hasher as Hasher>::Domain>, typenum::U2,
        typenum::U4, typenum::U0, >, > ();
}

BOOST_AUTO_TEST_CASE(merklepath_sha256_top_2_4_2) {
    merklepath::<MerkleTreeWrapper<Sha256Hasher, DiskStore << Sha256Hasher as Hasher>::Domain>, typenum::U2,
        typenum::U4, typenum::U2, >, > ();
}

BOOST_AUTO_TEST_CASE(merklepath_blake2s_2) {
    merklepath::<MerkleTreeWrapper<Blake2sHasher, DiskStore << Blake2sHasher as Hasher>::Domain>, typenum::U2,
        typenum::U0, typenum::U0, >, > ();
}

BOOST_AUTO_TEST_CASE(merklepath_blake2s_4) {
    merklepath::<MerkleTreeWrapper<Blake2sHasher, DiskStore << Blake2sHasher as Hasher>::Domain>, typenum::U4,
        typenum::U0, typenum::U0, >, > ();
}

BOOST_AUTO_TEST_CASE(merklepath_blake2s_8_4_2) {
    merklepath::<MerkleTreeWrapper<Blake2sHasher, DiskStore << Blake2sHasher as Hasher>::Domain>, typenum::U8,
        typenum::U4, typenum::U2, >, > ();
}

BOOST_AUTO_TEST_SUITE_END()
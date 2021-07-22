//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#define BOOST_TEST_MODULE filecoin_pieces_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/proofs/pieces.hpp>

BOOST_AUTO_TEST_SUITE(filecoin_pieces_test_suite)

template<typename PieceSizesIterator>
std::tuple<std::array<std::uint8_t, 32>, piece_info>
    build_sector(PieceSizesIterator piece_sizes_first, PieceSizesIterator pieces_sizes_last, sector_size ss) {
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
    let porep_id = [32; 32];
    let graph = StackedBucketGraph<DefaultPieceHasher>::new_stacked(
        sector_size / NODE_SIZE, DRG_DEGREE, EXP_DEGREE, porep_id);

    let mut staged_sector = Vec::with_capacity(u64::from(sector_size) as usize);
    let mut staged_sector_io = std::io::Cursor::new (&mut staged_sector);
    let mut piece_infos = Vec::with_capacity(piece_sizes.len());

    for (i, piece_size)
        in piece_sizes.iter().enumerate() {
            let piece_size_u = u64::from(*piece_size) as usize;
            let mut piece_bytes = vec ![255u8; piece_size_u];
            rng.fill_bytes(&mut piece_bytes);

            let mut piece_file = std::io::Cursor::new (&mut piece_bytes);

            let(piece_info, _) =
                crate::api::add_piece(&mut piece_file, &mut staged_sector_io, *piece_size, &piece_sizes[..i], ) ?
                ;

            piece_infos.push(piece_info);
        }
    BOOST_CHECK_EQUAL(staged_sector.len(), u64::from(sector_size) as usize);

    let data_tree : DataTree = create_base_merkle_tree::<DataTree>(None, graph.size(), &staged_sector);
    let comm_d_root : Fr = data_tree.root().into();
    let comm_d = commitment_from_fr(comm_d_root);

    return std::make_tuple(comm_d, piece_infos);
}

std::uint32_t prev_power_of_two(std::uint32_t x) {
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    return x - (x >> 1);
}

BOOST_AUTO_TEST_CASE(test_empty_source) {
    let mut source = EmptySource::new (12);
    let mut target = Vec::new ();
    source.read_to_end(&mut target);
    BOOST_CHECK_EQUAL(target, vec ![0u8; 12]);
}

BOOST_AUTO_TEST_CASE(test_compute_comm_d_empty) {
    let comm_d = compute_comm_d(SectorSize(2048), &[]);
    BOOST_CHECK_EQUAL(comm_d, [
        252, 126, 146, 130, 150, 229, 22, 250, 173, 233, 134, 178, 143, 146, 212, 74,
        79,  36,  185, 53,  72,  82,  35, 55,  106, 121, 144, 39,  188, 24,  248, 51
    ]);

    let comm_d = compute_comm_d(SectorSize(128), &[]);
    BOOST_CHECK_EQUAL(hex::encode(&comm_d), "3731bb99ac689f66eef5973e4a94da188f4ddcae580724fc6f3fd60dfd488333", );
}

BOOST_AUTO_TEST_CASE(test_get_piece_alignment) {
    let table = vec ![
        (0, 0, (0, 127)),
        (0, 127, (0, 0)),
        (0, 254, (0, 0)),
        (0, 508, (0, 0)),
        (0, 1016, (0, 0)),
        (127, 127, (0, 0)),
        (127, 254, (127, 0)),
        (127, 508, (381, 0)),
        (100, 100, (27, 27)),
        (200, 200, (54, 54)),
        (300, 300, (208, 208)),
    ];

    for (bytes_in_sector, bytes_in_piece, (expected_left_align, expected_right_align))
        in table.clone() {
            let PieceAlignment {
                left_bytes : UnpaddedBytesAmount(actual_left_align),
                right_bytes : UnpaddedBytesAmount(actual_right_align),
            } = get_piece_alignment(UnpaddedBytesAmount(bytes_in_sector), UnpaddedBytesAmount(bytes_in_piece), );
            BOOST_CHECK_EQUAL((expected_left_align, expected_right_align), (actual_left_align, actual_right_align));
        }
}

BOOST_AUTO_TEST_CASE(test_get_piece_start_byte) {
    let pieces = [
        UnpaddedBytesAmount(31),
        UnpaddedBytesAmount(32),
        UnpaddedBytesAmount(33),
    ];

    BOOST_CHECK_EQUAL(get_piece_start_byte(&pieces[..0], pieces[0]), UnpaddedByteIndex(0));
    BOOST_CHECK_EQUAL(get_piece_start_byte(&pieces[..1], pieces[1]), UnpaddedByteIndex(127));
    BOOST_CHECK_EQUAL(get_piece_start_byte(&pieces[..2], pieces[2]), UnpaddedByteIndex(254));
}

BOOST_AUTO_TEST_CASE(test_verify_simple_pieces) {
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    //     g
    //   /  \
        //  e    f
    // / \  / \
        // a  b c  d

    let(a, b, c, d) : ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) = rng.gen();

    let mut e = [0u8; 32];
    let h = piece_hash(&a, &b);
    e.copy_from_slice(h.as_ref());

    let mut f = [0u8; 32];
    let h = piece_hash(&c, &d);
    f.copy_from_slice(h.as_ref());

    let mut g = [0u8; 32];
    let h = piece_hash(&e, &f);
    g.copy_from_slice(h.as_ref());
    let a = PieceInfo::new (a, UnpaddedBytesAmount(127));
    let b = PieceInfo::new (b, UnpaddedBytesAmount(127));
    let c = PieceInfo::new (c, UnpaddedBytesAmount(127));
    let d = PieceInfo::new (d, UnpaddedBytesAmount(127));

    let e = PieceInfo::new (e, UnpaddedBytesAmount(254));
    let f = PieceInfo::new (f, UnpaddedBytesAmount(254));
    let g = PieceInfo::new (g, UnpaddedBytesAmount(508));

    let sector_size = SectorSize(4 * 128);
    let comm_d = g.commitment;

    // println!("e: {:?}", e);
    // println!("f: {:?}", f);
    // println!("g: {:?}", g);

    BOOST_CHECK(
        verify_pieces(&comm_d, &[ a.clone(), b.clone(), c.clone(), d.clone() ], sector_size).expect("failed to verify"),
        "[a, b, c, d]");

    BOOST_CHECK(verify_pieces(&comm_d, &[ e.clone(), c, d ], sector_size).expect("failed to verify"), "[e, c, d]");

    BOOST_CHECK(verify_pieces(&comm_d, &[ e, f.clone() ], sector_size).expect("failed to verify"), "[e, f]");

    BOOST_CHECK(verify_pieces(&comm_d, &[ a, b, f ], sector_size).expect("failed to verify"), "[a, b, f]");

    BOOST_CHECK(verify_pieces(&comm_d, &[g], sector_size).expect("failed to verify"), "[g]");
}

BOOST_AUTO_TEST_CASE(test_verify_padded_pieces) {
    // [
    //   {(A0 00) (BB BB)} -> A(1) P(1) P(1) P(1) B(4)
    //   {(CC 00) (00 00)} -> C(2)      P(1) P(1) P(1) P(1) P(1) P(1)
    // ]
    // [
    //   {(DD DD) (DD DD)} -> D(8)
    //   {(00 00) (00 00)} -> P(1) P(1) P(1) P(1) P(1) P(1) P(1) P(1)
    // ]

    let sector_size = SectorSize(32 * 128);
    let pad = zero_padding(UnpaddedBytesAmount(127));

    let pieces = vec ![
        PieceInfo::new ([1u8; 32], UnpaddedBytesAmount(1 * 127)),
        PieceInfo::new ([2u8; 32], UnpaddedBytesAmount(4 * 127)),
        PieceInfo::new ([3u8; 32], UnpaddedBytesAmount(2 * 127)),
        PieceInfo::new ([4u8; 32], UnpaddedBytesAmount(8 * 127)),
    ];

    let padded_pieces = vec ![
        PieceInfo::new ([1u8; 32], UnpaddedBytesAmount(1 * 127)),
        pad.clone(),
        pad.clone(),
        pad.clone(),
        PieceInfo::new ([2u8; 32], UnpaddedBytesAmount(4 * 127)),
        PieceInfo::new ([3u8; 32], UnpaddedBytesAmount(2 * 127)),
        pad.clone(),
        pad.clone(),
        pad.clone(),
        pad.clone(),
        pad.clone(),
        pad.clone(),
        PieceInfo::new ([4u8; 32], UnpaddedBytesAmount(8 * 127)),
        pad.clone(),
        pad.clone(),
        pad.clone(),
        pad.clone(),
        pad.clone(),
        pad.clone(),
        pad.clone(),
        pad,
    ];

    let hash = | a, b | {
        let hash = piece_hash(a, b);
        let mut res = [0u8; 32];
        res.copy_from_slice(hash.as_ref());
        res
    };

    std::array<std::uint8_t, 32> layer1 = {
        hash(&padded_pieces[0].commitment, &padded_pieces[1].commitment),      // 2: H(A(1) | P(1))
        hash(&padded_pieces[2].commitment, &padded_pieces[3].commitment),      // 2: H(P(1) | P(1))
        padded_pieces[4].commitment,                                           // 4: B(4)
        padded_pieces[5].commitment,                                           // 2: C(2)
        hash(&padded_pieces[6].commitment, &padded_pieces[7].commitment),      // 2: H(P(1) | P(1))
        hash(&padded_pieces[8].commitment, &padded_pieces[9].commitment),      // 2: H(P(1) | P(1))
        hash(&padded_pieces[10].commitment, &padded_pieces[11].commitment),    // 2: H(P(1) | P(1))
        padded_pieces[12].commitment,                                          // 8: D(8)
        hash(&padded_pieces[13].commitment, &padded_pieces[14].commitment),    // 2: H(P(1) | P(1))
        hash(&padded_pieces[15].commitment, &padded_pieces[16].commitment),    // 2: H(P(1) | P(1))
        hash(&padded_pieces[17].commitment, &padded_pieces[18].commitment),    // 2: H(P(1) | P(1))
        hash(&padded_pieces[19].commitment, &padded_pieces[20].commitment),    // 2: H(P(1) | P(1))
    };

    std::array<std::uint8_t, 32> layer2 = {
        hash(&layer1[0], &layer1[1]),      // 4
        layer1[2],                         // 4
        hash(&layer1[3], &layer1[4]),      // 4
        hash(&layer1[5], &layer1[6]),      // 4
        layer1[7],                         // 8
        hash(&layer1[8], &layer1[9]),      // 4
        hash(&layer1[10], &layer1[11]),    // 4
    };

    let layer3 = vec ![
        hash(&layer2[0], &layer2[1]),    // 8
        hash(&layer2[2], &layer2[3]),    // 8
        layer2[4],                       // 8
        hash(&layer2[5], &layer2[6]),    // 8
    ];

    let layer4 = vec ![
        hash(&layer3[0], &layer3[1]),    // 16
        hash(&layer3[2], &layer3[3]),    // 16
    ];

    let comm_d = hash(&layer4[0], &layer4[1]);    // 32

    BOOST_CHECK(verify_pieces(&comm_d, &pieces, sector_size));
}

BOOST_AUTO_TEST_CASE(test_verify_random_pieces) {
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    for
        sector_size in
            &[SectorSize(4 * 128), SectorSize(32 * 128), SectorSize(1024 * 128), SectorSize(1024 * 8 * 128), ] {
                println !("--- {:?} ---", sector_size);
    for (int i = 0; i < 100; i++) {
            println !(" - {} -", i);
            let unpadded_sector_size : UnpaddedBytesAmount = sector_size.clone().into();
            let sector_size = *sector_size;
            let padded_sector_size : PaddedBytesAmount = sector_size.into();

            let mut piece_sizes = Vec::new ();
            while(true) {
                std::size_t  sum_piece_sizes = sum_piece_bytes_with_alignment(piece_sizes);

                if (sum_piece_sizes
                    > padded_sector_size) {
                        piece_sizes.pop();
                        break;
                    }
                if (sum_piece_sizes
                    == padded_sector_size) {
                        break;
                    }

                while (true) {
                    // pieces must be power of two
                    let left = u64::from(padded_sector_size) - u64::from(sum_piece_sizes);
                let left_power_of_two = prev_power_of_two(left as u32);
                let max_exp = (left_power_of_two as f64).log2() as u32;

                std::size_t padded_exp;
                if (max_exp > 7) {
                    padded_exp = rng.gen_range(7,    // 2**7 == 128,
                                  max_exp);
                }
                else {padded_exp = 7;};
                let padded_piece_size = 2u64.pow(padded_exp);
                let piece_size : UnpaddedBytesAmount = PaddedBytesAmount(padded_piece_size).into();
                piece_sizes.push(piece_size);
                let sum : PaddedBytesAmount = sum_piece_bytes_with_alignment(&piece_sizes).into();

                if (sum
                    > padded_sector_size) {
                        // pieces might be too large after padding, so remove them and try again.
                        piece_sizes.pop();
                    }
                else {
                    break;
                }
            }
        }

    // println!(
    //     "  {:?}",
    //     piece_sizes
    //         .iter()
    //         .map(|s| u64::from(*s) / 127)
    //         .collect::<Vec<_>>()
    // );
    BOOST_CHECK(sum_piece_bytes_with_alignment(&piece_sizes) <= unpadded_sector_size);
    BOOST_CHECK(!piece_sizes.is_empty());

    let(comm_d, piece_infos) = build_sector(&piece_sizes, sector_size) ? ;

BOOST_CHECK(
verify_pieces(comm_d, piece_infos, sector_size));
            }
}
}

BOOST_AUTO_TEST_SUITE_END()

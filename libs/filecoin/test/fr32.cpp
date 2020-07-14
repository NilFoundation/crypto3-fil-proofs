//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020 Gokuyun Moscow Algorithm Lab
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

#define BOOST_TEST_MODULE filecoin_fr32_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/proofs/fr32.hpp>

BOOST_AUTO_TEST_SUITE(filecoin_fr32_test_suite)

// Simple (and slow) padder implementation using `BitVec`.
// It is technically not quite right to use `BitVec` to test
// `write_padded` since at the moment that function still uses
// it for some corner cases, but since largely this implementation
// has been replaced it seems reasonable.
std::uint8_t *bit_vec_padding(const std::vector<std::uint8_t> &raw_data) {
    let mut padded_data : BitVec<LittleEndian, u8> = BitVec::new ();
    let raw_data : BitVec<LittleEndian, u8> = BitVec::from(raw_data);

    for (data_unit : raw_data.into_iter().chunks(FR32_PADDING_MAP.data_bits).into_iter()) {
        padded_data.extend(data_unit);

        // To avoid reconverting the iterator, we deduce if we need the padding
        // by the length of `padded_data`: a full data unit would not leave the
        // padded layout aligned (it would leave it unaligned by just `pad_bits()`).
        if (padded_data.size() % 8) {
            for (int i = 0; i < FR32_PADDING_MAP.pad_bits(); i++) {
                padded_data.push_back(false);
            }
        }
    }

    return padded_data.into_boxed_slice();
}

BOOST_AUTO_TEST_CASE(test_position) {
    std::size_t bits = 0;
    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 8; j++) {
            let position = BitByte {bytes : i, bits : j};
            assert_eq !(position.total_bits(), bits);
            bits += 1;
        }
    }
}

// Test the `extract_bits_le` function against the `BitVec` functionality
// (assumed to be correct).
BOOST_AUTO_TEST_CASE(test_random_bit_extraction) {
    // Length of the data vector we'll be extracting from.
    let len = 20;

    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
    std::vector<std::uint8_t> data = (0..len).map(| _ | rng.gen()).collect();

    // TODO: Evaluate designing a scattered pattered of `pos` and `num_bits`
    // instead of repeating too many iterations with any number.
    for (int i = 0; i < 100; i++) {
        let pos = rng.gen_range(0, data.len() / 2);
        let num_bits = rng.gen_range(1, data.len() * 8 - pos);
        let new_offset = rng.gen_range(0, 8);

        let mut bv = BitVecLEu8::new ();
        bv.extend(BitVecLEu8::from(&data[..]).into_iter().skip(pos).take(num_bits), );
        let shifted_bv : BitVecLEu8 = bv >> new_offset;

        BOOST_CHECK_EQUAL(shifted_bv.as_slice(), &extract_bits_and_shift(&data, pos, num_bits, new_offset)[..], );
    }
}

// Test the `shift_bits` function against the `BitVec<LittleEndian, u8>`
// implementation of `shr_assign` and `shl_assign`.
BOOST_AUTO_TEST_CASE(test_bit_shifts) {
    let len = 5;
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    for (int amount = 1; amount < 8; amount++) {
            for
                left in[true, false].iter() {
                    let data : Vec<u8> = (0..len).map(| _ | rng.gen()).collect();

                    let shifted_bits = shift_bits(&data, amount, *left);

                    let mut bv : BitVec<LittleEndian, u8> = data.into();
                    if (*left) {
                        bv >>= amount;
                    } else {
                        bv <<= amount;
                    }
                    // We use the opposite shift notation (see `shift_bits`).

                    BOOST_CHECK_EQUAL(bv.as_slice(), shifted_bits.as_slice());
                }
    }
}

// `write_padded` and `write_unpadded` for 1016 bytes of 1s, check the
// recovered raw data.
BOOST_AUTO_TEST_CASE(test_read_write_padded) {
    let len = 1016;    // Use a multiple of 254.
    let data = vec ![255u8; len];
    let mut padded = Vec::new ();
    let mut reader = crate::fr32_reader::Fr32Reader::new (io::Cursor::new (&data));
    reader.read_to_end(&mut padded).unwrap();

    assert_eq !(padded.len(), FR32_PADDING_MAP.transform_byte_offset(len, true));

    let mut unpadded = Vec::new ();
    let unpadded_written = write_unpadded(&padded, &mut unpadded, 0, len).unwrap();
    assert_eq !(unpadded_written, len);
    assert_eq !(data, unpadded);
    assert_eq !(padded.into_boxed_slice(), bit_vec_padding(data));
}

// `write_padded` and `write_unpadded` for 1016 bytes of random data, recover
// different lengths of raw data at different offset, check integrity.
BOOST_AUTO_TEST_CASE(test_read_write_padded_offset) {
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    let len = 1016;
    let data : Vec<u8> = (0..len).map(| _ | rng.gen()).collect();

    let mut padded = Vec::new ();
    let mut reader = crate::fr32_reader::Fr32Reader::new (io::Cursor::new (&data));
    reader.read_to_end(&mut padded).unwrap();

    {
        let mut unpadded = Vec::new ();
        write_unpadded(&padded, &mut unpadded, 0, 1016).unwrap();
        let expected = &data[0..1016];

        assert_eq !(expected.len(), unpadded.len());
        assert_eq !(expected, &unpadded[..]);
    }

    {
        let mut unpadded = Vec::new ();
        write_unpadded(&padded, &mut unpadded, 0, 44).unwrap();
        let expected = &data[0..44];

        assert_eq !(expected.len(), unpadded.len());
        assert_eq !(expected, &unpadded[..]);
    }

    let excessive_len = 35;
    for
        start in(1016 - excessive_len + 2)..1016 {
            assert !(write_unpadded(&padded, &mut Vec::new (), start, excessive_len).is_err());
        }
}

BOOST_AUTO_TEST_SUITE_END()
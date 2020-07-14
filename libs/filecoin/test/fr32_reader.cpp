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

#define BOOST_TEST_MODULE filecoin_fr32_reader_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/proofs/fr32_reader.hpp>

BOOST_AUTO_TEST_SUITE(filecoin_fr32_reader_test_suite)

BOOST_AUTO_TEST_CASE(test_buffer_read_bit) {
    let mut buffer = Buffer::default();
    let val = 12345u64.to_le_bytes();
    buffer.copy_from_slice(&val[..]);
    buffer.reset_available(64);

    for (int i = 0; i < 8; i++) {
        BOOST_CHECK_EQUAL(buffer.read_bit(), 0 != val[0] & (1 << i));
    }
}

BOOST_AUTO_TEST_CASE(test_buffer_read_u8) {
    let mut buffer = Buffer::default();
    let val = 12345u64.to_le_bytes();
    buffer.copy_from_slice(&val[..]);
    buffer.reset_available(64);

    for (i, &byte)
        in val.iter().enumerate().take(8) {
            let read = buffer.read_u8();
            BOOST_CHECK_EQUAL(read, byte, "failed to read byte {}", i);
        }
}

BOOST_AUTO_TEST_CASE(test_buffer_read_u16) {
    let mut buffer = Buffer::default();
    let val = 12345u64.to_le_bytes();
    buffer.copy_from_slice(&val[..]);
    buffer.reset_available(64);

        for
            val in val.chunks(2) {
                let read = buffer.read_u16();
                BOOST_CHECK_EQUAL(read, u16::from_le_bytes([ val[0], val[1] ]));
            }
}

BOOST_AUTO_TEST_CASE(test_buffer_read_u32) {
    let mut buffer = Buffer::default();
    let val = 12345u64.to_le_bytes();
    buffer.copy_from_slice(&val[..]);
    buffer.reset_available(64);

        for
            val in val.chunks(4) {
                let read = buffer.read_u32();
                BOOST_CHECK_EQUAL(read, u32::from_le_bytes([ val[0], val[1], val[2], val[3] ]));
            }
}

BOOST_AUTO_TEST_CASE(test_buffer_read_u64) {
    let mut buffer = Buffer::default();
    let val = 12345u64;
    buffer.copy_from_slice(&val.to_le_bytes()[..]);
    buffer.reset_available(64);

    let read = buffer.read_u64();
    BOOST_CHECK_EQUAL(read, val);
}

BOOST_AUTO_TEST_CASE(test_simple_short) {
    // Source is shorter than 1 padding cycle.
    let data = vec ![3u8; 30];
    let mut reader = Fr32Reader::new (io::Cursor::new (&data));
    let mut padded = Vec::new ();
    reader.read_to_end(&mut padded).unwrap();
    BOOST_CHECK_EQUAL(&data[..], &padded[..]);

    BOOST_CHECK_EQUAL(padded.into_boxed_slice(), bit_vec_padding(data));
}

BOOST_AUTO_TEST_CASE(test_simple_single) {
    let data = vec ![255u8; 32];
    let mut padded = Vec::new ();
    let mut reader = Fr32Reader::new (io::Cursor::new (&data));
    reader.read_to_end(&mut padded).unwrap();

    BOOST_CHECK_EQUAL(&padded[0..31], &data[0..31]);
    BOOST_CHECK_EQUAL(padded[31], 0b0011_1111);
    BOOST_CHECK_EQUAL(padded[32], 0b0000_0011);
    BOOST_CHECK_EQUAL(padded.len(), 33);

    BOOST_CHECK_EQUAL(padded.into_boxed_slice(), bit_vec_padding(data));
}

BOOST_AUTO_TEST_CASE(test_simple_127) {
    let data = vec ![255u8; 127];
    let mut padded = Vec::new ();
    let mut reader = Fr32Reader::new (io::Cursor::new (&data));
    reader.read_to_end(&mut padded).unwrap();

    BOOST_CHECK_EQUAL(&padded[0..31], &data[0..31]);
    BOOST_CHECK_EQUAL(padded[31], 0b0011_1111);
    BOOST_CHECK_EQUAL(padded[32], 0b1111_1111);

    BOOST_CHECK_EQUAL(padded.len(), 128);

    BOOST_CHECK_EQUAL(padded.into_boxed_slice(), bit_vec_padding(data));
}

BOOST_AUTO_TEST_CASE(test_chained_byte_source) {
    let random_bytes : Vec<u8> = (0..127).map(| _ | rand::random::<u8>()).collect();

    // read 127 bytes from a non-chained source
    let output_x = { let input_x = io::Cursor::new (random_bytes.clone());

    let mut reader = Fr32Reader::new (input_x);
    let mut buf_x = Vec::new ();
    reader.read_to_end(&mut buf_x).expect("could not seek");
    buf_x
};

for (int n = 1; n < 127; n++) {
    let random_bytes = random_bytes.clone();

    // read 127 bytes from a n-byte buffer and then the rest
    let output_y = {
        let input_y = io::Cursor::new (random_bytes.iter().take(n).cloned().collect::<Vec<u8>>())
                          .chain(io::Cursor::new (random_bytes.iter().skip(n).cloned().collect::<Vec<u8>>(), ));

    let mut reader = Fr32Reader::new (input_y);
    let mut buf_y = Vec::new ();
    reader.read_to_end(&mut buf_y).expect("could not seek");

    buf_y
};

BOOST_CHECK_EQUAL(&output_x, &output_y, "should have written same bytes");
BOOST_CHECK_EQUAL(output_x.clone().into_boxed_slice(), bit_vec_padding(random_bytes));
}
}

BOOST_AUTO_TEST_CASE(test_full) {
    let data = vec ![255u8; 127];

    let mut buf = Vec::new ();
    let mut reader = Fr32Reader::new (io::Cursor::new (&data));
    reader.read_to_end(&mut buf).unwrap();

    BOOST_CHECK_EQUAL(buf.clone().into_boxed_slice(), bit_vec_padding(data));
    validate_fr32(&buf);
}

BOOST_AUTO_TEST_CASE(test_long) {
    use rand::RngCore;

    let mut rng = rand::thread_rng();
        for
            i in 1..100 {
            for
                j in 0..50 {
                    let mut data = vec ![0u8; i * j];
                    rng.fill_bytes(&mut data);

                    let mut buf = Vec::new ();
                    let mut reader = Fr32Reader::new (io::Cursor::new (&data));
                    reader.read_to_end(&mut buf).unwrap();

                    BOOST_CHECK_EQUAL(buf.clone().into_boxed_slice(), bit_vec_padding(data));
                }
            }
}

// Simple (and slow) padder implementation using `BitVec`.
// It is technically not quite right to use `BitVec` to test this, since at
// the moment that function still uses
// it for some corner cases, but since largely this implementation
// has been replaced it seems reasonable.
template<typename fn bit_vec_padding(raw_data
                                     : Vec<u8>)
             ->Box<[u8]> {
                 use bitvec:: {order::Lsb0 as LittleEndian, vec::BitVec};
                 use itertools::Itertools;

                 let mut padded_data : BitVec<LittleEndian, u8> = BitVec::new ();
                 let raw_data : BitVec<LittleEndian, u8> = BitVec::from(raw_data);

    for
        data_unit in raw_data.into_iter().chunks(DATA_BITS as usize).into_iter() {
            padded_data.extend(data_unit);

            // To avoid reconverting the iterator, we deduce if we need the padding
            // by the length of `padded_data`: a full data unit would not leave the
            // padded layout aligned (it would leave it unaligned by just `pad_bits()`).
            if padded_data
                .len() % 8 != 0 {
            for
                _ in 0..(TARGET_BITS - DATA_BITS) {
                    padded_data.push(false);
                }
                }
        }

    padded_data.into_boxed_slice()
             }

         fn validate_fr32(bytes
                          : &[u8]) {
    let chunks = (bytes.len() as f64 / 32_f64).ceil() as usize;
    for (i, chunk)
        in bytes.chunks(32).enumerate() {
            let _ = storage_proofs::fr32::bytes_into_fr(chunk).unwrap_or_else(
                | _ | {panic !("chunk {}/{} cannot be converted to valid Fr: {:?}", i + 1, chunks, chunk)});
        }
}

// raw data stream of increasing values and specific
// outliers (0xFF, 9), check the content of the raw data encoded (with
// different alignments) in the padded layouts.
BOOST_AUTO_TEST_CASE(test_exotic) {
    let mut source = vec ![
        1,  2,  3,  4,  5,  6,  7,  8,  9,  10,   11, 12, 13, 14, 15, 16, 17, 18, 19, 20,   21, 22,
        23, 24, 25, 26, 27, 28, 29, 30, 31, 0xff, 1,  2,  3,  4,  5,  6,  7,  8,  9,  10,   11, 12,
        13, 14, 15, 16, 17, 18, 19, 20, 21, 22,   23, 24, 25, 26, 27, 28, 29, 30, 31, 0xff, 9,  9,
    ];
    source.extend(vec ![ 9, 0xff ]);

    let mut buf = Vec::new ();
    let mut reader = Fr32Reader::new (io::Cursor::new (&source));
    reader.read_to_end(&mut buf).unwrap();

    for (i, &byte)
        in buf.iter().enumerate().take(31) {
            BOOST_CHECK_EQUAL(byte, i as u8 + 1);
        }
    BOOST_CHECK_EQUAL(buf[31], 63);                 // Six least significant bits of 0xff
    BOOST_CHECK_EQUAL(buf[32], (1 << 2) | 0b11);    // 7
    for (i, &byte)
        in buf.iter().enumerate().skip(33).take(30) {
            BOOST_CHECK_EQUAL(byte, (i as u8 - 31) << 2);
        }
    BOOST_CHECK_EQUAL(
        buf[63],
        (0x0f << 2));    // 4-bits of ones, half of 0xff, shifted by two, followed by two bits of 0-padding.
    BOOST_CHECK_EQUAL(buf[64], 0x0f | 9 << 4);    // The last half of 0xff, 'followed' by 9.
    BOOST_CHECK_EQUAL(buf[65], 9 << 4);           // A shifted 9.
    BOOST_CHECK_EQUAL(buf[66], 9 << 4);           // Another.
    BOOST_CHECK_EQUAL(buf[67], 0xf0);             // The final 0xff is split into two bytes. Here is the first half.
    BOOST_CHECK_EQUAL(buf[68], 0x0f);             // And here is the second.

    BOOST_CHECK_EQUAL(buf.into_boxed_slice(), bit_vec_padding(source));
}

BOOST_AUTO_TEST_SUITE_END()
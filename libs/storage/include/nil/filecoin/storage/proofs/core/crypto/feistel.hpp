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

use blake2b_simd::blake2b;
use std::mem;

pub const FEISTEL_ROUNDS : usize = 3;
// 3 rounds is an acceptable value for a pseudo-random permutation,
// see https://github.com/filecoin-project/rust-proofs/issues/425
// (and also https://en.wikipedia.org/wiki/Feistel_cipher#Theoretical_work).

pub type Index = u64;

pub type FeistelPrecomputed = (Index, Index, Index);

// Find the minimum number of even bits to represent `num_elements`
// within a `u32` maximum. Returns the left and right masks evenly
// distributed that together add up to that minimum number of bits.
pub fn precompute(num_elements : Index)->FeistelPrecomputed {
    let mut next_pow4 : Index = 4;
    let mut log4 = 1;
    while
        next_pow4 < num_elements {
            next_pow4 *= 4;
            log4 += 1;
        }

    let left_mask = ((1 << log4) - 1) << log4;
    let right_mask = (1 << log4) - 1;
    let half_bits = log4;

    (left_mask, right_mask, half_bits)
}

// Pseudo-randomly shuffle an input from a starting position to another
// one within the `[0, num_elements)` range using a `key` that will allow
// the reverse operation to take place.
pub fn permute(num_elements : Index, index : Index, keys : &[Index], precomputed : FeistelPrecomputed, )->Index {
    let mut u = encode(index, keys, precomputed);

    while
        u >= num_elements {u = encode(u, keys, precomputed)}
            // Since we are representing `num_elements` using an even number of bits,
            // that can encode many values above it, so keep repeating the operation
            // until we land in the permitted range.

            u
}

// Inverts the `permute` result to its starting value for the same `key`.
pub fn invert_permute(num_elements : Index, index : Index, keys : &[Index], precomputed : FeistelPrecomputed, )->Index {
    let mut u = decode(index, keys, precomputed);

    while
        u >= num_elements {
            u = decode(u, keys, precomputed);
        }
    u
}

/// common_setup performs common calculations on inputs shared by encode and decode.
/// Decompress the `precomputed` part of the algorithm into the initial `left` and
/// `right` pieces `(L_0, R_0)` with the `right_mask` and `half_bits` to manipulate
/// them.
fn common_setup(index : Index, precomputed : FeistelPrecomputed)->(Index, Index, Index, Index) {
    let(left_mask, right_mask, half_bits) = precomputed;

    let left = (index & left_mask) >> half_bits;
    let right = index & right_mask;

    (left, right, right_mask, half_bits)
}

fn encode(index : Index, keys : &[Index], precomputed : FeistelPrecomputed)->Index {
    let(mut left, mut right, right_mask, half_bits) = common_setup(index, precomputed);

    for
        key in keys.iter().take(FEISTEL_ROUNDS) {
            let(l, r) = (right, left ^ feistel(right, *key, right_mask));
            left = l;
            right = r;
        }

    (left << half_bits) | right
}

fn decode(index : Index, keys : &[Index], precomputed : FeistelPrecomputed)->Index {
    let(mut left, mut right, right_mask, half_bits) = common_setup(index, precomputed);

    for
        i in(0..FEISTEL_ROUNDS).rev() {
            let(l, r) = ((right ^ feistel(left, keys[i], right_mask)), left);
            left = l;
            right = r;
        }

    (left << half_bits) | right
}

const HALF_FEISTEL_BYTES : usize = mem::size_of::<Index>();
const FEISTEL_BYTES : usize = 2 * HALF_FEISTEL_BYTES;

// Round function of the Feistel network: `F(Ri, Ki)`. Joins the `right`
// piece and the `key`, hashes it and returns the lower `u32` part of
// the hash filtered trough the `right_mask`.
fn feistel(right : Index, key : Index, right_mask : Index)->Index {
    let mut data : [u8; FEISTEL_BYTES] = [0; FEISTEL_BYTES];

    // So ugly, but the price of (relative) speed.
    let r = if FEISTEL_BYTES <= 8 {
        data[0] = (right >> 24) as u8;
        data[1] = (right >> 16) as u8;
        data[2] = (right >> 8) as u8;
        data[3] = right as u8;

        data[4] = (key >> 24) as u8;
        data[5] = (key >> 16) as u8;
        data[6] = (key >> 8) as u8;
        data[7] = key as u8;

        let raw = blake2b(&data);
        let hash = raw.as_bytes();

        Index::from(hash[0]) << 24 | Index::from(hash[1]) << 16 | Index::from(hash[2]) << 8 | Index::from(hash[3])
    }
    else {
        data[0] = (right >> 56) as u8;
        data[1] = (right >> 48) as u8;
        data[2] = (right >> 40) as u8;
        data[3] = (right >> 32) as u8;
        data[4] = (right >> 24) as u8;
        data[5] = (right >> 16) as u8;
        data[6] = (right >> 8) as u8;
        data[7] = right as u8;

        data[8] = (key >> 56) as u8;
        data[9] = (key >> 48) as u8;
        data[10] = (key >> 40) as u8;
        data[11] = (key >> 32) as u8;
        data[12] = (key >> 24) as u8;
        data[13] = (key >> 16) as u8;
        data[14] = (key >> 8) as u8;
        data[15] = key as u8;

        let raw = blake2b(&data);
        let hash = raw.as_bytes();

        Index::from(hash[0]) << 56 | Index::from(hash[1]) << 48 | Index::from(hash[2]) << 40 |
            Index::from(hash[3]) << 32 | Index::from(hash[4]) << 24 | Index::from(hash[5]) << 16 |
            Index::from(hash[6]) << 8 | Index::from(hash[7])
    };

    r& right_mask
}
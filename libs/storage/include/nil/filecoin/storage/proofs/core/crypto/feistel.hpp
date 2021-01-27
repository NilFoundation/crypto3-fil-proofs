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

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/blake2b.hpp>

namespace nil {
    namespace filecoin {

        constexpr static const std::size_t FEISTEL_ROUNDS = 3;
        // 3 rounds is an acceptable value for a pseudo-random permutation,
        // see https://github.com/filecoin-project/rust-proofs/issues/425
        // (and also https://en.wikipedia.org/wiki/Feistel_cipher#Theoretical_work).

        typedef std::uint64_t Index;

        typedef std::tuple<Index, Index, Index> FeistelPrecomputed;

        // Find the minimum number of even bits to represent `num_elements`
        // within a `u32` maximum. Returns the left and right masks evenly
        // distributed that together add up to that minimum number of bits.
        FeistelPrecomputed precompute(Index num_elements) {
            Index next_pow4 = 4;
            Index log4 = 1;
            while (next_pow4 < num_elements) {
                next_pow4 *= 4;
                log4 += 1;
            }

            Index left_mask = ((1ULL << log4) - 1ULL) << log4;
            Index right_mask = (1ULL << log4) - 1ULL;
            Index half_bits = log4;

            return std::make_tuple(left_mask, right_mask, half_bits);
        }

        /// common_setup performs common calculations on inputs shared by encode and decode.
        /// Decompress the `precomputed` part of the algorithm into the initial `left` and
        /// `right` pieces `(L_0, R_0)` with the `right_mask` and `half_bits` to manipulate
        /// them.
        std::tuple<Index, Index, Index, Index> common_setup(Index index, FeistelPrecomputed precomputed) {
            Index left = (index & std::get<0>(precomputed)) >> std::get<2>(precomputed);
            Index right = index & std::get<1>(precomputed);

            return std::make_tuple(left, right, std::get<1>(precomputed), std::get<2>(precomputed));
        }

        constexpr static const std::size_t HALF_FEISTEL_BYTES = sizeof(Index);
        constexpr static const std::size_t FEISTEL_BYTES = 2 * HALF_FEISTEL_BYTES;

        // Round function of the Feistel network: `F(Ri, Ki)`. Joins the `right`
        // piece and the `key`, hashes it and returns the lower `u32` part of
        // the hash filtered trough the `right_mask`.
        template<typename Hash = crypto3::hashes::blake2b<128>>
        Index feistel(Index right, Index key, Index right_mask) {
            std::array<std::uint8_t, FEISTEL_BYTES> data{};
            data.fill(0);

            // So ugly, but the price of (relative) speed.
            Index r;
            if (FEISTEL_BYTES <= 8) {
                data[0] = (right >> 24);
                data[1] = (right >> 16);
                data[2] = (right >> 8);
                data[3] = right;

                data[4] = (key >> 24);
                data[5] = (key >> 16);
                data[6] = (key >> 8);
                data[7] = key;

                typename Hash::digest_type hash = crypto3::hash<Hash>(data);

                r = hash[0] << 24 | hash[1] << 16 | hash[2] << 8 |
                    hash[3];
            }
            else {
                data[0] = (right >> 56);
                data[1] = (right >> 48);
                data[2] = (right >> 40);
                data[3] = (right >> 32);
                data[4] = (right >> 24);
                data[5] = (right >> 16);
                data[6] = (right >> 8);
                data[7] = right;

                data[8] = (key >> 56);
                data[9] = (key >> 48);
                data[10] = (key >> 40);
                data[11] = (key >> 32);
                data[12] = (key >> 24);
                data[13] = (key >> 16);
                data[14] = (key >> 8);
                data[15] = key;

                typename Hash::digest_type hash = crypto3::hash<Hash>(data);

                r = hash[0] << 56 | hash[1] << 48 | hash[2] << 40 |
                    hash[3] << 32 | hash[4] << 24 | hash[5] << 16 |
                    hash[6] << 8 | hash[7];
            };

            return r &right_mask;
        }

        Index encode(Index index, const std::vector<Index> &keys, FeistelPrecomputed precomputed) {
            std::tuple<Index, Index, Index, Index> val = common_setup(index, precomputed);
            Index left = std::get<0>(val), right = std::get<1>(val);

            for (typename std::vector<Index>::const_iterator key = keys.begin(); key < keys.begin() + FEISTEL_ROUNDS;
                 ++key) {
                Index l = right, r = left ^ feistel(right, *key, std::get<2>(val));
                left = l;
                right = r;
            }

            return (left << std::get<3>(val)) | right;
        }

        Index decode(Index index, const std::vector<Index> &keys, FeistelPrecomputed precomputed) {
            std::tuple<Index, Index, Index, Index> val = common_setup(index, precomputed);
            Index left = std::get<0>(val), right = std::get<1>(val);

            for (int i = FEISTEL_ROUNDS; i > 0; i--) {
                Index l = (right ^ feistel(left, keys[i], std::get<2>(val))), r = left;
                left = l;
                right = r;
            }

            return (left << std::get<3>(val)) | right;
        }

        // Pseudo-randomly shuffle an input from a starting position to another
        // one within the `[0, num_elements)` range using a `key` that will allow
        // the reverse operation to take place.
        Index permute(Index num_elements, Index index, const std::vector<Index> &keys, FeistelPrecomputed precomputed) {
            Index u = encode(index, keys, precomputed);

            while (u >= num_elements) {
                u = encode(u, keys, precomputed);
            }
            // Since we are representing `num_elements` using an even number of bits,
            // that can encode many values above it, so keep repeating the operation
            // until we land in the permitted range.

            return u;
        }

        // Inverts the `permute` result to its starting value for the same `key`.
        Index invert_permute(Index num_elements, Index index, const std::vector<Index> &keys,
                             FeistelPrecomputed precomputed) {
            Index u = decode(index, keys, precomputed);

            while (u >= num_elements) {
                u = decode(u, keys, precomputed);
            }
            return u;
        }
    }    // namespace filecoin
}    // namespace nil

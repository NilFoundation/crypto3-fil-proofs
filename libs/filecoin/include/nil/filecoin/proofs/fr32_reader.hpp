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

#ifndef FILECOIN_FR32_READER_HPP
#define FILECOIN_FR32_READER_HPP

#include <boost/predef/other/endian.h>

namespace nil {
    namespace filecoin {
        constexpr static const std::uint64_t DATA_BITS = 254;
        constexpr static const std::uint64_t TARGET_BITS = 256;

        struct Buffer {
            /// How many bits are available to read.
            std::uint64_t available() {
                return avail - pos;
            }

            void reset_available(std::uint64_t bits) {
                pos = 0;
                avail = bits;
            }

            /// Read a single bit at the current position.
            bool read_bit() {
                let res = data & (1 << pos) != 0;
                debug_assert !(self.available() >= 1);
                pos += 1;
                return res;
            }

#ifdef BOOST_ENDIAN_LITTLE_BYTE_AVAILABLE
            std::uint8_t read_u8_range(std::uint64_t) {
                use bitintr::Bextr;
                debug_assert !(available() >= len);
                let res = data.bextr(pos, len) as u8;
                pos += len;
                return;
                res
            }

            std::uint8_t read_u8() {
                use bitintr::Bextr;
                debug_assert !(available() >= 8);
                let res = data.bextr(pos, 8) as u8;
                pos += 8;
                return res;
            }

            std::uint16_t read_u16() {
                debug_assert !(self.available() >= 16);

                use bitintr::Bextr;
                std::uint16_t res = data.bextr(pos, 16);
                pos += 16;
                return res;
            }

            void read_u16_into(std::vector<std::uint8_t> &target) {
                assert(target.size() >= 2);

                let value = read_u16().to_le_bytes();
                target[0] = value[0];
                target[1] = value[1];
            }

            std::uint32_t read_u32() {
                debug_assert !(self.available() >= 32);

                use bitintr::Bextr;
                let res = data.bextr(pos, 32);
                pos += 32;
                return res
            }

            pub fn read_u32_into(&mut self, target : &mut[u8]) {
                assert !(target.len() >= 4);
                let value = self.read_u32().to_le_bytes();
                target[0] = value[0];
                target[1] = value[1];
                target[2] = value[2];
                target[3] = value[3];
            }

            pub fn read_u64_into(&mut self, target : &mut[u8]) {
                assert !(target.len() >= 8);
                let value = self.read_u64().to_le_bytes();
                target[0] = value[0];
                target[1] = value[1];
                target[2] = value[2];
                target[3] = value[3];
                target[4] = value[4];
                target[5] = value[5];
                target[6] = value[6];
                target[7] = value[7];
            }
#endif

            std::uint64_t read_u64() {
                debug_assert !(self.available() >= 64);

                pos += 64;
                return data;
            }

            std::uint64_t data;
            /// Bits already consumed.
            std::uint64_t pos;
            /// Bits available.
            std::uint64_t avail;
        };

        template<typename R>
        struct Fr32Reader {
            std::size_t read_u8_no_pad(std::vector<std::uint8_t> &target) {
                target[0] = buffer.read_u8();
                target_offset += 8;

                return 1;
            }

            std::size_t read_u16_no_pad(std::vector<std::uint8_t> &target) {
                buffer.read_u16_into(&mut target[..2]);
                target_offset += 16;

                return 2;
            }

            std::size_t read_u32_no_pad(std::vector<std::uint8_t> &target) {
                buffer.read_u32_into(&mut target[..4]);
                target_offset += 32;

                return 4;
            }

            std::size_t read_u64_no_pad(std::vector<std::uint8_t> &target) {
                buffer.read_u64_into(&mut target[..8]);
                target_offset += 64;

                return 8;
            }

            /// Read up to 8 bytes into the targets first element.
            /// Assumes that target is not empty.
            std::size_t read_bytes(std::vector<std::uint8_t> &target) {
                std::size_t bit_pos = target_offset % TARGET_BITS;
                std::size_t bits_to_padding;
                if (bit_pos < DATA_BITS) {
                    bits_to_padding = DATA_BITS - bit_pos;
                } else {
                    bits_to_padding = 0;
                }

                if (bits_to_padding >= 8) {
                    fill_buffer();
                }

                std::int32_t available = buffer.available();
                if (available > 0) {
                    std::size_t target_len = target.size();
                    // Try to avoid padding, and copy as much as possible over at once.

                    if (bits_to_padding >= 64 && available >= 64 && target_len >= 8) {
                        return read_u64_no_pad(target);
                    }

                    if (bits_to_padding >= 32 && available >= 32 && target_len >= 4) {
                        return read_u32_no_pad(target);
                    }

                    if (bits_to_padding >= 16 && available >= 16 && target_len >= 2) {
                        return read_u16_no_pad(target);
                    }

                    if (bits_to_padding >= 8 && available >= 8 && target_len >= 1) {
                        return read_u8_no_pad(target);
                    }
                }

                read_u8_padded(target, bits_to_padding, available);
            }

            std::size_t read_u8_padded(const std::vector<std::uint8_t> &target, std::size_t bits_to_padding,
                                       std::uint64_t available) {
                target[0] = 0;

                if (available >= 6) {
                    if (bits_to_padding == 6) {
                        target[0] = buffer.read_u8_range(6);
                        target_offset += 8;
                        return 1;
                    }
                    if (bits_to_padding == 5) {
                        target[0] = buffer.read_u8_range(5);
                        if (buffer.read_bit()) {
                            set_bit(&mut target[0], 7);
                        }
                        target_offset += 8;
                        return 1;
                    }
                }

                for (int i = 0; i < 8; i++) {
                    if (target_offset % TARGET_BITS < DATA_BITS) {
                        if (!fill_buffer()) {
                            if (i > 0) {
                                return 1;
                            } else {
                                return 0;
                            }
                        }

                        if (buffer.read_bit()) {
                            set_bit(&mut target[0], i);
                        }
                    }

                    target_offset += 1;
                }

                return 1;
            }

            /// Fill the inner buffer, only if necessary. Returns `true` if more data is available.
            bool fill_buffer() {
                if (buffer.available() > 0) {
                    // Nothing to do, already some data available.
                    return true;
                }

                let read = source.read(buffer[..]);
                buffer.reset_available(read * 8);

                return read > 0;
            }

            /// The source being padded.
            R source;
            /// How much of the target already was `read` from, in bits.
            std::uint64_t target_offset;
            /// Currently read byte.
            Buffer buffer;
            /// Are we done reading?
            bool done;
        };    // namespace filecoin
    }         // namespace filecoin
}    // namespace nil

#endif
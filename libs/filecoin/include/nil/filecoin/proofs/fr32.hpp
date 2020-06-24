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

#ifndef FILECOIN_FR32_HPP
#define FILECOIN_FR32_HPP

#include <boost/endian/arithmetic.hpp>

namespace nil {
    namespace filecoin {
        typedef std::vector<bool> BitVecLEu8;

        /*!
         * @brief BitByte represents a size expressed in bytes extended
         * with bit precision, that is, not rounded.
         * Invariant: it is an error for bits to be > 7.
         */
        struct BitByte {
            static BitByte from_bits(std::size_t bits) {
                return {bits % 8, bits / 8};
            }

            static BitByte from_bytes(std::size_t bytes) {
                return from_bits(bytes * 8);
            }

            // How many bits in the BitByte (inverse of from_bits).
            std::size_t total_bits() {
                return bytes * 8 + bits;
            }

            // True if the BitByte has no bits component.
            bool is_byte_aligned() {
                return bits == 0;
            }

            // How many distinct bytes are needed to represent data of this size?
            std::size_t bytes_needed() {
                bytes + (bits == 1);
            }

            std::size_t bits;
            std::size_t bytes;
        }

        /*!
         * @brief PaddingMap represents a mapping between data and its padded equivalent.
         *
         * The padding process takes a *byte-aligned stream* of unpadded *raw* data
         * as input and returns another byte stream where padding is applied every
         * `data_bits` to align them to the byte boundary (`element_bits`). The
         * (inverse) *unpadding* process maps that output back to the raw input
         * that generated it.
         * # Padded layout
         * At the *byte-level*, the padded layout is:
         * ```text
         *        (full element)              (full)                 (incomplete)
            ||  data_bits  pad_bits  ||  data_bits  pad_bits  ||  some_data  (no_padding)
                                     ^^                               ^^
                              element boundary                (some_data < data_bits)
                               (byte-aligned)
           ```

         * Each *element* is a byte-aligned stream comprised of a *full unit* of `data_bits`
         * with `pad_bits` at the end to byte-align it (where `pad_bits` is less than a byte,
         * this is a *sub-byte padding* scheme). After the last element boundary there may be
         * an incomplete unit of data (`some_data`) with a length smaller than `data_bits`
         * that hasn't been padded. The padding rules are:
         * 1. Padding is always applied to a full unit of `data_bits`.
         * 2. A full data unit cannot exist without its corresponding padding.
         * 3. A unit of padding is complete by definition: padding can only be applied fully to each element.
         * 4. If there is padding present then there has to be an already formed
         * element there (an element is full if and only if its data unit is full).
         *
         * # Last byte
         *
         * When returning the byte-aligned output generated from the padded *bitstream*
         * (since the padding is done at the bit-level) the conversion results in the
         * last byte having (potentially) more bits than desired. At the *bit-level*
         * the layout of the last byte can either be a complete element (bits of raw
         * data followed by the corresponding padding bits) or an incomplete unit of
         * data: some number of *valid* data (D) bits followed by any number of *extra*
         * bits (X) necessary to complete the byte-aligned stream:
         *
         *   ```text
         *    |   D   D   D   D   X   X   X   X   |
         *            (data)         (extra)      ^ byte boundary (end of output)
         *   ```
         *
         *   (This diagram is just for illustrative purposes, we actually return the output
         *   in little-endian order, see `BitVecLEu8`).
         *
         *   It's important to distinguish these extra bits (generated as a side
         *   effect of the conversion to a byte-aligned stream) from the padding bits
         *   themselves introduced in the padding process: even though both will be
         *   left with a zero value, these extra bits are a place-holder for the actual
         *   raw data bits needed to complete the current unit of data (and hence also
         *   the element, with the corresponding padding bits added after it). Since
         *   extra bits are only a product of an incomplete unit of data there can't
         *   be extra bits after padding bits.
         *
         *   There's no metadata signaling the number of extra bits present in the
         *   last byte in any given padded layout, this is deduced from the fact
         *   that there's only a single number of valid data bits in the last byte,
         *   and hence a number of data bits in total, that maps to a byte-aligned
         *   (multiple of 8) raw data stream that could have been used as input.
         *
         *   # Example: `FR32_PADDING_MAP`
         *
         *   In this case the `PaddingMap` is defined with a data unit of 254 bits that
         *   are byte aligned to a 256-bit (32-byte) element. If the user writes as input,
         *   say, 40 bytes (320 bits) of raw input data to the padding process the resulting
         *   layout would be, at the element (byte) level:

            ```text
                  (full element: 32 bytes)         (incomplete: 9 bytes)
            ||  data_bits: 254  pad_bits: 2  ||   some_data: 66 bits (+ extra bits)
                                             ^^
                                      element boundary
            ```

         *
         * That is, of the original 320 bits (40 bytes) of raw input data, 254 are
         * padded in the first element and the remaining 66 bits form the incomplete
         * data unit after it, which is aligned to 9 bytes. At the bit level, that
         * last incomplete byte will have 2 valid bits and 6 extra bits.
         *
         * # Alignment of raw data bytes in the padded output
         *
         * This section is not necessary to use this structure but it does help to
         * reason about it. By the previous definition, the raw data bits *embedded*
         * in the padded layout are not necessarily grouped in the same byte units
         * as in the original raw data input (due to the inclusion of the padding
         * bits interleaved in that bit stream, which keep shifting the data bits
         * after them).
         *
         * This can also be stated as: the offsets of the bits (relative to the byte
         * they belong to, i.e., *bit-offset*) in the raw data input won't necessarily
         * match the bit-offsets of the raw data bits embedded in the padded layout.
         * The consequence is that each raw byte written to the padded layout won't
         * result in a byte-aligned bit stream output, i.e., it may cause the appearance
         * of extra bits (to convert the output to a byte-aligned stream).
         *
         * There are portions of the padded layout, however, where this alignment does
         * happen. Particularly, when the padded layout accumulates enough padding bits
         * that they altogether add up to a byte, the following raw data byte written
         * will result in a byte-aligned output, and the same is true for all the other
         * raw data byte that follow it up until the element end, where new padding bits
         * shift away this alignment. (The other obvious case is the first element, which,
         * with no padded bits in front of it, has by definition all its embedded raw data
         * bytes aligned, independently of the `data_bits`/`pad_bits` configuration used.)
         *
         * In the previous example, that happens after the fourth element, where 4 units
         * of `pad_bits` add up to one byte and all of the raw data bytes in the fifth
         * element will keep its original alignment from the byte input stream (and the
         * same will happen with every other element multiple of 4). When that fourth
         * element is completed we have then 127 bytes of raw data and 1 byte of padding
         * (totalling 32 * 4 = 128 bytes of padded output), so the interval of raw data
         * bytes `[127..159]` (indexed like this in the input raw data stream) will keep
         * its original alignment when embedded in the padded layout, i.e., every raw
         * data byte written will keep the output bit stream byte-aligned (without extra
         * bits). (Technically, the last byte actually won't be a full byte since its last
         * bits will be replaced by padding).
         *
         * # Key terms
         *
         * Collection of terms introduced in this documentation (with the format
         * `*<new-term>*`). This section doesn't provide a self-contained definition
         * of them (to avoid unnecessary repetition), it just provides (when appropriate)
         * an additional summary of what was already discussed.
         *
         * 1. Raw data: unpadded user-supplied data (we don't use the *unpadded* term
         * to avoid excessive *padding* suffixes in the code). Padding (data) bits.
         * 2. Element: byte-aligned stream consisting of a full unit of data plus the
         * padding bits.
         * 3. Full unit of raw `data_bits` (always followed by padding). Incomplete unit,
         * not followed by padding, doesn't form an element.
         * 4. Byte-aligned stream: always input and output of the (un)padding process,
         * either as raw data or padded (using the term "byte-aligned" and not "byte
         * stream" to stress the boundaries of the elements). Bit streams: used internally
         * when padding data (never returned as bits).
         * 5. Valid data bits, only in the context of the last byte of a byte-aligned stream
         * generated from the padding process. Extra bits: what's left unused of the last
         * byte (in a way the extra bits are the padding at the byte-level, but we don't
         * use that term here to avoid confusions).
         * 6. Sub-byte padding.
         * 7. Bit-offset: offset of a bit within the byte it belongs to, ranging in `[0..8]`.
         * 8. Embedded raw data: view of the input raw data when it has been decomposed in
         * bit streams and padded in the resulting output.
         */
        struct padding_map {
            std::size_t data_bits;
            std::size_t element_bits;

            padding_map(std::size_t data_bits, std::size_t element_bits) {
                // Check that we add less than 1 byte of padding (sub-byte padding).
                assert(("Padding (num bits: " element_bits - data_bits ") must be less than 1 byte.",
                        element_bits - data_bits <= 7, ));
                // Check that the element is byte aligned.
                assert(("Element (num bits: " element_bits ") must be byte aligned.", !element_bits % CHAR_BIT));
            }

            inline void pad(BitVecLEu8 &bits_out) {
                bits_out.insert(std::back_inserter(bits.out), pad_bits(), false);
                // TODO: Optimization: Drop this explicit `push` padding, the padding
                // should happen implicitly when byte-aligning the data unit.
            }

            inline std::size_t pad_bits() const {
                return element_bits - data_bits;
            }

            // Transform an offset (either a position or a size) *expressed in
            // bits* in a raw byte-aligned data stream to its equivalent in a
            // generated padded bit stream, that is, not byte aligned (so we
            // don't count the extra bits here). If `padding` is `false` calculate
            // the inverse transformation.
            std::size_t transform_bit_offset(std::size_t pos, bool padding) {
                // Set the sizes we're converting to and from.
                let(from_size, to_size) = if padding {
                    (self.data_bits, self.element_bits)
                }
                else {(self.element_bits, self.data_bits)};

                // For both the padding and unpadding cases the operation is the same.
                // The quotient is the number of full, either elements, in the padded layout,
                // or groups of `data_bits`, in the raw data input (that will be converted
                // to full elements).
                // The remainder (in both cases) is the last *incomplete* part of either of
                // the two. Even in the padded layout, if there is an incomplete element it
                // has to consist *only* of data (see `PaddingMap#padded-layout`). That amount
                // of spare raw data doesn't need conversion, it can just be added to the new
                // position.
                let(full_elements, incomplete_data) = div_rem(pos, from_size);
                (full_elements * to_size) + incomplete_data
            }

            // Similar to `transform_bit_pos` this function transforms an offset
            // expressed in bytes, that is, we are taking into account the extra
            // bits here.
            // TODO: Evaluate the relationship between this function and `transform_bit_offset`,
            // it seems the two could be merged, or at least restructured to better expose
            // their differences.
            std::size_t transform_byte_offset(std::size_t pos, bool padding) {
                let transformed_bit_pos = transform_bit_offset(pos * 8, padding);

                let transformed_byte_pos = transformed_bit_pos as f64 / 8.;
                // TODO: Optimization: It might end up being cheaper to avoid this
                // float conversion and use / and %.

                // When padding, the final bits in the bit stream will grow into the
                // last (potentially incomplete) byte of the byte stream, so round the
                // number up (`ceil`). When unpadding, there's no way to know a priori
                // how many valid bits are in the last byte, we have to choose the number
                // that fits in a byte-aligned raw data stream, so round the number down
                // to that (`floor`).
                return padding ? transformed_byte_pos.ceil() : transformed_byte_pos.floor();
            }

            // From the `position` specified, it returns:
            // - the absolute position of the start of the next element,
            //   in bytes (since elements -with padding- are byte aligned).
            // - the number of bits left to read (write) from (to) the current
            //   data unit (assuming it's full).
            std::tuple<std::size_t, std::size_t> next_boundary(const BitByte &position) {
                std::size_t position_bits = position.total_bits();

                let(_, bits_after_last_boundary) = div_rem(position_bits, self.element_bits);

                let remaining_data_unit_bits = data_bits - bits_after_last_boundary;

                let next_element_position_bits = position_bits + remaining_data_unit_bits + pad_bits();

                (next_element_position_bits / 8, remaining_data_unit_bits)
            }

            // For a `Seek`able `target` of a byte-aligned padded layout, return:
            // - the size in bytes
            // - the size in bytes of raw data which corresponds to the `target` size
            // - a BitByte representing the number of padded bits contained in the
            //   byte-aligned padded layout
            template<typename SeekableType>
            std::tuple<std::uint64_t, std::uint64_t, BitByte> target_offsets(SeekableType &target) {
                // The current position in `target` is the number of padded bytes already written
                // to the byte-aligned stream.
                let padded_bytes = target.seek(SeekFrom::End(0)) ? ;

                // Deduce the number of input raw bytes that generated that padded byte size.
                let raw_data_bytes = self.transform_byte_offset(padded_bytes as usize, false);

                // With the number of raw data bytes elucidated it can now be specified the
                // number of padding bits in the generated bit stream (before it was converted
                // to a byte-aligned stream), that is, `raw_data_bytes * 8` is not necessarily
                // `padded_bits`).
                let padded_bits = self.transform_bit_offset(raw_data_bytes * 8, true);

                Ok((padded_bytes, raw_data_bytes as u64, BitByte::from_bits(padded_bits), ))
                // TODO: Why do we use `usize` internally and `u64` externally?
            }
        };

        // TODO: Optimization: Evaluate saving the state of a (un)padding operation
        // inside (e.g., as a cursor like in `BitVec`), maybe not in this structure but
        // in a new `Padder` structure which would remember the positions (remaining
        // data bits in the element, etc.) to avoid recalculating them each time across
        // different (un)pad calls.

        // This is the padding map corresponding to Fr32.
        // Most of the code in this module is general-purpose and could move elsewhere.
        // The application-specific wrappers which implicitly use Fr32 embed the FR32_PADDING_MAP.
        const static padding_map FR32_PADDING_MAP = {254, 256};

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        // Convenience interface for API functions – all bundling FR32_PADDING_MAP
        // parameter/return types are tuned for current caller convenience.
        template<typename SeekableType>
        std::uint64_t target_unpadded_bytes(SeekableType &target) {
            let(_, unpadded, _) = FR32_PADDING_MAP.target_offsets(target) ? ;

            return unpadded;
        }

        // Leave the actual truncation to caller, since we can't do it generically.
        // Return the length to which target should be truncated.
        // We might should also handle zero-padding what will become the final byte of target.
        // Technically, this should be okay though because that byte will always be overwritten later.
        // If we decide this is unnecessary, then we don't need to pass target at all.
        template<typename SeekableType>
        std::size_t almost_truncate_to_unpadded_bytes(SeekableType &_target, std::uint64_t length) {
            let padded = BitByte::from_bits(FR32_PADDING_MAP.transform_bit_offset((length * 8) as usize, true));
            let real_length = padded.bytes_needed();
            let _final_bit_count = padded.bits;
            Ok(real_length)
        }

        std::uint64_t to_unpadded_bytes(std::uint64_t padded_bytes) {
            return FR32_PADDING_MAP.transform_byte_offset(padded_bytes as usize, false);
        }

        std::size_t to_padded_bytes(std::size_t unpadded_bytes) {
            return FR32_PADDING_MAP.transform_byte_offset(unpadded_bytes, true);
        }
    }    // namespace filecoin
}    // namespace nil
#endif
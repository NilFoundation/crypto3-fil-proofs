#ifndef FILECOIN_FR32_HPP
#define FILECOIN_FR32_HPP

#include <cstdint>

namespace filecoin {
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
}    // namespace filecoin
#endif
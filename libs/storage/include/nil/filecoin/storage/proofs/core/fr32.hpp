#ifndef FILECOIN_STORAGE_PROOFS_CORE_FR32_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_FR32_HPP

#include <cstdint>

namespace filecoin {
    // Contains 32 bytes whose little-endian value represents an Fr.
    // Invariants:
    // - Value MUST represent a valid Fr.
    // - Length must be 32.
    typedef std::uint8_t fr32;

    // Contains one or more 32-byte chunks whose little-endian values represent Frs.
    // Invariants:
    // - Value of each 32-byte chunks MUST represent valid Frs.
    // - Total length must be a multiple of 32.
    // That is to say: each 32-byte chunk taken alone must be a valid Fr32.
    typedef std::vector<fr32> fr32_vector;

    // Array whose little-endian value represents an Fr.
    // Invariants:
    // - Value MUST represent a valid Fr.
    typedef std::array<fr32, 32> fr32_array;

}    // namespace filecoin

#endif

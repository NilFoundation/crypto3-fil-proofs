#ifndef FILECOIN_PROOFS_TYPES_HPP
#define FILECOIN_PROOFS_TYPES_HPP

#include <cstdint>

namespace nil { namespace filecoin {
    typedef std::size_t post_proof_bytes_amount;
    typedef std::size_t porep_proof_bytes_amount;

    typedef std::uint64_t unpadded_byte_index;
    typedef std::uint64_t unpadded_bytes_amount;
    typedef std::uint64_t padded_bytes_amount;
}}    // namespace filecoin

#endif
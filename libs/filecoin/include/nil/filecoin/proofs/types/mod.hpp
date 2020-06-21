#ifndef FILECOIN_STORAGE_PROOFS_CORE_MOD_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_MOD_HPP

#include <cstdint>

#include <nil/filecoin/storage/proofs/porep/stacked/proof.hpp>

namespace nil {
    namespace filecoin {
        /// Arity for oct trees, used for comm_r_last.
        constexpr static const std::size_t oct_arity = 8;

        /// Arity for binary trees, used for comm_d.
        constexpr static const std::size_t binary_arity = 2;

        typedef std::array<std::uint8_t, 32> commitment;
        typedef std::array<std::uint8_t, 32> challenge_seed;
        typedef std::array<std::uint8_t, 32> proved_id;
        typedef std::array<std::uint8_t, 32> ticket;

        struct seal_pre_commit_output {
            commitment comm_r;
            commitment comm_d;
        }
    }    // namespace filecoin
}    // namespace nil

#endif
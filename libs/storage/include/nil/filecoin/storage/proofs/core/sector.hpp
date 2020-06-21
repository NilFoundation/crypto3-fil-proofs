#ifndef FILECOIN_STORAGE_PROOFS_CORE_SECTOR_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_SECTOR_HPP

#include <nil/filecoin/storage/proofs/core/detail/set.hpp>

namespace nil {
    namespace filecoin {
        typedef std::uint64_t sector_id;
        typedef btree::set<sector_id> ordered_sector_set;
    }    // namespace filecoin
}    // namespace nil

#endif
#ifndef FILECOIN_STORAGE_PROOFS_CORE_PARTITIONS_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_PARTITIONS_HPP

#include <cstdint>

namespace nil {
    namespace filecoin {
        typedef std::int64_t partitions;

        std::int64_t partition_count(partitions p) {
            if (p == -1) {
                return 1;
            } else if (p == 0) {
                return -1;
            } else {
                return p;
            }
        }
    }    // namespace filecoin
}    // namespace nil

#endif
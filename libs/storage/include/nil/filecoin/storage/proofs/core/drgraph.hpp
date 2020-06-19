#ifndef FILECOIN_STORAGE_PROOFS_CORE_DRGRAPH_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_DRGRAPH_HPP

#include <cstdint>

namespace filecoin {
    constexpr static const bool PARALLEL_MERKLE = true;

    /// The base degree used for all DRG graphs. One degree from this value is used to ensure that a
    /// given node always has its immediate predecessor as a parent, thus ensuring unique topological
    /// ordering of the graph nodes.
    constexpr static const std::size_t BASE_DEGREE = 6;
}    // namespace filecoin

#endif
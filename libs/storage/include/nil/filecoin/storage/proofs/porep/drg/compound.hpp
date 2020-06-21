#ifndef FILECOIN_STORAGE_PROOFS_POREP_DRG_COMPOUND_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_DRG_COMPOUND_HPP

#include <nil/filecoin/storage/proofs/porep/drg/compound.hpp>

namespace filecoin {
    template<typename Hash, typename Graph>
    struct drg_porep_compound {
        typedef Hash hash_type;
        typedef Graph graph_type;

        hash_accumulator_set<Hash> _h;
        Graph _g;
    };
}    // namespace filecoin

#endif
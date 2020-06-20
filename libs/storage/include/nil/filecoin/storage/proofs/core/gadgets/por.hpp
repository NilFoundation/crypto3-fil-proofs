#ifndef FILECOIN_STORAGE_PROOFS_CORE_GADGETS_POR_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_GADGETS_POR_HPP

#include <nil/filecoin/storage/proofs/core/proof/compound_proof.hpp>

#include <nil/filecoin/storage/proofs/core/gadgets/variables.hpp>

namespace filecoin {
    template<typename MerkleTreeType, typename Bls12>
    struct por_circuit {
        root<Bls12>
    };
}    // namespace filecoin

#endif
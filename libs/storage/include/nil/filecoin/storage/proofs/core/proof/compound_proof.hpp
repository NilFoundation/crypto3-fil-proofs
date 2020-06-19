#ifndef FILECOIN_STORAGE_PROOFS_CORE_PROOF_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_PROOF_HPP

#include <cstdint>

#include <nil/filecoin/storage/proofs/core/proof/proof.hpp>

namespace filecoin {
    template<typename ProofScheme>
    struct setup_params {
        typedef ProofScheme proof_scheme;

        typedef typename proof_scheme::setup_params setup_params;

        setup_params vanilla_params;
        std::size_t partitions;
        bool priority;
    };

    template<typename ProofScheme>
    struct public_params {
        typedef ProofScheme proof_scheme;
        typedef typename proof_scheme::public_params public_params;

        public_params vanilla_params;
        std::size_t partitions;
        bool priority;
    };

    template<typename ComponentPrivateInputs>
    struct circuit_component {
        typedef ComponentPrivateInputs component_private_inputs;
    };

    /// The CompoundProof trait bundles a proof::ProofScheme and a bellperson::Circuit together.
    /// It provides methods equivalent to those provided by proof::ProofScheme (setup, prove, verify).
    /// See documentation at proof::ProofScheme for details.
    /// Implementations should generally only need to supply circuit and generate_public_inputs.
    /// The remaining trait methods are used internally and implement the necessary plumbing.
    template<typename ProofScheme, template<typename> class Circuit, typename Bls12>
    struct compound_proof {
        typedef typename ProofScheme::proof
    };
}    // namespace filecoin

#endif
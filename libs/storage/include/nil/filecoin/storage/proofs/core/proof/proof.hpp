#ifndef FILECOIN_STORAGE_PROOFS_CORE_PROOF_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_PROOF_HPP

#include <stdint>

namespace filecoin {
    template<typename PublicParams, typename SetupParams, typename PublicInputs, typename PrivateInputs, typename Proof,
             typename Requirements>
    struct proof_scheme {
        typedef PublicParams public_params;
        typedef SetupParams setup_params;
        typedef PublicInputs public_inputs;
        typedef PrivateInputs private_inputs;
        typedef Proof proof_type;

        /// setup is used to generate public parameters from setup parameters in order to specialize
        /// a ProofScheme to the specific parameters required by a consumer.
        virtual public_params setup(const setup_params &p) = 0;

        virtual proof_type prove(const public_params &params, const public_inputs &inputs,
                                 const private_inputs &pinputs) = 0;

        /// verify returns true if the supplied proof is valid for the given public parameter and public inputs.
        /// Note that verify does not have access to private inputs.
        /// Remember that proof is untrusted, and any data it provides MUST be validated as corresponding
        /// to the supplied public parameters and inputs.
        virtual bool verify(const public_params &pub_params, const public_inputs &pub_inputs, const proof &pr) = 0;
    };

}    // namespace filecoin

#endif
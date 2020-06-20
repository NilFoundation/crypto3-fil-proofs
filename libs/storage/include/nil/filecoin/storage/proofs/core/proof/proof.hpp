#ifndef FILECOIN_STORAGE_PROOFS_CORE_PROOF_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_PROOF_HPP

#include <cstdint>

namespace filecoin {
    template<typename PublicParams, typename SetupParams, typename PublicInputs, typename PrivateInputs, typename Proof,
             typename Requirements>
    struct proof_scheme {
        typedef PublicParams public_params_type;
        typedef SetupParams setup_params_type;
        typedef PublicInputs public_inputs_type;
        typedef PrivateInputs private_inputs_type;
        typedef Proof proof_type;

        /// setup is used to generate public parameters from setup parameters in order to specialize
        /// a ProofScheme to the specific parameters required by a consumer.
        virtual public_params_type setup(const setup_params_type &p) = 0;

        virtual proof_type prove(const public_params_type &params, const public_inputs_type &inputs,
                                 const private_inputs_type &pinputs) = 0;

        /// verify returns true if the supplied proof is valid for the given public parameter and public inputs.
        /// Note that verify does not have access to private inputs.
        /// Remember that proof is untrusted, and any data it provides MUST be validated as corresponding
        /// to the supplied public parameters and inputs.
        virtual bool verify(const public_params_type &pub_params, const public_inputs_type &pub_inputs,
                            const proof_type &pr) = 0;
    };

    struct no_requirements { };

}    // namespace filecoin

#endif
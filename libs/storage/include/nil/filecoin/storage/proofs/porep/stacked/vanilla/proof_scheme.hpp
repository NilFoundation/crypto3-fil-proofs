//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nemo@nil.foundation>

//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_PROOF_SCHEME_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_PROOF_SCHEME_HPP

#include <nil/filecoin/storage/core/proof/proof_scheme.hpp>

namespace nil {
    namespace filecoin {
        namespace vanilla {
            template<typename PublicParams, typename SetupParams, typename PublicInputs, typename PrivateInputs,
                     typename Proof, typename Requirements>
            struct proof_scheme : public filecoin::proof_scheme<PublicParams, SetupParams, PublicInputs, PrivateInputs,
                                                                Proof, Requirements> {
                /// setup is used to generate public parameters from setup parameters in order to specialize
                /// a ProofScheme to the specific parameters required by a consumer.
                virtual public_params_type setup(const setup_params_type &p) override {
                }

                virtual proof_type prove(const public_params_type &params, const public_inputs_type &inputs,
                                         const private_inputs_type &pinputs) override {
                }

                /// verify returns true if the supplied proof is valid for the given public parameter and public inputs.
                /// Note that verify does not have access to private inputs.
                /// Remember that proof is untrusted, and any data it provides MUST be validated as corresponding
                /// to the supplied public parameters and inputs.
                virtual bool verify(const public_params_type &pub_params, const public_inputs_type &pub_inputs,
                                    const proof_type &pr) override {
                }
            };
        }    // namespace vanilla
    }        // namespace filecoin
}    // namespace nil

#endif

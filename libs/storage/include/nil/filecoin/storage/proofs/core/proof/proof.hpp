//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020 Gokuyun Moscow Algorithm Lab
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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_PROOF_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_PROOF_HPP

#include <cstdint>

namespace nil {
    namespace filecoin {
        template<typename PublicParams, typename SetupParams, typename PublicInputs, typename PrivateInputs,
                 typename Proof, typename Requirements>
        struct proof_scheme {
            typedef PublicParams public_params_type;
            typedef SetupParams setup_params_type;
            typedef PublicInputs public_inputs_type;
            typedef PrivateInputs private_inputs_type;
            typedef Proof proof_type;
            typedef Requirements requirements_type;

            /// setup is used to generate public parameters from setup parameters in order to specialize
            /// a ProofScheme to the specific parameters required by a consumer.
            virtual public_params_type setup(const setup_params_type &p) = 0;

            virtual proof_type prove(const public_params_type &params, const public_inputs_type &inputs,
                                     const private_inputs_type &pinputs) = 0;

            virtual std::vector<proof_type> prove_all_partitions(const public_params_type &pub_params,
                                                                 const public_inputs_type &pub_in,
                                                                 const private_inputs_type &priv_in,
                                                                 std::size_t partition_count) {
                std::vector<proof_type> result;

                for (int k = 0; k < partition_count; k++) {
                    result.push_back(prove(pub_params, with_partition(pub_in, k), priv_in));
                }

                return result;
            }

            /// verify returns true if the supplied proof is valid for the given public parameter and public inputs.
            /// Note that verify does not have access to private inputs.
            /// Remember that proof is untrusted, and any data it provides MUST be validated as corresponding
            /// to the supplied public parameters and inputs.
            virtual bool verify(const public_params_type &pub_params, const public_inputs_type &pub_inputs,
                                const proof_type &pr) = 0;

            // This method must be specialized by concrete ProofScheme implementations which use partitions.
            virtual public_inputs_type with_partition(const public_inputs_type &pub_in,
                                                      boost::optional<std::size_t> k) {
                return pub_in;
            }

            virtual bool satisfies_requirements(const public_params_type &_pub_params,
                                                const requirements_type &_requirements,
                                                std::size_t _partitions) {
                return true;
            }
        };

        struct no_requirements { };

    }    // namespace filecoin
}    // namespace nil

#endif
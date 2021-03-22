//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nemo@nil.foundation>
//
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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_POREP_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_POREP_HPP

#include <nil/filecoin/storage/proofs/core/data.hpp>
#include <nil/filecoin/storage/proofs/core/proof/proof.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/params.hpp>

namespace nil {
    namespace filecoin {
        template<typename Hash>
        struct binary_merkle_tree;

        template<typename H, typename G, typename TauType, typename AuxType, typename PublicParams,
                 typename SetupParams, typename PublicInputs, typename PrivateInputs, typename Proof,
                 typename Requirements>
        class PoRep : public ProofScheme<PublicParams, SetupParams, PublicInputs, PrivateInputs, Proof, Requirements> {
            typedef ProofScheme<PublicParams, SetupParams, PublicInputs, PrivateInputs, Proof, Requirements>
                policy_type;

        public:
            typedef TauType tau_type;
            typedef AuxType aux_type;

            typedef typename policy_type::public_params_type public_params_type;
            typedef typename policy_type::setup_params_type setup_params_type;
            typedef typename policy_type::public_inputs_type public_inputs_type;
            typedef typename policy_type::private_inputs_type private_inputs_type;
            typedef typename policy_type::proof_type proof_type;

            virtual std::pair<Tau, ProverAux> replicate(const public_params_type &pub_params,
                                                        const typename H::digest_type &replica_id, const data &data,
                                                        const binary_merkle_tree<G> &data_tree,
                                                        const store_config &config,
                                                        const boost::filesystem::path &replica_path) = 0;

            virtual std::vector<std::uint8_t> extract_all(const public_params_type &pub_params,
                                                          const typename H::digest_type &replica_id,
                                                          const std::vector<std::uint8_t> &replica,
                                                          const store_config &config) = 0;

            virtual std::vector<std::uint8_t> extract(const public_params_type &pub_params,
                                                      const typename H::digest_type &replica_id,
                                                      const std::vector<std::uint8_t> &replica,
                                                      std::size_t node,
                                                      const store_config &config) = 0;
        };
    }    // namespace filecoin
}    // namespace nil

#endif

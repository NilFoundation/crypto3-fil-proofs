//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_COMPOUND_PROOF_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_COMPOUND_PROOF_HPP

#include <cstdint>

#include <nil/filecoin/storage/proofs/core/proof/proof.hpp>
#include <nil/filecoin/storage/proofs/core/proof/multi_proof.hpp>

namespace nil {
    namespace filecoin {
        template<typename ProofScheme>
        struct setup_params {
            typedef ProofScheme proof_scheme;

            typedef typename proof_scheme::setup_params setup_params_type;

            setup_params_type vanilla_params;
            std::size_t partitions;
            bool priority;
        };

        template<typename ProofScheme>
        struct public_params {
            typedef ProofScheme proof_scheme;
            typedef typename proof_scheme::public_params public_params_type;

            public_params_type vanilla_params;
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
        template<typename ProofScheme, template<typename> class Circuit>
        struct compound_proof {
            typedef ProofScheme proof_scheme_type;
            typedef typename proof_scheme_type::public_inputs_type public_inputs_type;
            typedef typename proof_scheme_type::public_params_type public_params_type;
            typedef typename proof_scheme_type::private_inputs_type private_inputs_type;
            typedef typename proof_scheme_type::setup_params_type setup_inputs_type;
            typedef typename proof_scheme_type::requirements_type requirements_type;
            typedef typename proof_scheme_type::proof_type proof_type;

            virtual public_params_type setup(const setup_inputs_type &sp) {
                return {proof_scheme_type::setup(sp.vanilla_params), sp.partitions, sp.priority};
            }

            virtual std::size_t partition_count(const public_params_type &pp) const {
                return pp.partitions == -1 ? 1 : (!pp.partitions ? -1 : pp.partitions);
            }

            virtual multi_proof<groth16::mapped_parameters<algebra::curves::bls12<381>>>
                prove(const public_params_type &pp, const public_inputs_type &pub_in,
                      const private_inputs_type &priv_in,
                      const groth16::mapped_parameters<algebra::curves::bls12<381>> &groth_parameters) {
                std::size_t pc = partition_count(pp);

                assert(("There must be partitions", pc > 0));
            }

            virtual bool verify(const public_params_type &pp, const public_inputs_type &pi,
                                const groth16::mapped_parameters<algebra::curves::bls12<381>> &mproof,
                                const requirements_type &requirements) {
                assert(("Inconsistent inputs", mproof.circuit_proofs.size() == partition_count(pp)));
            }

            template<typename PublicInputsIterator, typename MultiProofIterator>
            bool verify(const public_params_type &pp, PublicInputsIterator pifirst, PublicInputsIterator pilast,
                        MultiProofIterator mpfirst, MultiProofIterator mplast, const requirements_type &requirements) {
                assert(("Inconsistent inputs", std::distance(pifirst, pilast) == std::distance(mpfirst, mplast)));
                assert(("Inconsistent inputs",
                        std::accumulate(
                            mpfirst, mplast, true,
                            [&](typename std::iterator_traits<MultiProofIterator>::value_type c,
                                const typename std::iterator_traits<MultiProofIterator>::value_type &v) -> bool {
                                return std::move(c) * (v.circuit_proofs.size() == partition_count(pp));
                            })));
                assert(("Cannot verify empty proofs", std::distance(pifirst, pilast)));
            }

            /*!
             * @brief Circuit_proof creates and synthesizes a circuit from concrete params/inputs, then generates a
             * groth proof from it. It returns a groth proof. circuit_proof is used internally and should neither be
             * called nor implemented outside of default trait methods.
             *
             * @tparam ProofIterator
             */
            template<typename ProofIterator>
            std::enable_if<
                std::is_same<typename std::iterator_traits<ProofIterator>::value_type, proof_type>::value,
                crypto3::zk::snark::r1cs_ppzksnark_proof<typename algebra::curves::bls12<381>::scalar_field_type>>::type
                circuit_proofs(const public_inputs_type &pub_in, ProofIterator vanilla_proof_first,
                               ProofIterator vanilla_proof_last, const public_params_type &pp,
                               const groth16::mapped_params<algebra::curves::bls12<381>> &groth_params, bool priority) {
                assert(("Cannot create a circuit proof over missing vanilla proofs",
                        std::distance(vanilla_proof_first, vanilla_proof_last)));
            }

            /*!
             * @brief generate_public_inputs generates public inputs suitable for use as input during verification
        of a proof generated from this CompoundProof's bellperson::Circuit (C). These inputs correspond
        to those allocated when C is synthesized.
             * @param pub_in
             * @param pub_params
             * @param partition_k
             * @return
             */
            virtual std::vector<fr> generate_public_inputs(const public_inputs_type &pub_in,
                                                           const public_params_type &pub_params,
                                                           std::size_t partition_k) = 0;

            /*!
             * @brief circuit constructs an instance of this CompoundProof's bellperson::Circuit.
        circuit takes PublicInputs, PublicParams, and Proof from this CompoundProof's proof::ProofScheme (S)
        and uses them to initialize Circuit fields which will be used to construct public and private
        inputs during circuit synthesis.
             * @param public_inputs
             * @param components_private_inputs
             * @param vanilla_proof
             * @param public_param
             * @param partition_k
             * @return
             */
            virtual Circuit<algebra::curves::bls12<381>>
                circuit(const public_inputs_type &public_inputs,
                        const ComponentsPrivateInputs &components_private_inputs, const proof_type &vanilla_proof,
                        const public_params_type &public_param, std::size_t partition_k) = 0;

            virtual Circuit<algebra::curves::bls12<381>> blank_circuit(const public_params_type &pp) = 0;

            /*!
             * @brief If the rng option argument is set, parameters will be
        generated using it.  This is used for testing only, or where
        parameters are otherwise unavailable (e.g. benches).  If rng
        is not set, an error will result if parameters are not
        present.
             * @tparam UniformRandomGenerator
             * @param rng
             * @param pp
             * @return
             */
            template<typename UniformRandomGenerator, template<typename> class Groth16MappedParams>
            virtual Groth16MappedParams<algebra::curves::bls12<381>> groth_params(UniformRandomGenerator &rng,
                                                                                  const public_params_type &pp) {
                return get_groth_params(rng, blank_circuit(pp), pp);
            }

            /*!
             * @brief If the rng option argument is set, parameters will be generated using it.  This is used for
        testing
             * only, or where parameters are otherwise unavailable (e.g. benches).  If rng
        is not set, an error will result if parameters are not
        present.
             * @tparam UniformRandomGenerator
             * @param rng
             * @param pp
             * @return
             */
            template<typename UniformRandomGenerator>
            virtual crypto3::zk::snark::r1cs_ppzksnark_verification_key<
                typename algebra::curves::bls12<381>::scalar_field_type>
                verifying_key(UniformRandomGenerator &rng, const public_params_type &pp) {
                return get_verifying_key(rng, blank_circuit(pp), pp);
            }
        };
    }    // namespace filecoin
}    // namespace nil

#endif
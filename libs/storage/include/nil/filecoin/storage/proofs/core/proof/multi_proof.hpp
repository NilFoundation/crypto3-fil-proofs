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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_MULTI_PROOF_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_MULTI_PROOF_HPP

#include <vector>

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

namespace nil {
    namespace filecoin {
        class multi_proof {
            typedef crypto3::zk::snark::r1cs_gg_ppzksnark<typename crypto3::algebra::curves::bls12<381>> proof_system_type;

        public:
            std::vector<typename proof_system_type::proof_type> circuit_proofs;
            typename proof_system_type::verification_key_type verifying_key;

            multi_proof(const std::vector<typename proof_system_type::proof_type> &proof,
                        const typename proof_system_type::verification_key_type &key) :
                circuit_proofs(proof),
                verifying_key(key) {
            }

            std::size_t size() {
                return circuit_proofs.size();
            }

            bool empty() {
                return circuit_proofs.empty();
            }
        };
    }    // namespace filecoin
}    // namespace nil

#endif

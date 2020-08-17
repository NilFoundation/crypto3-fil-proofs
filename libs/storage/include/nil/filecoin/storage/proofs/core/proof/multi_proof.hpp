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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_MULTI_PROOF_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_MULTI_PROOF_HPP

#include <vector>

#include <nil/algebra/curves/bls12.hpp>

#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

namespace nil {
    namespace filecoin {
        struct multi_proof {
            std::vector<r1cs_ppzksnark_proof<algebra::curves::bls12<381>>> circuit_proofs;
            std::vector<r1cs_ppzksnark_verification_key<algebra::curves::bls12<381>>> verifying_key;

            multi_proof(const r1cs_ppzksnark_proof<algebra::curves::bls12<381>> &proof, const r1cs_ppzksnark_verification_key<algebra::curves::bls12<381>> &key) :
                circuit_proofs(proof), verifying_key(key) {
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
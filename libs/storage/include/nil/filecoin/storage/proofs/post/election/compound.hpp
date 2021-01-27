//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020 Wukong Moscow Algorithm Lab
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

#ifndef FILECOIN_STORAGE_PROOFS_POST_ELECTION_COMPOUND_HPP
#define FILECOIN_STORAGE_PROOFS_POST_ELECTION_COMPOUND_HPP

#include <nil/filecoin/storage/proofs/core/parameter_cache.hpp>
#include <nil/filecoin/storage/proofs/core/proof/compound_proof.hpp>

#include <nil/filecoin/storage/proofs/post/election/vanilla.hpp>
#include <nil/filecoin/storage/proofs/post/election/circuit.hpp>

namespace nil {
    namespace filecoin {
        namespace post {
            namespace election {
                template<typename MerkleTreeType, template<typename> class Circuit,
                         typename ParameterSetMetadata, typename ProofScheme>
                struct ElectionPoStCompound
                    : public cacheable_parameters<Circuit, ParameterSetMetadata, MerkleTreeType>,
                      public compound_proof<ElectionPoSt<MerkleTreeType>,
                                            ElectionPoStCircuit<MerkleTreeType, algebra::curves::bls12<381>, Circuit>> {
                    virtual std::string cache_prefix() const override {
                        return "proof-of-spacetime-election-" + MerkleTreeType::display();
                    }
                };
            }    // namespace election
        }        // namespace post
    }            // namespace filecoin
}    // namespace nil

#endif

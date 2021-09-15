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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_COLUMN_PROOF_COMPONENT_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_COLUMN_PROOF_COMPONENT_HPP

#include <nil/filecoin/storage/proofs/porep/stacked/circuit/column.hpp>

namespace nil {
    namespace filecoin {
        namespace porep {
            namespace stacked {
                namespace components {

                    using namespace crypto3::zk::snark;

                    template<typename FieldType, typename Hash, std::size_t BaseArity, std::size_t SubTreeArity,
                             std::size_t TopTreeArity>
                    struct ColumnProof : public components::component<FieldType> {

                        Column<FieldType> column;
                        AuthPath<Hash, BaseArity, SubTreeArity, TopTreeArity> inclusion_proof;

                        ColumnProof(components::blueprint<FieldType> &bp, 
                                    const vanilla::PublicParams<MerkleTreeType> &params) :
                                    components::component<FieldType>(bp), column(bp, params), 
                                    AuthPath<Hash, BaseArity, SubTreeArity, TopTreeArity>(params.graph.size()) {}

                        ColumnProof(components::blueprint<FieldType> &bp, 
                                    VanillaColumnProof<Proof> vanilla_proof): 
                                    components::component<FieldType>(bp), column(vanilla_proof.column){

                            inclusion_proof = AuthPath<Hash, BaseArity, SubTreeArity, TopTreeArity>(
                                vanilla_proof.inclusion_proof);
                        }
                    };
                }    // namespace components
            }        // namespace stacked
        }            // namespace porep
    }                // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_STORAGE_PROOFS_POREP_STACKED_COLUMN_PROOF_COMPONENT_HPP

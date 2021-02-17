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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_COLUMN_PROOF_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_COLUMN_PROOF_HPP

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/column.hpp>

namespace nil {
    namespace filecoin {
        namespace stacked {
            namespace vanilla {
                template<typename MerkleTreeType>
                struct ColumnProof {
                    typedef MerkleTreeType tree_type;
                    typedef typename tree_type::hash_type hash_type;

                    typename hash_type::digest_type root() {
                        return inclusion_proof.root();
                    }

                    typename hash_type::digest_type get_node_at_layer(std::size_t layer) {
                        return column.get_node_at_layer(layer);
                    }

                    Fr column_hash() {
                        return column.hash();
                    }

                    bool verify(std::uint32_t challenge, typename hash_type::digest_type &expected_root) {
                        Fr c_i = column_hash();

                        return inclusion_proof.root() == expected_root && inclusion_proof.validate_data(c_i.into()) &&
                               inclusion_proof.validate(challenge);
                    }

                    Column<hash_type> column;
                    tree_type inclusion_proof;
                };

                /// Create a column proof for this column.
                template<template<typename = typename hash_type::digest_type> class StoreType,
                         template<typename = hash_type,
                                  typename = StoreType<typename hash_type::digest_type> class MerkleTreeType>
                         ColumnProof make_proof(const Column &columnself, tree_c
                                                : &Tree, )
                             ->Result<ColumnProof<MerkleTreeType::Proof>> {
                    const auto inclusion_proof = generate_proof(tree_c, std::size_t(self.index()));
                    ColumnProof::<MerkleTreeType::Proof>::from_column(self, inclusion_proof)
                }
            }    // namespace vanilla
        }        // namespace stacked
    }            // namespace filecoin
}    // namespace nil

#endif

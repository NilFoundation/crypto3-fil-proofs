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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_CIRCUIT_COLUMN_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_CIRCUIT_COLUMN_HPP

#include <nil/crypto3/zk/snark/blueprint.hpp>
#include <nil/crypto3/zk/snark/component.hpp>

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/params.hpp>

namespace nil {
    namespace filecoin {
        namespace porep {
            namespace stacked {
                namespace components {

                    using namespace crypto3::zk::snark;

                    template<typename FieldType>
                    struct Column : public components::component<FieldType> {

                        components::blueprint_variable_vector<FieldType> rows;

                        /// Create an empty `Column`, used in `blank_circuit`s.
                        template<typename MerkleTreeType>
                        Column(components::blueprint<FieldType> &bp,
                               const vanilla::PublicParams<MerkleTreeType> &params) :
                            components::component<FieldType>(bp){

                            for (const auto &layer : params.layer_challenges.layers()) {
                                components::blueprint_variable<FieldType> val;
                                val.allocate(bp);

                                bp.val(val) = layer;
                                rows.emplace_back(val);
                            }
                        }

                        /// Consume this column, and allocate its values in the circuit.
                        template<typename Hash>
                        Column(components::blueprint<FieldType> &bp, const vanilla::Column<Hash> &vanilla_column) :
                            components::component<FieldType>(bp) {

                            for (const auto &row : vanilla_column.rows) {
                                components::blueprint_variable<FieldType> val;
                                val.allocate(bp);

                                bp.val(val) = row;
                                rows.emplace_back(val);
                            }
                        }

                        template<template<typename> class ConstraintSystem>
                        components::blueprint_variable<FieldType> hash(const ConstraintSystem<FieldType> &cs) {
                            return hash_single_column(cs, rows);
                        }

                        components::blueprint_variable<FieldType> get_value(std::size_t layer) {
                            BOOST_ASSERT_MSG(layer > 0, "layers are 1 indexed");
                            BOOST_ASSERT_MSG(layer <= rows.len(),
                                             std::format("layer {} out of range: 1..={}", layer, rows.size()));
                            return rows[layer - 1];
                        }

                    };
                }    // namespace components
            }        // namespace stacked
        }            // namespace porep
    }                // namespace filecoin
}    // namespace nil

#endif

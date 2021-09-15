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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_COLUMN_COMPONENTS_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_COLUMN_COMPONENTS_HPP

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

                    template<typename TField>
                    class Column : public components::component<TField> {

                        components::blueprint_variable<TField> hash_result;
                        hash_single_column<TField> hash_single_column_component;

                    public:

                        components::blueprint_variable_vector<TField> rows;

                        /// Create an empty `Column`, used in `blank_circuit`s.
                        template<typename MerkleTreeType>
                        Column(components::blueprint<TField> &bp,
                               const vanilla::PublicParams<MerkleTreeType> &params) :
                            components::component<TField>(bp){

                            for (const auto &layer : params.layer_challenges.layers()) {
                                components::blueprint_variable<TField> val;
                                val.allocate(bp);

                                bp.val(val) = layer;
                                rows.emplace_back(val);
                            }

                            hash_result.allocate(bp);
                            hash_single_column_component = hash_single_column(bp, hash_result);
                        }

                        /// Consume this column, and allocate its values in the circuit.
                        template<typename Hash>
                        Column(components::blueprint<TField> &bp, const vanilla::Column<Hash> &vanilla_column) :
                            components::component<TField>(bp) {

                            for (const auto &row : vanilla_column.rows) {
                                components::blueprint_variable<TField> val;
                                val.allocate(bp);

                                bp.val(val) = row;
                                rows.emplace_back(val);
                            }
                        }

                        void generate_r1cs_constraints() {
                            hash_single_column_component.generate_r1cs_constraints();
                        }
                        
                        void generate_r1cs_witness(){
                            hash_single_column_component.generate_r1cs_witness(rows);
                        }

                        components::blueprint_variable<TField> get_hash() const {
                            return hash_result;
                        }

                        components::blueprint_variable<TField> get_value(std::size_t layer) const {
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

#endif    // FILECOIN_STORAGE_PROOFS_POREP_STACKED_COLUMN_COMPONENTS_HPP

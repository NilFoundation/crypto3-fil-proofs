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
                namespace circuit {
                    template<typename CurveType, template<typename> class AllocatedNumber>
                    struct AllocatedColumn : public crypto3::zk::snark::components::component<CurveType> {
                        typedef CurveType curve_type;

                        AllocatedColumn(crypto3::zk::snark::blueprint<CurveType> &bp) :
                            crypto3::zk::snark::components::component<CurveType>(bp) {
                        }

                        template<template<typename> class ConstraintSystem>
                        AllocatedNumber<curve_type> hash(const ConstraintSystem<curve_type> &cs) {
                            hash_single_column(cs, rows);
                        }

                        AllocatedNumber<curve_type> get_value(std::size_t layer) {
                            BOOST_ASSERT_MSG(layer > 0, "layers are 1 indexed");
                            BOOST_ASSERT_MSG(layer <= rows.len(),
                                             std::format("layer {} out of range: 1..={}", layer, rows.size()));
                            return rows[layer - 1];
                        }

                        std::vector<AllocatedNumber<curve_type>> rows;
                    };

                    template<typename CurveType>
                    struct Column : public crypto3::zk::snark::components::component<CurveType> {
                        typedef CurveType curve_type;

                        /// Create an empty `Column`, used in `blank_circuit`s.
                        template<typename MerkleTreeType>
                        Column(crypto3::zk::snark::blueprint<CurveType> &bp,
                               const vanilla::PublicParams<MerkleTreeType> &params) :
                            crypto3::zk::snark::components::component<CurveType>(bp),
                            rows(params.layer_challenges.layers()) {
                            for (const auto &row : rows) {
                                crypto3::zk::snark::blueprint_variable<CurveType> val;
                                val.allocate(bp);

                                bp.val(val) = row;
                            }
                        }

                        /// Consume this column, and allocate its values in the circuit.
                        template<typename Hash>
                        Column(crypto3::zk::snark::blueprint<CurveType> &bp, const vanilla::Column<Hash> &vanilla) :
                            crypto3::zk::snark::components::component<CurveType>(bp), rows(vanilla.rows) {
                            for (const auto &row : rows) {
                                crypto3::zk::snark::blueprint_variable<CurveType> val;
                                val.allocate(bp);

                                bp.val(val) = row;
                            }
                        }

                        std::vector<typename curve_type::scalar_field_type::value_type> rows;
                    };
                }    // namespace circuit
            }        // namespace stacked
        }            // namespace porep
    }                // namespace filecoin
}    // namespace nil

#endif

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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_CIRCUIT_COLUMN_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_CIRCUIT_COLUMN_HPP

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/params.hpp>

namespace nil {
    namespace filecoin {
        namespace stacked {
            namespace circuit {
                template<template<typename> class AllocatedNum, typename Bls12>
                struct AllocatedColumn {
                    template<template<typename> class ConstraintSystem>
                    AllocatedNum<Bls12> hash(const ConstraintSystem<Bls12> &cs) {
                        hash_single_column(cs, rows);
                    }

                    AllocatedNum<Bls12> get_value(std::size_t layer) {
                        assert(("layers are 1 indexed", layer > 0));
                        assert(layer <= self.rows.len(), "layer {} out of range: 1..={}", layer, rows.size());
                        return rows[layer - 1];
                    }

                    std::vector<AllocatedNum<Bls12>> rows;
                };

                struct Column {
                    /// Create an empty `Column`, used in `blank_circuit`s.
                    template<typename MerkleTreeType>
                    Column(const PublicParams<MerkleTreeType> &params) : rows(params.layer_challenges.layers()) {
                    }

                    template<typename Hash>
                    Column(const vanilla::Column<Hash> &vanilla) :
                        rows(vanilla.rows.into_iter().map(| r | Some(r.into())).collect()) {
                    }

                    /// Consume this column, and allocate its values in the circuit.
                    template<template<typename> class ConstraintSystem, typename Bls12>
                    AllocatedColumn alloc(ConstraintSystem<Bls12> &cs) {
                        let Self {rows} = self;

                        let rows = rows.into_iter()
                                       .enumerate()
                                       .map(| (i, val) |
                                            {num::AllocatedNum::alloc(
                                                cs.namespace(|| format !("column_num_row_{}", i)),
                                                || {val.ok_or_else(|| SynthesisError::AssignmentMissing)})})
                                       .collect::<Result<Vec<_>, _>>() ?
                            ;

                        return {rows};
                    }

                    std::vector<Fr> rows;
                };
            }    // namespace circuit
        }        // namespace stacked
    }            // namespace filecoin
}    // namespace nil

#endif
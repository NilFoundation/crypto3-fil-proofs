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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_GADGETS_POR_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_GADGETS_POR_HPP

#include <nil/filecoin/storage/proofs/core/proof/compound_proof.hpp>

#include <nil/filecoin/storage/proofs/core/gadgets/variables.hpp>

namespace nil {
    namespace filecoin {
        struct Fr;

        template<typename Hash, std::size_t BaseArity>
        struct PathElement {
            std::vector<Fr> hashes;
            std::size_t index;
        };

        template<typename Hash, std::size_t BaseArity>
        struct SubPath {
            template<template<typename> class ConstraintSystem, typename Bls12>
            std::pair<AllocatedNumber<Bls12>, std::vector<bool>> synthesize(ConstraintSystem<Bls12> &cs,
                                                                            AllocatedNumber<Bls12> &cur) {
                std::size_t arity = BaseArity;

                if (arity == 0) {
                    // Nothing to do here.
                    assert(path.empty());
                    return std::make_pair(cur, std::vector<bool>());
                }

                assert(("arity must be a power of two", 1 == arity.count_ones()));
                std::size_t index_bit_count = arity.trailing_zeros();

                let mut auth_path_bits = Vec::with_capacity(self.path.len());

                for ((i, path_element) : self.path.into_iter().enumerate()) {
                    let path_hashes = path_element.hashes;
                    let optional_index =
                        path_element.index;    // Optional because of Bellman blank-circuit construction mechanics.

                    let cs = &mut cs.namespace(|| format !("merkle tree hash {}", i));

                    let mut index_bits = Vec::with_capacity(index_bit_count);

                    for (int i = 0; i < index_bit_count; i++) {
                        let bit = AllocatedBit::alloc(cs.namespace(|| format !("index bit {}", i)),
                                                      {optional_index.map(| index | ((index >> i) & 1) == 1)});

                        index_bits.push(Boolean::from(bit));
                    }

                    auth_path_bits.extend_from_slice(&index_bits);

                    // Witness the authentication path elements adjacent at this depth.
                    let path_hash_nums =
                        path_hashes.iter()
                            .enumerate()
                            .map(| (i, elt) |
                                 {num::AllocatedNum::alloc(cs.namespace(|| format !("path element {}", i)),
                                                           || {elt.ok_or_else(|| SynthesisError::AssignmentMissing)})})
                            .collect::<Result<Vec<_>, _>>() ?
                        ;

                    let inserted = insert(cs, &cur, &index_bits, &path_hash_nums) ? ;

                    // Compute the new subtree value
                    cur = H::Function::hash_multi_leaf_circuit::<Arity, _>(
                        cs.namespace(|| "computation of commitment hash"), &inserted, i, ) ?
                        ;
                }

                return std::make_pair(cur, auth_path_bits);
            }

            std::vector<PathElement<Hash, BaseArity>> path;
        };

        template<typename Hash, std::size_t BaseArity, std::size_t SubTreeArity, std::size_t TopTreeArity>
        struct AuthPath {
            AuthPath(std::size_t leaves) {
                let has_sub = V::to_usize() > 0;
                let has_top = W::to_usize() > 0;
                let base_elements = base_path_length::<U, V, W>(leaves);

                let base = vec ![PathElement::<H, U>{
                    hashes:
                        vec ![None; U::to_usize() - 1], index : None, _a : Default::default(), _h : Default::default(),
                };
                    base_elements];

                let sub = if has_sub {
                    vec ![PathElement::<H, V>{
                        hashes:
                            vec ![None; V::to_usize() - 1],
                                index : None, _a : Default::default(), _h : Default::default(),
                    }]
                }
                else {Vec::new ()};

                let top = if has_top {
                    vec ![PathElement::<H, W>{
                        hashes:
                            vec ![None; W::to_usize() - 1],
                                index : None, _a : Default::default(), _h : Default::default(),
                    }]
                }
                else {Vec::new ()};

                AuthPath {
                base:
                    SubPath {path : base}, sub : SubPath {path : sub}, top : SubPath {path : top},
                }
            }

            AuthPath(const std::vector<std::pair<std::vector<Fr>, std::size_t>> &base_opts) {
                bool has_top = TopTreeArity > 0;
                bool has_sub = SubTreeArity > 0;
                std::size_t len = base_opts.size();
                std::size_t x;

                if (has_top) {
                    x = 2;
                } else if (has_sub) {
                    x = 1;
                } else {
                    x = 0;
                }

                let mut opts = base_opts.split_off(len - x);

                let base = base_opts.into_iter()
                               .map(| (hashes, index) | PathElement {
                                   hashes,
                                   index,
                                   _a : Default::default(),
                                   _h : Default::default(),
                               })
                               .collect();

                let top = if has_top {
                    let(hashes, index) = opts.pop().unwrap();
                    vec ![PathElement {
                        hashes,
                        index,
                        _a : Default::default(),
                        _h : Default::default(),
                    }]
                }
                else {Vec::new ()};

                let sub = if has_sub {
                    let(hashes, index) = opts.pop().unwrap();
                    vec ![PathElement {
                        hashes,
                        index,
                        _a : Default::default(),
                        _h : Default::default(),
                    }]
                }
                else {Vec::new ()};

                assert(opts.is_empty());

                return AuthPath {base : {path : base}, sub : SubPath {path : sub}, top : SubPath {path : top}};
            }

            SubPath<Hash, BaseArity> base;
            SubPath<Hash, SubTreeArity> sub;
            SubPath<Hash, TopTreeArity> top;
        };

        template<typename MerkleTreeType, typename Bls12>
        struct PoRCircuit {
            root<Bls12> value;
            AuthPath<typename MerkleTreeType::hash_type,
                     MerkleTreeType::Arity,
                     MerkleTreeType::SubTreeArity,
                     MerkleTreeType::TopTreeArity>
                auth_path;
            root<Bls12> root;
            bool priv;
        };
    }    // namespace filecoin
}    // namespace nil

#endif
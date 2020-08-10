//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020 Gokuyun Moscow Algorithm Lab
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
#include <nil/filecoin/storage/proofs/core/merkle/proof.hpp>
#include <nil/filecoin/storage/proofs/core/gadgets/variables.hpp>
#include <nil/filecoin/storage/proofs/core/path_element.hpp>

namespace nil {
    namespace filecoin {
        template<typename Hash, std::size_t BaseArity>
        struct SubPath {
            SubPath(std::size_t capacity) : path(capacity) {
            }

            template<template<typename> class ConstraintSystem, typename Bls12>
            std::pair<AllocatedNumber<Bls12>, std::vector<bool>> synthesize
                (ConstraintSystem<Bls12>
                &cs,
                                                                            AllocatedNumber<Bls12> &cur) {
                std::size_t arity = BaseArity;

                if (arity == 0) {
                    // Nothing to do here.
                    assert(path.empty());
                    return std::make_pair(cur, std::vector<bool>());
                }

                assert(("arity must be a power of two", 1 == arity.count_ones()));
                std::size_t index_bit_count = arity.trailing_zeros();

                std::vector<bool> auth_path_bits(path.size());

                for (int i = 0; i < path.size(); i++) {
                    std::vector<Fr> path_hashes = path[i].hashes;
                    std::size_t optional_index =
                        path[i].index;    // Optional because of Bellman blank-circuit construction mechanics.

                    let cs = &mut cs.namespace(|| format !("merkle tree hash {}", i));

                    std::vector<bool> index_bits(index_bit_count);

                    for (int i = 0; i < index_bit_count; i++) {
                        let bit = AllocatedBit::alloc(cs.namespace(|| format !("index bit {}", i)),
                                                      {optional_index.map(| index | ((index >> i) & 1) == 1)});

                        index_bits.push_back(bit);
                    }

                    auth_path_bits.extend_from_slice(&index_bits);

                    // Witness the authentication path elements adjacent at this depth.
                    let path_hash_nums = path_hashes.iter()
                                             .enumerate()
                                             .map(| (i, elt) |
                                                  {num::AllocatedNumber::alloc(
                                                      cs.namespace(|| format !("path element {}", i)),
                                                      || {elt.ok_or_else(|| SynthesisError::AssignmentMissing)})})
                                             .collect::<Result<Vec<_>, _>>();

                    let inserted = insert(cs, &cur, &index_bits, &path_hash_nums);

                    // Compute the new subtree value
                    cur = H::Function::hash_multi_leaf_circuit::<Arity, _>(
                        cs.namespace(|| "computation of commitment hash"), &inserted, i);
                }

                return std::make_pair(cur, auth_path_bits);
            }

            std::vector<PathElement<Hash, BaseArity>> path;
        };

        template<typename Hash, std::size_t BaseArity, std::size_t SubTreeArity, std::size_t TopTreeArity>
        struct AuthPath {
            AuthPath(std::size_t leaves) :
                base(SubPath<Hash, BaseArity>(base_path_length<BaseArity, SubTreeArity, TopTreeArity>(leaves))) {
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
                    let(hashes, index) = opts.pop();
                    vec ![PathElement {
                        hashes,
                        index,
                        _a : Default::default(),
                        _h : Default::default(),
                    }]
                }
                else {Vec::new ()};

                let sub = if has_sub {
                    let(hashes, index) = opts.pop();
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

        template<typename MerkleTreeType, template<typename> class Circuit, typename Bls12>
        struct PoRCircuit : public cacheable_parameters<Circuit<Bls12>, ParameterSetMetadata>, public Circuit<Bls12> {
            /// # Public Inputs
            ///
            /// This circuit expects the following public inputs.
            ///
            /// * [0] - packed version of the `is_right` components of the auth_path.
            /// * [1] - the merkle root of the tree.
            ///
            /// This circuit derives the following private inputs from its fields:
            /// * value_num - packed version of `value` as bits. (might be more than one Fr)
            ///
            /// Note: All public inputs must be provided as `E::Fr`.
            template<template<typename> class ConstraintSystem>
            void synthesize(ConstraintSystem<Bls12> &cs) {
                root<Bls12> value = value;
                AuthPath<typename MerkleTreeType::hash_type, MerkleTreeType::Arity, MerkleTreeType::SubTreeArity,
                         MerkleTreeType::TopTreeArity>
                    auth_path = auth_path;
                root<Bls12> root = root;

                std::size_t base_arity = MerkleTreeType::Arity;
                std::size_t sub_arity = MerkleTreeType::SubTreeArity;
                std::size_t top_arity = MerkleTreeType::TopTreeArity;

                // All arities must be powers of two or circuits cannot be generated.
                assert(("base arity must be power of two", 1 == base_arity.count_ones()));
                if (sub_arity > 0) {
                    assert(("subtree arity must be power of two", 1 == sub_arity.count_ones()));
                }
                if (top_arity > 0) {
                    assert(("top tree arity must be power of two", 1 == top_arity.count_ones()));
                }

                {
                    let value_num = value.allocated(cs.namespace(|| "value")) ? ;
                    let cur = value_num;

                    // Ascend the merkle tree authentication path

                    // base tree
                    let(cur, base_auth_path_bits) = auth_path.base.synthesize(cs.namespace(|| "base"), cur) ? ;

                    // sub
                    let(cur, sub_auth_path_bits) = auth_path.sub.synthesize(cs.namespace(|| "sub"), cur) ? ;

                    // top
                    let(computed_root, top_auth_path_bits) = auth_path.top.synthesize(cs.namespace(|| "top"), cur) ? ;

                    let mut auth_path_bits = Vec::new ();
                    auth_path_bits.extend(base_auth_path_bits);
                    auth_path_bits.extend(sub_auth_path_bits);
                    auth_path_bits.extend(top_auth_path_bits);

                    multipack::pack_into_inputs(cs.namespace(|| "path"), &auth_path_bits) ? ;
                    {
                        // Validate that the root of the merkle tree that we calculated is the same as the input.
                        let rt = root.allocated(cs.namespace(|| "root_value")) ? ;
                        constraint::equal(cs, || "enforce root is correct", &computed_root, &rt);

                        if (!priv) {
                            // Expose the root
                            rt.inputize(cs.namespace(|| "root")) ? ;
                        }
                    }
                }
            }

            template<template<typename> class ConstraintSystem>
            void synthesize(ConstraintSystem<Bls12> &cs, const root<Bls12> &value,
                            const AuthPath<typename MerkleTreeType::hash_type, MerkleTreeType::Arity,
                                           MerkleTreeType::SubTreeArity, MerkleTreeType::TopTreeArity> &auth_path,
                            root<Bls12> root, bool priv) {
                this->value = value;
                this->auth_path = auth_path;
                this->root = root;
                this->priv = priv;

                synthesize(cs);
            }

            root<Bls12> value;
            AuthPath<typename MerkleTreeType::hash_type, MerkleTreeType::Arity, MerkleTreeType::SubTreeArity,
                     MerkleTreeType::TopTreeArity>
                auth_path;
            root<Bls12> root;
            bool priv;
        };
    }    // namespace filecoin
}    // namespace nil

#endif
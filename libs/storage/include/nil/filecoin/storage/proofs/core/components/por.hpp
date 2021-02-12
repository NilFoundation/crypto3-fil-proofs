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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_COMPONENTS_POR_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_COMPONENTS_POR_HPP

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/zk/snark/components/basic_components.hpp>

#include <nil/filecoin/storage/proofs/core/path_element.hpp>
#include <nil/filecoin/storage/proofs/core/parameter_cache.hpp>
#include <nil/filecoin/storage/proofs/core/por.hpp>

#include <nil/filecoin/storage/proofs/core/proof/compound_proof.hpp>

#include <nil/filecoin/storage/proofs/core/merkle/proof.hpp>

#include <nil/filecoin/storage/proofs/core/components/variables.hpp>

namespace nil {
    namespace filecoin {
        template<typename Hash, std::size_t BaseArity, typename FieldType>
        struct SubPath : public crypto3::zk::snark::components::component<FieldType> {
            std::vector<PathElement<Hash, FieldType, BaseArity>> path;

            SubPath(crypto3::zk::snark::blueprint<FieldType> &bp, crypto3::zk::snark::blueprint_variable<FieldType> cur,
                    std::size_t capacity) :
                path(capacity),
                crypto3::zk::snark::components::component<FieldType>(bp) {
                std::size_t arity = BaseArity;

                if (arity == 0) {
                    // Nothing to do here.
                    assert(path.empty());
                    return std::make_pair(cur, std::vector<bool>());
                }

                assert(("arity must be a power of two", std::ceil(std::log2(arity)) == std::floor(std::log2(arity))));
                std::size_t index_bit_count = arity.trailing_zeros();

                std::vector<bool> auth_path_bits(path.size());
            }

            void generate_r1cs_constraints() {
            }
            void generate_r1cs_witness() {
            }

            template<template<typename> class ConstraintSystem>
            std::pair<AllocatedNumber<algebra::curves::bls12<381>>, std::vector<bool>>
                synthesize(ConstraintSystem<algebra::curves::bls12<381>> &cs,
                           crypto3::zk::snark::blueprint_variable<algebra::curves::bls12<381>> &cur) {

                std::size_t arity = BaseArity;

                if (arity == 0) {
                    // Nothing to do here.
                    assert(path.empty());
                    return std::make_pair(cur, std::vector<bool>());
                }

                assert(("arity must be a power of two", std::ceil(std::log2(arity)) == std::floor(std::log2(arity))));
                std::size_t index_bit_count = arity.trailing_zeros();

                std::vector<bool> auth_path_bits(path.size());

                for (int i = 0; i < path.size(); i++) {
                    std::vector<Fr> path_hashes = path[i].hashes;
                    std::size_t optional_index =
                        path[i].index;    // Optional because of Bellman blank-circuit construction mechanics.

                    auto cs = cs.namespace(|| std::format("merkle tree hash {}", i));

                    std::vector<bool> index_bits(index_bit_count);

                    for (int i = 0; i < index_bit_count; i++) {
                        const auto bit = AllocatedBit::alloc(cs.namespace(|| std::format("index bit {}", i)),
                                                      {optional_index.map(| index | ((index >> i) & 1) == 1)});

                        index_bits.push_back(bit);
                    }

                    auth_path_bits.extend_from_slice(&index_bits);

                    // Witness the authentication path elements adjacent at this depth.
                    const auto path_hash_nums = path_hashes.iter()
                                             .enumerate()
                                             .map(| (i, elt) |
                                                  {num::AllocatedNumber::alloc(
                                                      cs.namespace(|| std::format("path element {}", i)),
                                                      || {elt.ok_or_else(|| SynthesisError::AssignmentMissing)})})
                                             .collect::<Result<Vec<_>, _>>();

                    const auto inserted = insert(cs, &cur, &index_bits, &path_hash_nums);

                    // Compute the new subtree value
                    cur = H::Function::hash_multi_leaf_circuit::<Arity, _>(
                        cs.namespace(|| "computation of commitment hash"), &inserted, i);
                }

                return std::make_pair(cur, auth_path_bits);
            }
        };

        template<typename Hash, std::size_t BaseArity, std::size_t SubTreeArity, std::size_t TopTreeArity,
                 typename FieldType>
        struct AuthPath : public crypto3::zk::snark::components::component<FieldType> {
            SubPath(crypto3::zk::snark::blueprint<FieldType> &bp, std::size_t capacity) :
                path(capacity), crypto3::zk::snark::components::component<FieldType>(bp) {
            }

            void generate_r1cs_constraints() {
            }
            void generate_r1cs_witness() {
            }

            AuthPath(crypto3::zk::snark::blueprint<FieldType> &bp, std::size_t leaves) :
                base(SubPath<Hash, BaseArity>(bp, base_path_length<BaseArity, SubTreeArity, TopTreeArity>(leaves))) {
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

                auto opts = base_opts.split_off(len - x);

                const auto base = base_opts.into_iter()
                               .map(| (hashes, index) | PathElement {
                                   hashes,
                                   index,
                                   _a : Default::default(),
                                   _h : Default::default(),
                               })
                               .collect();

                const auto top = if has_top {
                    const auto(hashes, index) = opts.pop();
                    vec ![PathElement {
                        hashes,
                        index,
                        _a : Default::default(),
                        _h : Default::default(),
                    }]
                }
                else {Vec::new ()};

                const auto sub = if has_sub {
                    const auto(hashes, index) = opts.pop();
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

        template<typename MerkleTreeType, template<typename> class Circuit>
        struct PoRCircuit : public cacheable_parameters<Circuit<algebra::curves::bls12<381>>, parameter_set_metadata>,
                            public crypto3::zk::snark::components::component<FieldType> {

            constexpr static const std::size_t base_arity = MerkleTreeType::arity;
            constexpr static const std::size_t sub_arity = MerkleTreeType::arity;
            constexpr static const std::size_t top_arity = MerkleTreeType::arity;

            using auth_path_type = AuthPath<typename MerkleTreeType::hash_type, 
                base_arity, sub_tree_arity, top_tree_arity, field_type>;

            void generate_r1cs_constraints() {
                // base tree
                auth_path.base.generate_r1cs_constraints();

                // sub
                auth_path.sub.generate_r1cs_constraints();

                // top
                auth_path.top.generate_r1cs_constraints();
            }
            void generate_r1cs_witness() {
                // base tree
                auth_path.base.generate_r1cs_witness();

                // sub
                auth_path.sub.generate_r1cs_witness();

                // top
                auth_path.top.generate_r1cs_witness();
            }

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
            void synthesize(ConstraintSystem<algebra::curves::bls12<381>> &cs) {
                root<algebra::curves::bls12<381>> value = value;
                auth_path_type auth_path = auth_path;
                root<algebra::curves::bls12<381>> root = root;

                // All arities must be powers of two or circuits cannot be generated.
                assert(("base arity must be power of two", 1 == base_arity.count_ones()));
                if (sub_arity > 0) {
                    assert(("subtree arity must be power of two", 1 == sub_arity.count_ones()));
                }
                if (top_arity > 0) {
                    assert(("top tree arity must be power of two", 1 == top_arity.count_ones()));
                }

                
                const auto value_num = value.allocated(cs.namespace(|| "value")) ? ;
                const auto cur = value_num;

                // Ascend the merkle tree authentication path

                // base tree
                const auto(cur, base_auth_path_bits) = auth_path.base.synthesize(cs.namespace(|| "base"), cur) ? ;

                // sub
                const auto(cur, sub_auth_path_bits) = auth_path.sub.synthesize(cs.namespace(|| "sub"), cur) ? ;

                // top
                const auto(computed_root, top_auth_path_bits) = auth_path.top.synthesize(cs.namespace(|| "top"), cur) ? ;

                auto auth_path_bits = Vec::new ();
                auth_path_bits.extend(base_auth_path_bits);
                auth_path_bits.extend(sub_auth_path_bits);
                auth_path_bits.extend(top_auth_path_bits);

                multipack::pack_into_inputs(cs.namespace(|| "path"), &auth_path_bits) ? ;
                // Validate that the root of the merkle tree that we calculated is the same as the input.
                const auto rt = root.allocated(cs.namespace(|| "root_value")) ? ;
                constraint::equal(cs, || "enforce root is correct", &computed_root, &rt);

                if (!priv) {
                    // Expose the root
                    rt.inputize(cs.namespace(|| "root")) ? ;
                }
            }

            template<template<typename> class ConstraintSystem>
            void synthesize(ConstraintSystem<algebra::curves::bls12<381>> &cs,
                            const root<algebra::curves::bls12<381>> &value,
                            auth_path_type &auth_path,
                            root<algebra::curves::bls12<381>> root, bool priv) {
                this->value = value;
                this->auth_path = auth_path;
                this->root = root;
                this->priv = priv;

                synthesize(cs);
            }

            root<algebra::curves::bls12<381>> value;
            auth_path_type auth_path;
            root<algebra::curves::bls12<381>> root;
            bool priv;
        };

        template<typename MerkleTreeType, template<typename> class Circuit>
        struct PoRCompound : public PoRCircuit<MerkleTreeType, Circuit<algebra::curves::bls12<381>>>,
                             public CompoundProof<PoR<MerkleTreeType>, PoRCircuit<MerkleTreeType>> { };
    }    // namespace filecoin
}    // namespace nil

#endif // FILECOIN_STORAGE_PROOFS_CORE_COMPONENTS_POR_HPP

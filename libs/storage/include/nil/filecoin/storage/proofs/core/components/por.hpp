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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_COMPONENTS_POR_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_COMPONENTS_POR_HPP

#include <tuple>
#include <vector>
#include <unordered_map>

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/components/blueprint_variable.hpp>
#include <nil/crypto3/zk/components/component.hpp>

#include <nil/filecoin/storage/proofs/core/path_element.hpp>
#include <nil/filecoin/storage/proofs/core/parameter_cache.hpp>
#include <nil/filecoin/storage/proofs/core/por.hpp>

#include <nil/filecoin/storage/proofs/core/proof/compound_proof.hpp>

#include <nil/filecoin/storage/proofs/core/merkle/proof.hpp>

#include <nil/filecoin/storage/proofs/core/components/variables.hpp>

namespace nil {
    namespace filecoin {
        namespace components {

            template<typename TField>
            struct PathElement {
                std::vector<typename TField::value_type> hashes;
                std::size_t index;
            }

            template<typename TField, typename THash, std::size_t BaseArity>
            class SubPath : public components::component<TField> {
                
                BOOST_STATIC_ASSERT_MSG(std::ceil(std::log2(BaseArity)) == std::floor(std::log2(BaseArity)),
                                        "arity must be a power of two");

                template<typename Integer>
                Integer trailing_zeros(Integer n) {
                    Integer bits = 0, x = n;

                    if (x) {
                        while ((x & 1) == 0) {
                            ++bits;
                            x >>= 1;
                        }
                    }
                    return bits;
                }

                std::vector<components::blueprint_variable_vector<TField>> path_hash_vars;
                std::vector<components::blueprint_variable_vector<TField>> index_bits;
                components::blueprint_variable_vector<TField> inserted;
                std::vector<components::insert> insert_components;
                std::vector<H::Function::hash_multi_leaf_circuit> hash_components;
                std::vector<std::size_t> capacities;

            public:

                components::blueprint_variable<TField> current;

                SubPath(components::blueprint<TField> &bp, components::blueprint_variable<TField> current,
                        std::vector<std::size_t> capacities) :
                    current(current), capacities(capacities),
                    components::component<FieldType>(bp) {

                    inserted.allocate(bp, capacities.size());
                    for (std::size_t i = 0; i < capacities.size(); i++) {

                        index_bits[i].allocate(bp, trailing_zeros(BaseArity));
                        path_hash_vars[i].allocate(bp, capacities[i]);

                        insert_components.emplace_back(bp, current, index_bits[i], path_hash_vars[i], inserted[i]);

                        hash_components.emplace_back(bp, inserted[i], current);
                    }
                }

                SubPath(components::blueprint<TField> &bp, components::blueprint_variable<TField> current) :
                    current(current), 
                    components::component<FieldType>(bp) {}

                void generate_r1cs_constraints() {
                    for (std::size_t i = 0; i < path.size(); i++) {

                        insert_components[i].generate_r1cs_witness();

                        hash_components[i].generate_r1cs_witness(i);
                    }
                }

                void generate_r1cs_witness(std::vector<PathElement<TField, Hash, BaseArity>> path) {

                    assert(capacities.size() == path.size());

                    std::size_t arity = BaseArity;
                    std::size_t index_bit_count = trailing_zeros(arity);
                    for (std::size_t i = 0; i < path.size(); i++) {

                        for (std::size_t j = 0; j<index_bit_count; j++) {
                            this->bp.val(index_bits) = (((path[i].index >> j) & 1) == 1);
                        }

                        assert(capacities[i] == path[i].hashes.size());
                        for (std::size_t j = 0; j < path[i].hashes.size(); j++) {
                            this->bp.val(path_hash_vars[i][j]) = path[i].hashes[j];
                        }

                        insert_components[i].generate_r1cs_witness();

                        hash_components[i].generate_r1cs_witness(i);
                    }
                }
            };

            template<typename TField, typename THash, 
                     std::size_t BaseArity, std::size_t SubTreeArity, std::size_t TopTreeArity>
            struct AuthPath : public components::component<TField> {
                AuthPath(components::blueprint<TField> &bp,
                         const std::unordered_map<std::vector<typename TField::value_type>, std::size_t> &base_opts) :
                         components::component<TField>(bp) {

                    std::size_t len = base_opts.size();
                    std::size_t x;

                    if (TopTreeArity > 0) {
                        x = 2;
                    } else if (SubTreeArity > 0) {
                        x = 1;
                    }  else {
                        x = 0;
                    }

                    std::unordered_map<std::vector<typename TField::value_type>, std::size_t> opts(
                        base_opts.begin() + len - x, base_opts.end());

                    std::vector<PathElement<TField>> base, top, sub;
                    for (const auto &pair : base_opts) {
                        base.emplace_back(pair.first, pair.second);
                    }

                    if (TopTreeArity > 0) {
                        top = *(opts.end() - 1);
                        opts.erase(opts.end() - 1);
                    }

                    if (SubTreeArity > 0) {
                        sub = *(opts.end() - 1);
                        opts.erase(opts.end() - 1);
                    }

                    assert(opts.empty());

                    base = {.path = base};
                    sub = {.path = sub};
                    top = {.path = top};
                }

                void generate_r1cs_constraints() {
                    base.generate_r1cs_constraints();
                    sub.generate_r1cs_constraints();
                    top.generate_r1cs_constraints();
                }

                void generate_r1cs_witness() {
                    base.generate_r1cs_witness();
                    sub.generate_r1cs_witness();
                    top.generate_r1cs_witness();
                }

                SubPath<TField, THash, BaseArity> base;
                SubPath<TField, THash, SubTreeArity> sub;
                SubPath<TField, THash, TopTreeArity> top;
            };

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
            template<typename TField, typename TMerkleTree>
            class PoRCircuit : public components::component<TField> {

                components::blueprint_variable<TField> value_var;
            public:

                constexpr static const std::size_t base_arity = TMerkleTree::arity;
                constexpr static const std::size_t sub_arity = TMerkleTree::arity;
                constexpr static const std::size_t top_arity = TMerkleTree::arity;

                typedef AuthPath<TField, typename TMerkleTree::hash_type, 
                                 base_arity, sub_arity, top_arity> auth_path_type;

                // All arities must be powers of two or circuits cannot be generated.
                BOOST_STATIC_ASSERT_MSG(base_arity > 0 ? 
                                        std::ceil(std::log2(base_arity)) == std::floor(std::log2(base_arity)) :
                                        true, "base arity must be power of two");
                BOOST_STATIC_ASSERT_MSG(sub_arity > 0 ?
                                        std::ceil(std::log2(sub_arity)) == std::floor(std::log2(sub_arity)) :
                                        true, "subtree arity must be power of two");
                BOOST_STATIC_ASSERT_MSG(top_arity > 0 ?
                                        std::ceil(std::log2(top_arity)) == std::floor(std::log2(top_arity)) :
                                        true, "subtree arity must be power of two");

                auth_path_type auth_path;
                bool priv;

                PoRCircuit(crypto3::zk::components::blueprint<TField> &bp,
                           root<TField> root) :
                           components::component<TField>(bp) {

                    value_var.allocate(bp);
                    auth_path = auth_path_type(bp, value_var);

                }

                void generate_r1cs_constraints() {
                    auth_path.generate_r1cs_constraints();
                }

                void generate_r1cs_witness(root<TField> value, 
                        std::vector<typename TField::value_type> auth_path, root<TField> r) {

                    std::size_t len = auth_path.size();
                    std::size_t x;

                    if (TopTreeArity > 0) {
                        x = 2;
                    } else if (SubTreeArity > 0) {
                        x = 1;
                    }  else {
                        x = 0;
                    }

                    std::vector<PathElement<TField>> base, top, sub;

                    std::copy(auth_path.begin(), auth_path.begin() + len - x, base.begin());

                    if (TopTreeArity > 0) {
                        top = *(auth_path.end() - 1);
                        auth_path.erase(auth_path.end() - 1);
                    }

                    if (SubTreeArity > 0) {
                        sub = *(auth_path.end() - 1);
                        auth_path.erase(auth_path.end() - 1);
                    }

                    assert(auth_path.empty());



                    bp.val(value_var) = value;

                    auth_path.generate_r1cs_witness();
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
                void synthesize(ConstraintSystem<crypto3::algebra::curves::bls12<381>> &cs) {
                    const auto cur = value_num;

                    // Ascend the merkle tree authentication path

                    // base tree
                    const auto(cur, base_auth_path_bits) = auth_path.base.synthesize(cs.namespace(|| "base"), cur);

                    // sub
                    const auto(cur, sub_auth_path_bits) = auth_path.sub.synthesize(cs.namespace(|| "sub"), cur);

                    // top
                    const auto(computed_root, top_auth_path_bits) = auth_path.top.synthesize(cs.namespace(|| "top"), cur);

                    std::vector<auto> auth_path_bits;
                    auth_path_bits.extend(base_auth_path_bits);
                    auth_path_bits.extend(sub_auth_path_bits);
                    auth_path_bits.extend(top_auth_path_bits);

                    multipack::pack_into_inputs(cs.namespace(|| "path"), &auth_path_bits);
                    // Validate that the root of the merkle tree that we calculated is the same as the input.
                    const auto rt = root.allocated(cs.namespace(|| "root_value"));
                    constraint::equal(cs, || "enforce root is correct", &computed_root, &rt);

                    if (!priv) {
                        // Expose the root
                        rt.inputize(cs.namespace(|| "root"));
                    }
                }
            };

            template<typename TMerkleTree, typename Circuit>
            struct PoRCompound : public PoRCircuit<TMerkleTree, Circuit>,
                                 public CompoundProof<PoR<TMerkleTree>, Circuit>,
                                 public CacheableParameters<ParameterSetMetadata, TMerkleTree, Circuit> {
                typedef Circuit circuit_type;
                typedef typename circuit_type::curve_type curve_type;
            };

        }    // namespace components
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_STORAGE_PROOFS_CORE_COMPONENTS_POR_HPP

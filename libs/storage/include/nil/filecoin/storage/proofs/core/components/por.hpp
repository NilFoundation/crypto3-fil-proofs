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
        template<typename Hash, std::size_t BaseArity, typename FieldType>
        class SubPath : public crypto3::zk::components::component<FieldType> {
            template<typename Integer>
            Integer trailing_zeroes(Integer n) {
                Integer bits = 0, x = n;

                if (x) {
                    while ((x & 1) == 0) {
                        ++bits;
                        x >>= 1;
                    }
                }
                return bits;
            }

        public:
            BOOST_STATIC_ASSERT_MSG(std::ceil(std::log2(BaseArity)) == std::floor(std::log2(BaseArity)),
                                    "arity must be a power of two");

            crypto3::zk::components::blueprint_variable<FieldType> current;
            crypto3::zk::components::blueprint_variable_vector<FieldType> index_bits;
            std::vector<crypto3::zk::components::blueprint_variable_vector<FieldType>> path_hash_nums;

            std::vector<PathElement<Hash, BaseArity, FieldType>> path;

            SubPath(crypto3::zk::snark::blueprint<FieldType> &bp, crypto3::zk::blueprint_variable<FieldType> cur,
                    std::size_t capacity) :
                current(cur),
                path(capacity), crypto3::zk::components::component<FieldType>(bp) {

                for (int i = 0; i < path.size(); i++) {
                    index_bits.allocate(bp, trailing_zeroes(BaseArity));
                    path_hash_nums[i].allocate(bp, path[i].hashes.size());
                }
            }

            void generate_r1cs_constraints() {
            }
            void generate_r1cs_witness() {
                for (int i = 0; i < index_bits.size(); i++) {
                    this->bp.val(index_bits[i]) = (((path[i].index >> i) & 1) == 1);

                    for (int j = 0; j < path[i].hashes.size(); j++) {
                        this->bp.val(path_hash_nums[i][j]) = path[i].hashes[j];
                    }
                }
            }
        };

        template<typename Hash, std::size_t BaseArity, std::size_t SubTreeArity, std::size_t TopTreeArity,
                 typename FieldType>
        struct AuthPath : public crypto3::zk::components::component<FieldType> {
            AuthPath(crypto3::zk::components::blueprint<FieldType> &bp,
                     const std::unordered_map<std::vector<typename FieldType::value_type>, std::size_t> &base_opts) :
                crypto3::zk::components::component<FieldType>(bp) {
                std::size_t len = base_opts.size(), x = 0;

                if (TopTreeArity > 0) {
                    x = 2;
                } else if (SubTreeArity > 0) {
                    x = 1;
                }

                std::unordered_map<std::vector<typename FieldType::value_type>, std::size_t> opts(
                    base_opts.begin() + len - x, base_opts.end());

                std::vector<PathElement<Hash, BaseArity, FieldType>> base, top, sub;
                for (const auto &pair : base_opts) {
                    base.emplace_back(pair.first, pair.second);
                }

                if (TopTreeArity > 0) {
                    top = {*(opts.end() - 1)};
                    opts.erase(opts.end() - 1);
                }

                if (SubTreeArity > 0) {
                    sub = {*(opts.end() - 1)};
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

            SubPath<Hash, BaseArity, FieldType> base;
            SubPath<Hash, SubTreeArity, FieldType> sub;
            SubPath<Hash, TopTreeArity, FieldType> top;
        };

        template<typename MerkleTreeType, typename FieldType>
        struct PoRCircuit : public crypto3::zk::components::component<FieldType> {
            typedef FieldType field_type;
            typedef MerkleTreeType tree_type;
            typedef typename MerkleTreeType::hash_type hash_type;

            constexpr static const std::size_t base_arity = MerkleTreeType::arity;
            constexpr static const std::size_t sub_arity = MerkleTreeType::arity;
            constexpr static const std::size_t top_arity = MerkleTreeType::arity;

            typedef AuthPath<hash_type, base_arity, sub_arity, top_arity, FieldType> auth_path_type;

            // All arities must be powers of two or circuits cannot be generated.
            BOOST_STATIC_ASSERT_MSG(std::ceil(std::log2(base_arity)) == std::floor(std::log2(base_arity)),
                                    "base arity must be power of two");
            BOOST_STATIC_ASSERT_MSG(sub_arity > 0 ?
                                        std::ceil(std::log2(sub_arity)) == std::floor(std::log2(sub_arity)) :
                                        true,
                                    "subtree arity must be power of two");
            BOOST_STATIC_ASSERT_MSG(top_arity > 0 ?
                                        std::ceil(std::log2(top_arity)) == std::floor(std::log2(top_arity)) :
                                        true,
                                    "subtree arity must be power of two");

            root<FieldType> r;

            auth_path_type auth_path;
            bool priv;

            crypto3::zk::components::blueprint_variable<FieldType> value;

            PoRCircuit(crypto3::zk::snark::blueprint<FieldType> &bp,
                       const crypto3::zk::snark::blueprint_variable<FieldType> &value, auth_path_type &auth_path,
                       root<FieldType> root, bool priv) :
                value(value),
                auth_path(auth_path), r(root), priv(priv), crypto3::zk::components::component<FieldType>(bp) {
            }

            void generate_r1cs_constraints() {
                auth_path.generate_r1cs_constraints();
            }

            void generate_r1cs_witness() {
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
                const auto value_num = value.allocated(cs.namespace(|| "value"));
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

        template<typename MerkleTreeType, typename Circuit>
        struct PoRCompound : public PoRCircuit<MerkleTreeType, Circuit>,
                             public CompoundProof<PoR<MerkleTreeType>, Circuit>,
                             public CacheableParameters<ParameterSetMetadata, MerkleTreeType, Circuit> {
            typedef Circuit circuit_type;
            typedef typename circuit_type::curve_type curve_type;
        };
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_STORAGE_PROOFS_CORE_COMPONENTS_POR_HPP

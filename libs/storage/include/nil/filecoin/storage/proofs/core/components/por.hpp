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

            template<typename TField>
            struct AuthPathData {
                std::vector<PathElement<TField>> base;
                std::vector<PathElement<TField>> sub;
                std::vector<PathElement<TField>> top;
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
                        components::blueprint_variable<TField> &result, 
                        components::blueprint_variable_vector<TField> &auth_path_bits,
                        std::vector<std::size_t> capacities) :
                    current(current), result(result) capacities(capacities),
                    components::component<FieldType>(bp) {

                    inserted.allocate(bp, capacities.size());
                    for (std::size_t i = 0; i < capacities.size(); i++) {

                        index_bits[i].allocate(bp, trailing_zeros(BaseArity));
                        path_hash_vars[i].allocate(bp, capacities[i]);

                        insert_components.emplace_back(bp, current, index_bits[i], path_hash_vars[i], inserted[i]);

                        hash_components.emplace_back(bp, inserted[i], current);
                    }
                }

                void generate_r1cs_constraints() {
                    for (std::size_t i = 0; i < path.size(); i++) {

                        insert_components[i].generate_r1cs_witness();

                        hash_components[i].generate_r1cs_witness(i);
                    }
                }

                void generate_r1cs_witness(std::vector<PathElement<TField>> path) {

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
            template<typename TField, typename TMerkleTree, bool PrivateRoot = false>
            class PoRCircuit : public components::component<TField> {

                components::blueprint_variable<TField> value_var_base;
                components::blueprint_variable<TField> value_var_sub;
                components::blueprint_variable<TField> value_var_top;

                components::blueprint_variable<TField> root_var;

                // All arities must be powers of two or circuits cannot be generated.
                BOOST_STATIC_ASSERT_MSG(TMerkleTree::arity > 0 ? 
                                        std::ceil(std::log2(TMerkleTree::arity)) == 
                                        std::floor(std::log2(TMerkleTree::arity)) :
                                        true, "base arity must be power of two");
                BOOST_STATIC_ASSERT_MSG(TMerkleTree::arity > 0 ?
                                        std::ceil(std::log2(TMerkleTree::arity)) == 
                                        std::floor(std::log2(TMerkleTree::arity)) :
                                        true, "subtree arity must be power of two");
                BOOST_STATIC_ASSERT_MSG(TMerkleTree::arity > 0 ?
                                        std::ceil(std::log2(TMerkleTree::arity)) == 
                                        std::floor(std::log2(TMerkleTree::arity)) :
                                        true, "subtree arity must be power of two");
            public:

                SubPath<TField, TMerkleTree::hash, TMerkleTree::arity> base;
                SubPath<TField, TMerkleTree::hash, TMerkleTree::arity> sub;
                SubPath<TField, TMerkleTree::hash, TMerkleTree::arity> top;

                components::multipack::pack_into_inputs pack_component;

                PoRCircuit(crypto3::zk::components::blueprint<TField> &bp,
                           root<TField> root, 
                           std::vector<std::size_t> base_capacities,
                           std::vector<std::size_t> sub_capacities,
                           std::vector<std::size_t> top_capacities) :
                           components::component<TField>(bp) {

                    value_var_base.allocate(bp);
                    value_var_sub.allocate(bp);
                    value_var_top.allocate(bp);

                    root_var.allocate(bp);

                    computed_root.allocate(bp);
                    components::blueprint_variable_vector<TField> base_auth_path_bits;
                    components::blueprint_variable_vector<TField> sub_auth_path_bits;
                    components::blueprint_variable_vector<TField> top_auth_path_bits;

                    base(bp, value_var_base, value_var_sub, base_auth_path_bits, base_capacities);
                    sub(bp, value_var_sub, value_var_top, sub_auth_path_bits, sub_capacities);
                    top(bp, value_var_top, computed_root, top_auth_path_bits, top_capacities);

                    components::blueprint_variable_vector<TField> pre_pack_vector(base_auth_path_bits);
                    pre_pack_vector.insert(pre_pack_vector.end(), sub_auth_path_bits.begin(), sub_auth_path_bits.end());
                    pre_pack_vector.insert(pre_pack_vector.end(), top_auth_path_bits.begin(), top_auth_path_bits.end());
                    pack_component(pre_pack_vector);
                }

                void generate_r1cs_constraints() {

                    base.generate_r1cs_constraints();
                    sub.generate_r1cs_constraints();
                    top.generate_r1cs_constraints();

                    this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(
                        1, computed_root, root_var));

                    pack_component.generate_r1cs_constraints();
                }

                void generate_r1cs_witness(root<TField> value, 
                        AuthPathData<TField> auth_path, root<TField> root) {

                    bp.val(value_var_base) = value;
                    bp.val(root_var) = root;

                    base.generate_r1cs_witness(auth_path.base);
                    sub.generate_r1cs_witness(auth_path.sub);
                    top.generate_r1cs_witness(auth_path.top);

                    pack_component.generate_r1cs_witness();
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

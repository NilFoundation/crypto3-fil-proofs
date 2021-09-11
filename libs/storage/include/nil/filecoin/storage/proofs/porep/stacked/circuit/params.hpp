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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_PARAMS_COMPONENTS_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_PARAMS_COMPONENTS_HPP

#include <nil/filecoin/storage/proofs/core/components/por.hpp>

#include <nil/filecoin/storage/proofs/porep/stacked/circuit/column_proof.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/proof.hpp>

namespace nil {
    namespace filecoin {
        namespace porep {
            namespace stacked {
                namespace components {

                    template<typename TField, typename MerkleTreeType>
                    using TreeAuthPath = AuthPath<TField, typename MerkleTreeType::hash_type, 
                                                  MerkleTreeType::base_arity,
                                                  MerkleTreeType::sub_tree_arity, 
                                                  MerkleTreeType::top_tree_arity>;

                    template<typename TField, typename MerkleTreeType>
                    using TreeColumnProof = ColumnProof<TField, typename MerkleTreeType::hash_type, 
                                                        MerkleTreeType::base_arity,
                                                        MerkleTreeType::sub_tree_arity, 
                                                        MerkleTreeType::top_tree_arity>;

                    /// Proof for a single challenge.
                    template<typename TField, typename TMerkleTree, typename THash>
                    class Proof {

                        components::blueprint_variable<TField> data_leaf_var;

                        std::vector<auto> drg_parents;
                    public:
                        /// Inclusion path for the challenged data node in tree D.
                        AuthPath<THash, 2, 0, 0> comm_d_path;
                        /// The value of the challenged data node.
                        typename TField::value_type data_leaf;
                        /// The index of the challenged node.
                        std::uint64_t challenge;
                        /// Inclusion path of the challenged replica node in tree R.
                        TreeAuthPath<TField, TMerkleTree> comm_r_last_path;

                        /// Inclusion path of the column hash of the challenged node  in tree C.
                        TreeAuthPath<TField, TMerkleTree> comm_c_path;
                        /// Column proofs for the drg parents.
                        std::vector<TreeColumnProof<TField, TMerkleTree>> drg_parents_proofs;
                        /// Column proofs for the expander parents.
                        std::vector<TreeColumnProof<TField, TMerkleTree>> exp_parents_proofs;

                        Proof(components::blueprint<TField> &bp, 
                              const PublicParams<TMerkleTree> &params, 
                              std::size_t layers) :
                            comm_d_path(AuthPath<typename TMerkleTree::hash_type, TMerkleTree::base_arity,
                                                 TMerkleTree::sub_tree_arity, TMerkleTree::top_tree_arity>(
                                params.graph.size())),
                            comm_r_last_path(AuthPath<typename TMerkleTree::hash_type, TMerkleTree::base_arity,
                                                      TMerkleTree::sub_tree_arity, TMerkleTree::top_tree_arity>(
                                params.graph.size())),
                            comm_c_path(AuthPath<typename TMerkleTree::hash_type, TMerkleTree::base_arity,
                                                 TMerkleTree::sub_tree_arity, TMerkleTree::top_tree_arity>(
                                params.graph.size())),
                            drg_parents_proofs(std::vector<TreeColumnProof<TField, TMerkleTree>>(
                                ColumnProof(params), params.graph.base_graph().degree())),
                            exp_parents_proofs(std::vector<TreeColumnProof<TField, TMerkleTree>>(
                                ColumnProof(params), params.graph.expansion_degree())) {

                            replica_id_var.allocate(data_leaf_var);
                        }

                        Proof(components::blueprint<TField> &bp, 
                              const vanilla::Proof<TField, TMerkleTree, THash> &vanilla_proof, 
                              std::size_t layers) {

                            comm_d_proofs, comm_r_last_proof, replica_column_proofs,
                                                      = vanilla_proof;

                            const typename TField::value_type data_leaf = 
                                vanilla_proof.comm_d_proofs.leaf();

                            comm_d_path = comm_d_proofs;
                            challenge = vanilla_proof.labeling_proofs[0].node;
                            comm_r_last_path = comm_r_last_proof;
                            comm_c_path = vanilla_proof.replica_column_proofs.c_x.inclusion_proof;
                            drg_parents_proofs = vanilla_proof.replica_column_proofs.drg_parents;
                            exp_parents_proofs = vanilla_proof.replica_column_proofs.exp_parents;
                            
                            assert(!drg_parents_proofs.empty());
                            assert(!exp_parents_proofs.empty());

                            replica_id_var.allocate(data_leaf_var);
                        }

                        void generate_r1cs_constraints() {
                            
                        }

                        void generate_r1cs_witness(std::size_t layers, 
                                                   components::blueprint_variable<TField> &comm_d, 
                                                   components::blueprint_variable<TField> &comm_c, 
                                                   components::blueprint_variable<TField> &comm_r_last, 
                                                   const std::vector<bool> &replica_id){


                            // Private Inputs for the DRG parent nodes.
                            drg_parents.reserve(layers);

                            // -- verify replica column openings

                            for (TreeColumnProof<TField, TMerkleTree>::iterator parent = drg_parents_proofs.begin();
                                 parent != drg_parents_proofs.end(); ++parent) {

                                auto parent_col = parent.column;
                                auto inclusion_path = parent.inclusion_path;

                                assert(layers == parent_col.size());

                                // calculate column hash
                                const auto val =
                                    parent_col.hash(cs.namespace(|| std::format("drg_parent_%d_constraint", i)));
                                // enforce inclusion of the column hash in the tree C
                                enforce_inclusion(cs.namespace(|| std::format("drg_parent_%d_inclusion", i)),
                                                  inclusion_path, comm_c, &val);
                                drg_parents.push(parent_col);
                            }
                        }

                        /// Circuit synthesis.
                        void synthesize() {

                            // Private Inputs for the Expander parent nodes.
                            std::vector<auto> exp_parents;

                            for (std::size_t i = 0, exp_parents_proofs::iterator parent = exp_parents_proofs.begin();
                                 parent != exp_parents_proofs.end(); ++i, ++parent) {

                                const auto(parent_col, inclusion_path) =
                                    (*parent).alloc(cs.namespace(|| std::format("exp_parent_%d_num", i)));
                                assert(layers == parent_col.size());

                                // calculate column hash
                                const auto val =
                                    parent_col.hash(cs.namespace(|| std::format("exp_parent_%d_constraint", i)));
                                // enforce inclusion of the column hash in the tree C
                                enforce_inclusion(cs.namespace(|| std::format("exp_parent_%d_inclusion", i)),
                                                  inclusion_path, comm_c, &val);
                                exp_parents.push_back(parent_col);
                            }

                            // -- Verify labeling and encoding

                            // stores the labels of the challenged column
                            std::vector<auto> column_labels;

                            // PublicInput: challenge index
                            const auto challenge_num = uint64::UInt64::alloc(cs.namespace(|| "challenge"), challenge);
                            challenge_num.pack_into_input(cs.namespace(|| "challenge input"));

                            for (uint32_t layer = 1; layer != layers; layer++) {
                                const auto layer_num = uint32::UInt32::constant(layer as u32);

                                auto cs = cs.namespace(|| std::format("labeling_%d", layer));

                                // Collect the parents
                                std::vector<auto> parents;

                                // all layers have drg parents
                                for (drg_parents::iterator parent_col = drg_parents.begin();
                                     parent_col != drg_parents.end();
                                     ++parent_col) {

                                    const auto parent_val_num = (*parent_col).get_value(layer);
                                    const auto parent_val_bits = reverse_bit_numbering(parent_val_num.to_bits_le(
                                        cs.namespace(|| std::format("drg_parent_%d_bits", parents.len()))));
                                    parents.push(parent_val_bits);
                                }

                                // the first layer does not contain expander parents
                                if (layer > 1) {
                                    for (exp_parents::iterator parent_col = exp_parents.begin();
                                         parent_col != exp_parents.end();
                                         ++parent_col) {

                                        // subtract 1 from the layer index, as the exp parents, are shifted by one,
                                        // as they do not store a value for the first layer
                                        const auto parent_val_num = (*parent_col).get_value(layer - 1);
                                        const auto parent_val_bits = reverse_bit_numbering(parent_val_num.to_bits_le(
                                            cs.namespace(|| std::format("exp_parent_%d_bits", parents.len()))));
                                        parents.push(parent_val_bits);
                                    }
                                }

                                // Duplicate parents, according to the hashing algorithm.
                                auto expanded_parents = parents.clone();
                                if (layer > 1) {
                                    expanded_parents.extend_from_slice(&parents);         // 28
                                    expanded_parents.extend_from_slice(&parents[..9]);    // 37
                                } else {
                                    // layer 1 only has drg parents
                                    expanded_parents.extend_from_slice(&parents);    // 12
                                    expanded_parents.extend_from_slice(&parents);    // 18
                                    expanded_parents.extend_from_slice(&parents);    // 24
                                    expanded_parents.extend_from_slice(&parents);    // 30
                                    expanded_parents.extend_from_slice(&parents);    // 36
                                    expanded_parents.push(parents[0].clone());       // 37
                                };

                                // Reconstruct the label
                                const auto label = create_label(cs.namespace(|| "create_label"), replica_id,
                                                                expanded_parents, layer_num, challenge_num.clone());
                                column_labels.push(label);
                            }

                            // -- encoding node
                            // encode the node

                            // key is the last label
                            const auto key = &column_labels[column_labels.len() - 1];
                            const auto encoded_node = encode(cs.namespace(|| "encode_node"), key, &data_leaf_num);

                            // verify inclusion of the encoded node
                            enforce_inclusion(cs.namespace(|| "comm_r_last_data_inclusion"), comm_r_last_path,
                                              comm_r_last, &encoded_node);

                            // -- ensure the column hash of the labels is included
                            // calculate column_hash
                            const auto column_hash =
                                hash_single_column(cs.namespace(|| "c_x_column_hash"), &column_labels);

                            // enforce inclusion of the column hash in the tree C
                            enforce_inclusion(cs.namespace(|| "c_x_inclusion"), comm_c_path, comm_c, &column_hash);
                        }

                    };

                    /// Enforce the inclusion of the given path, to the given leaf and the root.
                    template<typename Hash, std::size_t BaseArity, std::size_t SubTreeArity, std::size_t TopTreeArity,
                             template<typename> class ConstraintSystem>
                    void enforce_inclusion(const ConstraintSystem<algebra::curves::bls12<381>> &cs,
                                           const AuthPath<Hash, BaseArity, SubTreeArity, TopTreeArity> &path,
                                           const AllocatedNumber<algebra::curves::bls12<381>> &root,
                                           const AllocatedNumber<algebra::curves::bls12<381>> &leaf) {
                        const auto root = Root::from_allocated::<CS>(root.clone());
                        const auto leaf = Root::from_allocated::<CS>(leaf.clone());

                        PoRCircuitMerkleTreeWrapper<H, DiskStore<H::digest_type>, U, V, W> >
                            ::synthesize(cs, leaf, path, root, true);
                    }
                }    // namespace components
            }        // namespace stacked
        }            // namespace porep
    }                // namespace filecoin
}    // namespace nil

#endif  // FILECOIN_STORAGE_PROOFS_POREP_STACKED_PARAMS_COMPONENTS_HPP

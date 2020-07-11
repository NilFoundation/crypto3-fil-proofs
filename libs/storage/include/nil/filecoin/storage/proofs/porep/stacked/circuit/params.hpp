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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_CIRCUIT_PARAMS_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_CIRCUIT_PARAMS_HPP

#include <nil/filecoin/storage/proofs/core/gadgets/por.hpp>

#include <nil/filecoin/storage/proofs/porep/stacked/circuit/column_proof.hpp>

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/proof.hpp>

namespace nil {
    namespace filecoin {
        namespace porep {
            namespace stacked {
                namespace circuit {

                    template<typename MerkleTreeType>
                    using TreeAuthPath = AuthPath<typename MerkleTreeType::hash_type, MerkleTreeType::Arity,
                                                  MerkleTreeType::SubTreeArity, MerkleTreeType::TopTreeArity>;

                    template<typename MerkleTreeType>
                    using TreeColumnProof = ColumnProof<typename MerkleTreeType::hash_type, MerkleTreeType::Arity,
                                                        MerkleTreeType::SubTreeArity, MerkleTreeType::TopTreeArity>;

                    /// Proof for a single challenge.
                    template<typename MerkleTreeType, typename Hash>
                    struct Proof {
                        Proof(const PublicParams<MerkleTreeType> &params) {
                        comm_d_path:
                            AuthPath::blank(params.graph.size()), data_leaf : None,
                                                                              challenge : None,
                                                                                          comm_r_last_path
                                : AuthPath::blank(params.graph.size()),
                                  comm_c_path : AuthPath::blank(params.graph.size()),
                                                drg_parents_proofs
                                : vec ![ColumnProof::empty(params); params.graph.base_graph().degree()],
                                  exp_parents_proofs
                                : vec ![ColumnProof::empty(params); params.graph.expansion_degree()],
                                  _t : PhantomData,
                        }

                        Proof(const vanilla::Proof<MerkleTreeType, Hash> &vanilla_proof) {
                            let VanillaProof {comm_d_proofs, comm_r_last_proof, replica_column_proofs, labeling_proofs,
                                              ..} = vanilla_proof;
                            let VanillaReplicaColumnProof {
                                c_x,
                                drg_parents,
                                exp_parents,
                            } = replica_column_proofs;

                            let data_leaf = Some(comm_d_proofs.leaf().into());

                            Proof {
                            comm_d_path:
                                comm_d_proofs.as_options().into(), data_leaf,
                                    challenge
                                    : Some(labeling_proofs[0].node),
                                      comm_r_last_path : comm_r_last_proof.as_options().into(),
                                      comm_c_path : c_x.inclusion_proof.as_options().into(),
                                      drg_parents_proofs : drg_parents.into_iter().map(| p | p.into()).collect(),
                                      exp_parents_proofs : exp_parents.into_iter().map(| p | p.into()).collect(),
                                      _t : PhantomData,
                            }
                        }

                        /// Circuit synthesis.
                        template<template<typename> class ConstraintSystem, typename Bls12>
                        void synthesize(ConstraintSystem<Bls12> &cs, std::size_t layers, AllocatedNumber<Bls12> &comm_d,
                                        AllocatedNumber<Bls12> &comm_c, AllocatedNumber<Bls12> &comm_r_last,
                                        const std::vector<bool> &replica_id) {
                            let Proof {comm_d_path, data_leaf,          challenge,          comm_r_last_path,
                                       comm_c_path, drg_parents_proofs, exp_parents_proofs, ..} = self;

                            assert(!drg_parents_proofs.empty());
                            assert(!exp_parents_proofs.empty());

                            // -- verify initial data layer

                            // PrivateInput: data_leaf
                            let data_leaf_num = num::AllocatedNum::alloc(
                                cs.namespace(|| "data_leaf"),
                                || {data_leaf.ok_or_else(|| SynthesisError::AssignmentMissing)}) ?
                                ;

                            // enforce inclusion of the data leaf in the tree D
                            enforce_inclusion(cs.namespace(|| "comm_d_inclusion"), comm_d_path, comm_d,
                                              &data_leaf_num, ) ?
                                ;

                            // -- verify replica column openings

                            // Private Inputs for the DRG parent nodes.
                            let mut drg_parents = Vec::with_capacity(layers);

                            for ((i, parent) : drg_parents_proofs.into_iter().enumerate()) {
                                let(parent_col, inclusion_path) =
                                    parent.alloc(cs.namespace(|| format !("drg_parent_{}_num", i))) ?
                                    ;
                                assert(layers == parent_col.size());

                                // calculate column hash
                                let val = parent_col.hash(cs.namespace(|| format !("drg_parent_{}_constraint", i))) ? ;
                                // enforce inclusion of the column hash in the tree C
                                enforce_inclusion(cs.namespace(|| format !("drg_parent_{}_inclusion", i)),
                                                  inclusion_path, comm_c, &val, ) ?
                                    ;
                                drg_parents.push(parent_col);
                            }

                            // Private Inputs for the Expander parent nodes.
                            let mut exp_parents = Vec::new ();

                            for ((i, parent) : exp_parents_proofs.into_iter().enumerate()) {
                                let(parent_col, inclusion_path) =
                                    parent.alloc(cs.namespace(|| format !("exp_parent_{}_num", i))) ?
                                    ;
                                assert(layers == parent_col.size());

                                // calculate column hash
                                let val = parent_col.hash(cs.namespace(|| format !("exp_parent_{}_constraint", i))) ? ;
                                // enforce inclusion of the column hash in the tree C
                                enforce_inclusion(cs.namespace(|| format !("exp_parent_{}_inclusion", i)),
                                                  inclusion_path, comm_c, &val, ) ?
                                    ;
                                exp_parents.push_back(parent_col);
                            }

                            // -- Verify labeling and encoding

                            // stores the labels of the challenged column
                            let mut column_labels = Vec::new ();

                            // PublicInput: challenge index
                            let challenge_num = uint64::UInt64::alloc(cs.namespace(|| "challenge"), challenge) ? ;
                            challenge_num.pack_into_input(cs.namespace(|| "challenge input")) ? ;

                            for (uint32_t layer = 1; layer != layers; layer++) {
                                let layer_num = uint32::UInt32::constant(layer as u32);

                                let mut cs = cs.namespace(|| format !("labeling_{}", layer));

                                // Collect the parents
                                let mut parents = Vec::new ();

                                // all layers have drg parents
                                for (parent_col : &drg_parents) {
                                    let parent_val_num = parent_col.get_value(layer);
                                    let parent_val_bits =
                                        reverse_bit_numbering(parent_val_num.to_bits_le(
                                    cs.namespace(|| format!("drg_parent_{}_bits", parents.len())),
                                    )?);
                                    parents.push(parent_val_bits);
                                }

                                // the first layer does not contain expander parents
                                if (layer > 1) {
                                    for (parent_col : exp_parents) {
                                        // subtract 1 from the layer index, as the exp parents, are shifted by one,
                                        // as they do not store a value for the first layer
                                        let parent_val_num = parent_col.get_value(layer - 1);
                                        let parent_val_bits = reverse_bit_numbering(parent_val_num.to_bits_le(
                                        cs.namespace(|| format!("exp_parent_{}_bits", parents.len())),
                                        )?);
                                        parents.push(parent_val_bits);
                                    }
                                }

                                // Duplicate parents, according to the hashing algorithm.
                                let mut expanded_parents = parents.clone();
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
                                let label = create_label(cs.namespace(|| "create_label"), replica_id, expanded_parents,
                                                         layer_num, challenge_num.clone(), ) ?
                                    ;
                                column_labels.push(label);
                            }

                            // -- encoding node
                            {
                                // encode the node

                                // key is the last label
                                let key = &column_labels[column_labels.len() - 1];
                                let encoded_node = encode(cs.namespace(|| "encode_node"), key, &data_leaf_num) ? ;

                                // verify inclusion of the encoded node
                                enforce_inclusion(cs.namespace(|| "comm_r_last_data_inclusion"), comm_r_last_path,
                                                  comm_r_last, &encoded_node, ) ?
                                    ;
                            }

                            // -- ensure the column hash of the labels is included
                            {
                                // calculate column_hash
                                let column_hash =
                                    hash_single_column(cs.namespace(|| "c_x_column_hash"), &column_labels) ?
                                    ;

                                // enforce inclusion of the column hash in the tree C
                                enforce_inclusion(cs.namespace(|| "c_x_inclusion"), comm_c_path, comm_c,
                                                  &column_hash, ) ?
                                    ;
                            }
                        }

                        /// Inclusion path for the challenged data node in tree D.
                        AuthPath<G, U2, U0, U0> comm_d_path;
                        /// The value of the challenged data node.
                        Fr data_leaf;
                        /// The index of the challenged node.
                        std::uint64_t challenge;
                        /// Inclusion path of the challenged replica node in tree R.
                        TreeAuthPath<MerkleTreeType> comm_r_last_path;

                        /// Inclusion path of the column hash of the challenged node  in tree C.
                        TreeAuthPath<MerkleTreeType> comm_c_path;
                        /// Column proofs for the drg parents.
                        std::vector<TreeColumnProof<MerkleTreeType>> drg_parents_proofs;
                        /// Column proofs for the expander parents.
                        std::vector<TreeColumnProof<MerkleTreeType>> exp_parents_proofs;
                    };

                    /// Enforce the inclusion of the given path, to the given leaf and the root.
                    template<typename Hash, std::size_t BaseArity, std::size_t SubTreeArity, std::size_t TopTreeArity,
                             template<typename> class ConstraintSystem, typename Bls12>
                    void enforce_inclusion(const ConstraintSystem<Bls12> &cs,
                                           const AuthPath<Hash, BaseArity, SubTreeArity, TopTreeArity> &path,
                                           const AllocatedNumber<Bls12> &root,
                                           const AllocatedNumber<Bls12> &leaf) {
                        let root = Root::from_allocated::<CS>(root.clone());
                        let leaf = Root::from_allocated::<CS>(leaf.clone());

                        PoRCircuitMerkleTreeWrapper<H, DiskStore<H::Domain>, U, V, W> >
                            ::synthesize(cs, leaf, path, root, true);
                    }

                }    // namespace circuit
            }        // namespace stacked
        }            // namespace porep
    }                // namespace filecoin
}    // namespace nil

#endif
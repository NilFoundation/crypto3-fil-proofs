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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_MERKLE_PROOF_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_MERKLE_PROOF_HPP

#include <vector>

#include <boost/variant.hpp>

namespace nil {
    namespace filecoin {
        /// Trait to abstract over the concept of Merkle Proof.
        template<typename Hash, typename Arity = PoseidonArity, typename SubTreeArity = PoseidonArity,
                 typename TopTreeArity = PoseidonArity>
        struct MerkleProofTrait {
            typedef Hash hash_type;
            typedef Arity arity_type;
            typedef SubTreeArity subtree_arity;
            typedef TopTreeArity top_tree_arity;

            /// Try to convert a merkletree proof into this structure.
            static MerkleProofTrait<Hash, Arity, SubTreeArity, TopTreeArity>
                try_from_proof(const Proof<typename Hash::digest_type, Arity> &p) {
            }

            std::vector<std::pair<std::vector<Fr>, std::size_t>> as_options(&self) {
                return path()
                    .iter()
                    .map(| v | {(v .0.iter().copied().map(Into::into).map(Some).collect(), Some(v .1), )})
                    .collect::<Vec<_>>();
            }

            std::pair<Fr, std::vector<std::pair<std::vector<Fr>, std::size_t>>> into_options_with_leaf() {
                let leaf = leaf();
                let path = path();
                (Some(leaf.into()),
                 path.into_iter()
                     .map(| (a, b) | {(a.iter().copied().map(Into::into).map(Some).collect(), Some(b), )})
                     .collect::<Vec<_>>(), )
            }

            std::vector<std::pair<std::vector<Fr>, std::size_t>> as_pairs() {
                self.path()
                    .iter()
                    .map(| v | (v .0.iter().copied().map(Into::into).collect(), v .1))
                    .collect::<Vec<_>>();
            }

            virtual bool verify() const = 0;

            /// Validates the MerkleProof and that it corresponds to the supplied node.
            ///
            /// TODO: audit performance and usage in case verification is
            /// unnecessary based on how it's used.
            virtual bool validate(std::size_t node) {
                if (!verify()) {
                    return false;
                }

                return node == path_index();
            }

            virtual bool validate_data(const typename Hash::digest_type &data) {
                if (!verify()) {
                    return false;
                }

                return leaf() == data;
            }

            virtual typename Hash::digest_type leaf() = 0;
            virtual typename Hash::digest_type root() = 0;
            virtual std::size_t typename Hash::digest_type size() = 0;
            virtual std::vector<std::pair<std::vector<typename Hash::digest_type>, std::size_t>> path() = 0;

            std::size_t path_index() {
                return path().iter().rev().fold(0, | acc, (_, index) | (acc * Self::Arity::to_usize()) + index);
            }

            bool proves_challenge(std::size_t challenge) {
                path_index() == challenge;
            }

            /// Calcluates the exected length of the full path, given the number of leaves in the base layer.
            std::size_t expected_len(std::size_t leaves) {
                compound_path_length::<Self::Arity, Self::SubTreeArity, Self::TopTreeArity>(leaves)
            }
        };

        template<std::size_t A, std::size_t B, std::size_t C>
        std::size_t base_path_length(std::size_t leaves) {
            std::size_t l;
            if (C > 0) {
                l = leaves / C / B;
            } else if (B > 0) {
                l = leaves / B;
            } else {
                l = leaves;
            }

            return graph_height<A>(leaves) - 1;
        }

        template<std::size_t A, std::size_t B, std::size_t C>
        std::size_t compound_path_length(std::size_t leaves) {
            std::size_t len = base_path_length<A, B, C>(leaves);
            if (B > 0) {
                len += 1;
            }

            if (C > 0) {
                len += 1;
            }

            return len;
        }

        template<std::size_t A, std::size_t B, std::size_t C>
        std::size_t compound_tree_height(std::size_t leaves) {
            // base layer
            std::size_t a = graph_height<A>(leaves) - 1;

            // sub tree layer
            std::size_t b;
            if (B > 0) {
                b = B - 1;
            } else {
                b = 0;
            }

            // top tree layer
            std::size_t c;
            if (C > 0) {
                c = C - 1;
            } else {
                c = 0;
            }

            return a + b + c;
        }

        template<typename Hash, typename Arity = PoseidonArity>
        struct InclusionPath {
            /// Calculate the root of this path, given the leaf as input.
            typename Hash::digest_type root(const typename Hash::digest_type &leaf) {
                let mut a = H::Function::default();
                (0..self.path.len())
                    .fold(
                        leaf, | h, height | {
                            a.reset();

                            let index = self.path[height].index;
                            let mut nodes = self.path[height].hashes.clone();
                            nodes.insert(index, h);

                            a.multi_node(&nodes, height)
                        })
            }

            std::size_t size() {
                return path.size();
            }

            bool empty() {
                return path.empty();
            }

            pub fn iter(&self)
                    ->std::slice::Iter<PathElement<H, Arity>> {self.path.iter()}

                pub fn path_index(&self)
                    ->usize {self.path.iter().rev().fold(0, | acc, p | (acc * Arity::to_usize()) + p.index)}

                std::vector < PathElement<Hash, Arity> path;
        };

        template<typename Hash, typename Arity>
        struct PathElement {
            std::vector<typename Hash::digest_type> &hashes;
            std::size_t index;
        };

        template<typename Hash, typename Arity>
        struct SingleProof {
            template<template<typename, typename> class Proof>
            static SingleProof<Hash, Arity> try_from_proof(const Proof<typename Hash::digest_type, Arity> &p) {
                return proof_to_single(&p, 1);
            }

            bool verify() {
                let calculated_root = path.root(self.leaf);
                return root == calculated_root;
            }

            fn leaf(&self)
                ->H::Domain {self.leaf}

            fn root(&self)
                ->H::Domain {self.root}

            fn len(&self)
                ->usize {self.path.len() * (Arity::to_usize() - 1) + 2}

            fn path(&self)
                ->Vec<(Vec<H::Domain>, usize)> {
                    self.path.iter().map(| x | (x.hashes.clone(), x.index)).collect::<Vec<_>>()}

            fn path_index(&self)
                ->usize {
                self.path.path_index()
            }

            /// Root of the merkle tree.
            typename Hash::digest_type root;
            /// The original leaf data for this prof.
            typename Hash::digest_type leaf;
            /// The path from leaf to root.
            InclusionPath<Hash, Arity> path;
        };

        template<typename Hash, typename BaseArity, typename SubTreeArity>
        struct SubProof {
            fn try_from_proof(p : proof::Proof << H as Hasher > ::Domain, Arity >)->Result<Self> {
                ensure !(p.sub_layer_nodes() == SubTreeArity::to_usize(), "sub arity mismatch");
                ensure !(p.sub_tree_proof.is_some(), "Cannot generate sub proof without a base-proof");
                let base_p = p.sub_tree_proof.as_ref().unwrap();

                // Generate SubProof
                let root = p.root();
                let leaf = base_p.item();
                let base_proof = extract_path::<H, Arity>(base_p.lemma(), base_p.path(), 1);
                let sub_proof = extract_path::<H, SubTreeArity>(p.lemma(), p.path(), 0);

                Ok(SubProof::new (base_proof, sub_proof, root, leaf))
            }

            fn verify(&self)->bool {
                let sub_leaf = self.base_proof.root(self.leaf);
                let calculated_root = self.sub_proof.root(sub_leaf);

                self.root == calculated_root
            }

            fn leaf(&self)
                ->H::Domain {self.leaf}

            fn root(&self)
                ->H::Domain {self.root}

            fn len(&self)
                ->usize {SubTreeArity::to_usize()}

            fn path(&self)
                ->Vec<(Vec<H::Domain>, usize)> {self.base_proof.iter()
                                                    .map(| x | (x.hashes.clone(), x.index))
                                                    .chain(self.sub_proof.iter().map(| x | (x.hashes.clone(), x.index)))
                                                    .collect()}

            fn path_index(&self)
                ->usize {
                let mut base_proof_leaves = 1;
                for
                    _i in 0..self.base_proof.len() {base_proof_leaves *= Arity::to_usize()}

                    let sub_proof_index = self.sub_proof.path_index();

                (sub_proof_index * base_proof_leaves) + self.base_proof.path_index()
            }

            InclusionPath<Hash, BaseArity> base_proof;

            InclusionPath<Hash, SubTreeArity> sub_proof;

            typename Hash::digest_type root;
            /// The original leaf data for this prof.

            typename Hash::digest_type leaf;
        };

        template<typename Hash, typename BaseArity, typename SubTreeArity, typename TopTreeArity>
        struct TopProof {
            fn try_from_proof(p : proof::Proof << H as Hasher > ::Domain, Arity >)->Result<Self> {
                ensure !(p.top_layer_nodes() == TopTreeArity::to_usize(), "top arity mismatch");
                ensure !(p.sub_layer_nodes() == SubTreeArity::to_usize(), "sub arity mismatch");

                ensure !(p.sub_tree_proof.is_some(), "Cannot generate top proof without a sub-proof");
                let sub_p = p.sub_tree_proof.as_ref().unwrap();

                ensure !(sub_p.sub_tree_proof.is_some(), "Cannot generate top proof without a base-proof");
                let base_p = sub_p.sub_tree_proof.as_ref().unwrap();

                let root = p.root();
                let leaf = base_p.item();

                let base_proof = extract_path::<H, Arity>(base_p.lemma(), base_p.path(), 1);
                let sub_proof = extract_path::<H, SubTreeArity>(sub_p.lemma(), sub_p.path(), 0);
                let top_proof = extract_path::<H, TopTreeArity>(p.lemma(), p.path(), 0);

                Ok(TopProof::new (base_proof, sub_proof, top_proof, root, leaf))
            }

            fn verify(&self)->bool {
                let sub_leaf = self.base_proof.root(self.leaf);
                let top_leaf = self.sub_proof.root(sub_leaf);
                let calculated_root = self.top_proof.root(top_leaf);

                self.root == calculated_root
            }

            fn leaf(&self)
                ->H::Domain {self.leaf}

            fn root(&self)
                ->H::Domain {self.root}

            fn len(&self)
                ->usize {TopTreeArity::to_usize()}

            fn path(&self)
                ->Vec<(Vec<H::Domain>, usize)> {self.base_proof.iter()
                                                    .map(| x | (x.hashes.clone(), x.index))
                                                    .chain(self.sub_proof.iter().map(| x | (x.hashes.clone(), x.index)))
                                                    .chain(self.top_proof.iter().map(| x | (x.hashes.clone(), x.index)))
                                                    .collect()}

            fn path_index(&self)
                ->usize {
                let mut base_proof_leaves = 1;
                for
                    _i in 0..self.base_proof.len() {base_proof_leaves *= Arity::to_usize()}

                    let sub_proof_leaves = base_proof_leaves * SubTreeArity::to_usize();

                let sub_proof_index = self.sub_proof.path_index();
                let top_proof_index = self.top_proof.path_index();

                (sub_proof_index * base_proof_leaves) + (top_proof_index * sub_proof_leaves) +
                    self.base_proof.path_index()
            }

            InclusionPath<Hash, BaseArity> base_proof;

            InclusionPath<Hash, SubTreeArity> sub_proof;

            InclusionPath<Hash, TopTreeArity> top_proof;
            /// Root of the merkle tree.

            typename Hash::digest_type root;
            /// The original leaf data for this prof.
            typename Hash::digest_type leaf;
        };

        template<typename Hash, typename BaseArity, typename SubTreeArity, typename TopTreeArity>
        using ProofData = boost::variant<SingleProof<Hash, BaseArity>, SubProof<Hash, BaseArity, SubTreeArity>,
                                         TopProof<Hash, BaseArity, SubTreeArity, TopTreeArity>>;

        template<typename Hash, typename BaseArity = PoseidonArity, typename SubTreeArity = PoseidonArity,
                 typename TopTreeArity = PoseidonArity>
        struct MerkleProof : public MerkleProofTrait<Hash, BaseArity, SubTreeArity, TopTreeArity> {
            typedef typename Hash::digest_type digest_type;
            MerkleProof(std::size_t n) {
                let root = Default::default();
                let leaf = Default::default();
                let path_elem = PathElement {
                hashes:
                    vec ![Default::default(); BaseArity::to_usize()], index : 0, _arity : Default::default(),
                };
                let path = vec ![path_elem; n];
                data = ProofData::Single(SingleProof::new (path.into(), root, leaf));
            }

            virtual bool verify() const override {
                return false;
            }
            virtual bool validate(std::size_t node) override {
                return MerkleProofTrait::validate(node);
            }
            virtual bool validate_data(const digest_type &data) override {
                return MerkleProofTrait::validate_data(data);
            }
            virtual digest_type leaf() override {
                return nullptr;
            }
            virtual digest_type root() override {
                return nullptr;
            }
            virtual std::vector<std::pair<std::vector<typename Hash::digest_type>, std::size_t>> path() override {
                return std::vector<std::pair<std::vector<typename Hash::digest_type>, std::size_t>>();
            }

            ProofData<Hash, BaseArity, SubTreeArity, TopTreeArity> data;
        };

        /// 'lemma_start_index' is required because sub/top proofs start at
        /// index 0 and base proofs start at index 1 (skipping the leaf at the
        /// front)
        template<typename Hash, typename Arity, typename LemmaIterator, typename PathIterator>
        InclusionPath<Hash, Arity> extract_path(LemmaIterator lemma_first, LemmaIterator lemma_last,
                                                PathIterator path_first, PathIterator path_last,
                                                std::size_t lemma_start_index) {
            let path = lemma[lemma_start_index..lemma.len() - 1]
                           .chunks(Arity::to_usize() - 1)
                           .zip(path.iter())
                           .map(| (hashes, index) | PathElement {
                               hashes : hashes.to_vec(),
                               index : *index,
                               _arity : Default::default(),
                           })
                           .collect::<Vec<_>>();

            path.into()
        }

        /// Converts a merkle_light proof to a SingleProof
        template<typename Hash, typename Arity, typename TargetArity, template<typename, typename> class Proof>
        SingleProof<Hash, TargetArity>
            proof_to_single(const Proof<Hash, Arity> &proof, std::size_t lemma_start_index,
                            typename Hash::digest_type &sub_root = typename Hash::digest_type()) {
            typename Hash::digest_type root = proof.root();
            typename Hash::digest_type leaf = sub_root.emplty() ? sub_root : proof.item();

            InclusionPath<Hash, TargetArity> path =
                extract_path<Hash, TargetArity>(proof.lemma(), proof.path(), lemma_start_index);

            return {path, root, leaf};
        }
    }    // namespace filecoin
}    // namespace nil

#endif
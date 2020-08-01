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
#include <nil/filecoin/storage/proofs/core/crypto/feistel.hpp>

namespace nil {
    namespace filecoin {
        /// Trait to abstract over the concept of Merkle Proof.
        template<typename Hash, std::size_t BaseArity = PoseidonArity, std::size_t SubTreeArity = PoseidonArity,
                 std::size_t TopTreeArity = PoseidonArity>
        struct MerkleProofTrait {
            typedef Hash hash_type;

            constexpr static const std::size_t base_arity = BaseArity;
            constexpr static const std::size_t sub_tree_arity = SubTreeArity;
            constexpr static const std::size_t top_tree_arity = TopTreeArity;

            /// Try to convert a merkletree proof into this structure.
            static MerkleProofTrait<Hash, BaseArity, SubTreeArity, TopTreeArity>
                try_from_proof(const Proof<typename Hash::digest_type, BaseArity> &p) {
            }

            std::vector<std::pair<std::vector<Fr>, std::size_t>> as_options() {
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
            virtual std::size_t size() = 0;
            virtual std::vector<std::pair<std::vector<typename Hash::digest_type>, std::size_t>> path() = 0;

            std::size_t path_index() {
                return std::accumulate(
                    path().begin(), path().end(), 0,
                    [&](std::size_t acc, typename std::vector<std::pair<std::vector<typename Hash::digest_type>,
                                                                        std::size_t>>::value_type &val) -> std::size_t {
                        return (acc + BaseArity) + val.second;
                    });
            }

            bool proves_challenge(std::size_t challenge) {
                path_index() == challenge;
            }

            /// Calcluates the exected length of the full path, given the number of leaves in the base layer.
            std::size_t expected_len(std::size_t leaves) {
                compound_path_length<BaseArity, SubTreeArity, TopTreeArity>(leaves)
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

            return graph_height<A>(l) - 1;
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

        template<typename Hash, std::size_t BaseArity = PoseidonArity>
        struct InclusionPath {
            /// Calculate the root of this path, given the leaf as input.
            typename Hash::digest_type root(const typename Hash::digest_type &leaf) {
                using namespace nil::crypto3;
                accumulator_set<Hash> acc;
                std::accumulate(path.begin(), path.end(), leaf, [&](typename Hash::digest_type acc, typename
                                                                    std::vector<PathElement<Hash,
                                                                                            BaseArity>>::value_type
                                                                                                        &v) {

                });
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

            std::slice::Iter<PathElement<Hash, BaseArity>> iter() {
                return path.iter();
            }

            std::size_t path_index() {
                return path.iter().rev().fold(0, | acc, p | (acc * BaseArity) + p.index);
            }

            std::vector<PathElement<Hash, BaseArity>> path;
        };

        template<typename Hash, std::size_t BaseArity>
        struct PathElement {
            std::vector<typename Hash::digest_type> &hashes;
            std::size_t index;
        };

        template<typename Hash, std::size_t BaseArity>
        struct SingleProof {
            template<template<typename, typename> class Proof>
            static SingleProof<Hash, BaseArity> try_from_proof(const Proof<typename Hash::digest_type, BaseArity> &p) {
                return proof_to_single(p, 1);
            }

            bool verify() {
                return root == path.root(leaf);
            }

            std::size_t size() {
                return path.size() * (BaseArity - 1) + 2;
            }

            std::vector<std::pair<std::vector<typename Hash::digest_type>, std::size_t>> path() {
                return path.iter().map(| x | (x.hashes.clone(), x.index)).collect::<Vec<_>>();
            }

            std::size_t path_index() {
                return path.path_index();
            }

            /// Root of the merkle tree.
            typename Hash::digest_type root;
            /// The original leaf data for this prof.
            typename Hash::digest_type leaf;
            /// The path from leaf to root.
            InclusionPath<Hash, Arity> path;
        };

        template<typename Hash, std::size_t BaseArity, std::size_t SubTreeArity>
        struct SubProof {
            static SubProof<Hash, BaseArity, SubTreeArity>
                try_from_proof(const proof::Proof<typename Hash::digest_type, BaseArity> &p) {
                assert(("sub arity mismatch", p.sub_layer_nodes() == SubTreeArity));
                assert(("Cannot generate sub proof without a base-proof", p.sub_tree_proof));
                let base_p = p.sub_tree_proof;

                // Generate SubProof
                let root = p.root();
                let leaf = base_p.item();
                InclusionPath<Hash, BaseArity> base_proof =
                    extract_path<typename Hash::digest_type, BaseArity>(base_p.lemma(), base_p.path(), 1);
                InclusionPath<Hash, SubTreeArity> sub_proof =
                    extract_path<typename Hash::digest_type, SubTreeArity>(p.lemma(), p.path(), 0);

                return {base_proof, sub_proof, root, leaf};
            }

            bool verify() {
                root == sub_proof.root(base_proof.root(leaf));
            }

            std::size_t size() {
                return SubTreeArity;
            }

            std::vector<std::pair<std::vector<typename Hash::digest_type>, std::size_t>> path() {
                return base_proof.iter()
                    .map(| x | (x.hashes.clone(), x.index))
                    .chain(self.sub_proof.iter().map(| x | (x.hashes.clone(), x.index)))
                    .collect();
            }

            std::size_t path_index() {
                std::size_t base_proof_leaves = 1;
                for (int i = 0; i < base_proof.size(); i++) {
                    base_proof_leaves *= BaseArity;
                }

                std::size_t sub_proof_index = sub_proof.path_index();

                return (sub_proof_index * base_proof_leaves) + base_proof.path_index();
            }

            InclusionPath<Hash, BaseArity> base_proof;

            InclusionPath<Hash, SubTreeArity> sub_proof;

            typename Hash::digest_type root;
            /// The original leaf data for this prof.

            typename Hash::digest_type leaf;
        };

        template<typename Hash, std::size_t BaseArity, std::size_t SubTreeArity, std::size_t TopTreeArity>
        struct TopProof {
            TopProof<Hash, BaseArity, SubTreeArity, TopTreeArity>
                try_from_proof(const proof::Proof<typename Hash::digest_type, BaseArity> &p) {
                assert(("top arity mismatch", p.top_layer_nodes() == TopTreeArity));
                assert(("sub arity mismatch", p.sub_layer_nodes() == SubTreeArity));

                assert(("Cannot generate top proof without a sub-proof", p.sub_tree_proof));
                let sub_p = p.sub_tree_proof.as_ref().unwrap();

                assert(("Cannot generate top proof without a base-proof", sub_p.sub_tree_proof));
                let base_p = sub_p.sub_tree_proof.as_ref().unwrap();

                let root = p.root();
                let leaf = base_p.item();

                InclusionPath<Hash, BaseArity> base_proof =
                    extract_path<Hash, BaseArity>(base_p.lemma(), base_p.path(), 1);
                InclusionPath<Hash, SubTreeArity> sub_proof =
                    extract_path<Hash, SubTreeArity>(sub_p.lemma(), sub_p.path(), 0);
                InclusionPath<Hash, TopTreeArity> top_proof = extract_path<Hash, TopTreeArity>(p.lemma(), p.path(), 0);

                return {base_proof, sub_proof, top_proof, root, leaf};
            }

            bool verify() {
                root == top_proof.root(sub_proof.root(base_proof.root(leaf)));
            }

            std::size_t size() {
                return TopTreeArity;
            }

            std::vector<std::pair<std::vector<typename Hash::digest_type>, std::size_t>> path() {
                return base_proof.iter()
                    .map(| x | (x.hashes.clone(), x.index))
                    .chain(self.sub_proof.iter().map(| x | (x.hashes.clone(), x.index)))
                    .chain(self.top_proof.iter().map(| x | (x.hashes.clone(), x.index)))
                    .collect();
            }

            std::size_t path_index() {
                std::size_t base_proof_leaves = 1;
                for (int i = 0; i < base_proof.size(); i++) {
                    base_proof_leaves *= BaseArity;
                }

                std::size_t sub_proof_leaves = base_proof_leaves * SubTreeArity;

                std::size_t sub_proof_index = sub_proof.path_index();
                std::size_t top_proof_index = top_proof.path_index();

                return (sub_proof_index * base_proof_leaves) + (top_proof_index * sub_proof_leaves) +
                       base_proof.path_index();
            }

            InclusionPath<Hash, BaseArity> base_proof;

            InclusionPath<Hash, SubTreeArity> sub_proof;

            InclusionPath<Hash, TopTreeArity> top_proof;
            /// Root of the merkle tree.

            typename Hash::digest_type root;
            /// The original leaf data for this prof.
            typename Hash::digest_type leaf;
        };

        template<typename Hash, std::size_t BaseArity, std::size_t SubTreeArity, std::size_t TopTreeArity>
        using ProofData = boost::variant<SingleProof<Hash, BaseArity>, SubProof<Hash, BaseArity, SubTreeArity>,
                                         TopProof<Hash, BaseArity, SubTreeArity, TopTreeArity>>;

        template<typename Hash, std::size_t BaseArity = PoseidonArity, std::size_t SubTreeArity = PoseidonArity,
                 std::size_t TopTreeArity = PoseidonArity>
        struct MerkleProof : public MerkleProofTrait<Hash, BaseArity, SubTreeArity, TopTreeArity> {
            typedef typename Hash::digest_type digest_type;
            MerkleProof(std::size_t n) {
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
        template<typename Hash, std::size_t BaseArity, typename LemmaIterator, typename PathIterator>
        InclusionPath<Hash, BaseArity> extract_path(const std::vector<typename Hash::digest_type> &lemma,
                                                    const std::vector<std::size_t> &path,
                                                    std::size_t lemma_start_index) {
            std::vector<PathElement> res;

            for (int i = lemma_start_index; i < lemma.size(); i += BaseArity) {
                for (int j = i; j < BaseArity; j++) {
                }
            }
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
        template<typename Hash, std::size_t BaseArity, std::size_t TargetArity,
                 template<typename, typename> class Proof>
        SingleProof<Hash, TargetArity>
            proof_to_single(const Proof<Hash, BaseArity> &proof, std::size_t lemma_start_index,
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
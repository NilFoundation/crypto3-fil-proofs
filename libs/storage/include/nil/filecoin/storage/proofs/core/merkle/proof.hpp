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
                try_from_proof(const Proof<typename Hash::domain_type, Arity> &p) {
            }

            std::vector<std::pair<std::vector<Fr>, std::size_t>> as_options(&self) {
                return path()
                    .iter()
                    .map(| v | {(v .0.iter().copied().map(Into::into).map(Some).collect(), Some(v .1), )})
                    .collect::<Vec<_>>();
            }

            std::pair<Fr, std::vector<std::pair<std::vector<Fr>, std::size_t>>> into_options_with_leaf() {
                let leaf = self.leaf();
                let path = self.path();
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
            bool validate(std::size_t node) {
                if (!verify()) {
                    return false;
                }

                return node == self.path_index();
            }

            bool validate_data(&self, data : <Self::Hasher as Hasher>::Domain) {
                if (!self.verify()) {
                    return false;
                }

                return leaf() == data;
            }

            virtual typename Hash::domain_type leaf() = 0;
            virtual typename Hash::domain_type root() = 0;
            virtual std::size_t typename Hash::domain_type len() = 0;
            virtual std::vector<std::pair<std::vector<typename Hash::domain_type>, std::size_t>> path() = 0;

            std::size_t path_index() {
                return path().iter().rev().fold(0, | acc, (_, index) | (acc * Self::Arity::to_usize()) + index);
            }

            bool proves_challenge(std::size_t challenge) {
                self.path_index() == challenge;
            }

            /// Calcluates the exected length of the full path, given the number of leaves in the base layer.
            std::size_t expected_len(std::size_t leaves) {
                compound_path_length::<Self::Arity, Self::SubTreeArity, Self::TopTreeArity>(leaves)
            }
        }
    }    // namespace filecoin
}    // namespace nil

#endif
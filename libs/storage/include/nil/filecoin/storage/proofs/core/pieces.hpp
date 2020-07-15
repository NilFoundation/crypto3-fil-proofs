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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_PIECES_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_PIECES_HPP

#include <cstdint>
#include <cmath>

#include <nil/filecoin/storage/proofs/core/fr32.hpp>
#include <nil/filecoin/storage/proofs/core/utilities.hpp>

namespace nil {
    namespace filecoin {
        namespace detail {
            std::size_t subtree_capacity(std::size_t pos, std::size_t total) {
                assert(("position must be less than tree capacity", pos < total));

                std::size_t capacity = 1;
                // If tree is not 'full', then pos 0 will have subtree_capacity greater than size of tree.
                std::size_t cursor = pos + std::ceil(std::log2(total));

                while (cursor & 1 == 0) {
                    capacity *= 2;
                    cursor >>= 1;
                }
                return capacity;
            }

            bool piece_is_aligned(std::size_t position, std::size_t length, std::size_t tree_len) {
                std::size_t capacity_at_pos = subtree_capacity(position, tree_len);

                return (capacity_at_pos & (capacity_at_pos - 1)) == 0 && capacity_at_pos >= length;
            }

            std::size_t height_for_length(std::size_t n) {
                return n == 0 ? 0 : std::ceil(std::log2(n));
            }
        }    // namespace detail
        struct PieceSpec {
            std::size_t height() {
                return detail::height_for_length(number_of_leaves);
            }

            // `proof_length` is length of proof that comm_p is in the containing root, excluding comm_p and root, which
            // aren't needed for the proof itself.
            std::size_t proof_length(std::size_t tree_len) {
                return detail::height_for_length(tree_len) - height();
            }

            /// `compute_packing` returns a packing list and a proof size.
            /// A packing list is a pair of (start, length) pairs, relative to the beginning of the piece,
            /// in leaf units.
            /// Proof size is a number of elements (size same as one leaf) provided in the variable part of a
            /// PieceInclusionProof.
            std::tuple<std::vector<std::tuple<std::size_t, std::size_t>>, std::size_t>
                compute_packing(std::size_t tree_len) {
                assert(is_aligned(tree_len));

                std::vector<std::tuple<std::size_t, std::size_t>> packing_list {{0, number_of_leaves}};
                return std::make_tuple(packing_list, proof_length(tree_len));
            }

            bool is_aligned(std::size_t tree_len) const {
                return detail::piece_is_aligned(position, number_of_leaves, tree_len);
            }

            fr32_array comm_p;
            std::size_t position;
            std::size_t number_of_leaves;
        };

        /// Generate `comm_p` from a source and return it as bytes.
        template<typename Hash, typename Read>
        fr32_array generate_piece_commitment_bytes_from_source(Read &source, std::size_t padded_piece_size) {
            assert(("piece is too small", padded_piece_size > 32));
            assert(("piece is not valid size", padded_piece_size % 32 == 0));

            std::array<std::uint32_t, NODE_SIZE> buf;
            buf.fill(0);

            std::size_t parts = std::ceil(static_cast<double>(padded_piece_size) / static_cast<double>(NODE_SIZE));

            BinaryMerkleTree<Hash> tree = BinaryMerkleTree<Hash>::try_from_iter((0..parts).map(| _ | {
                                              source.read_exact(&mut buf) ? ;
                                              <H::Domain as Domain>::try_from_bytes(&buf).context("invalid Fr element")
                                          })).context("failed to build tree");

            std::array<std::uint32_t, NODE_SIZE> comm_p_bytes;
            comm_p_bytes.fill(0);
            auto comm_p = tree.root();
            comm_p.write_bytes(comm_p_bytes);

            return comm_p_bytes;
        }
    }    // namespace filecoin
}    // namespace nil

#endif
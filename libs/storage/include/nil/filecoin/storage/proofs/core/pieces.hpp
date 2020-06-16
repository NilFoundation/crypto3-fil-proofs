#ifndef FILECOIN_STORAGE_PROOFS_CORE_PIECES_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_PIECES_HPP

#include <stdint>
#include <cmath>

#include <nil/filecoin/storage/proofs/core/fr32.hpp>

namespace filecoin {
    namespace detail {
        std::size_t subtree_capacity(std::size_t pos, std::size_t total) {
            assert(pos < total, "position must be less than tree capacity");

            std::size_t capacity = 1;
            // If tree is not 'full', then pos 0 will have subtree_capacity greater than size of tree.
            std::size_t cursor = pos + next_pow2(total);

            while (!(cursor & 1)) {
                capacity *= 2;
                cursor >>= 1;
            }
            return capacity;
        }

        std::size_t height_for_length(std::size_t n) {
            if (n == 0) {
                return 0;
            } else {
                return std::ceil(std::log2(n));
            }
        }

        bool piece_is_aligned(std::size_t position, std::size_t length, std::size_t tree_len) {
            std::size_t capacity_at_pos = subtree_capacity(position, tree_len);

            return capacity_at_pos.is_power_of_two() && capacity_at_pos >= length;
        }
    }    // namespace detail

    struct piece_spec {
        /// `compute_packing` returns a packing list and a proof size.
        /// A packing list is a pair of (start, length) pairs, relative to the beginning of the piece,
        /// in leaf units.
        /// Proof size is a number of elements (size same as one leaf) provided in the variable part of a
        /// PieceInclusionProof.
        std::tuple<std::vector<std::tuple<std::size_t, std::size_t>>, std::size_t>
            compute_packing(std::size_t tree_len) {
        }

        bool is_aligned(std::size_t tree_len) {
            return detail::piece_is_aligned(position, leaves_amount, tree_len);
        }

        std::size_t height() {
            return detail::height_for_length(self.number_of_leaves);
        }

        // `proof_length` is length of proof that comm_p is in the containing root, excluding comm_p and root, which
        // aren't needed for the proof itself.
        std::size_t proof_length(std::size_t tree_len) {
            return detail::height_for_length(tree_len) - self.height();
        }

        fr32_array comm_p;
        std::size_t position;
        std::size_t leaves_amount;
    };

    /// Generate `comm_p` from a source and return it as bytes.
    template<typename Hash, typename Read>
    fr32_array generate_piece_commitment_bytes_from_source(Read &source, std::size_t padded_piece_size) {
        assert(padded_piece_size > 32, "piece is too small");
        assert(padded_piece_size % 32 == 0, "piece is not valid size");

        std::array<std::uint32_t, NODE_SIZE> buf;
        buf.fill(0);

        std::size_t parts = std::ceil(static_cast<double>(padded_piece_size) / static_case<double>(NODE_SIZE));

        let tree = BinaryMerkleTree::<H>::try_from_iter(
                       (0..parts).map(| _ |
                                      {
                                          source.read_exact(&mut buf) ? ;
                                          <H::Domain as Domain>::try_from_bytes(&buf).context("invalid Fr element")
                                      }))
                       .context("failed to build tree") ?
            ;

        std::array<std::uint32_t, NODE_SIZE> comm_p_bytes;
        comm_p_bytes.fill(0);
        auto comm_p = tree.root();
        comm_p.write_bytes(comm_p_bytes);
    }
}    // namespace filecoin

#endif
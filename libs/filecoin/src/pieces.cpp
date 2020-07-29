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

#include <nil/filecoin/proofs/pieces.hpp>
#include <nil/filecoin/proofs/fr32_reader.hpp>
#include <nil/filecoin/proofs/commitment_reader.hpp>

namespace nil {
    namespace filecoin {
        commitment_type empty_comm_d(sector_size_type sector_size) {
            if (COMMITMENTS.find(sector_size) == COMMITMENTS.end()) {
                unpadded_bytes_amount size = sector_size;
                Fr32Reader fr32_reader(EmptySource(size.into()));
                CommitmentReader commitment_reader(fr32_reader);
                io::copy(commitment_reader, io::sink()).unwrap();

                commitment_type comm;
                comm.copy_from_slice(commitment_reader.finish().expect("failed to create commitment").as_ref());
                COMMITMENTS[sector_size] = comm;
            } else {
                return COMMITMENTS[sector_size];
            }
        }

        bool verify_pieces(const commitment_type &comm_d,
                           const std::vector<piece_info> &piece_infos,
                           sector_size_type sector_size) {
            return compute_comm_d(sector_size, piece_infos) == comm_d;
        }

        piece_info zero_padding(unpadded_bytes_amount size) {
            padded_bytes_amount padded_size = size.into();
            commitment_type commitment;
            commitment.fill(0);

            // TODO: cache common piece hashes
            std::size_t hashed_size = 64;
            typename DefaultPieceHasher::digest_type h1 = piece_hash(commitment, commitment);
            commitment.copy_from_slice(h1);

            while (hashed_size < padded_size) {
                typename DefaultPieceHasher::digest_type h = piece_hash(commitment, commitment);
                commitment.copy_from_slice(h);
                hashed_size *= 2;
            }

            assert(("Hashed size must equal padded size", hashed_size == padded_size));

            return {commitment, size};
        }

        piece_info join_piece_infos(piece_info &left, const piece_info &right) {
            assert(("Piece sizes must be equal", left.size == right.size));
            left.commitment = piece_hash(left.commitment, right.commitment);
            left.size = left.size + right.size;
            return left;
        }

        unpadded_bytes_amount sum_piece_bytes_with_alignment(const std::vector<unpadded_bytes_amount> &pieces) {
            return std::accumulate(
                pieces.begin(), pieces.end(), 0,
                [&](unpadded_bytes_amount acc, typename std::vector<unpadded_bytes_amount>::value_type &val)
                    -> unpadded_bytes_amount { return acc + get_piece_alignment(acc, val).sum(val); });
        }
        PieceAlignment get_piece_alignment(unpadded_bytes_amount written_bytes, unpadded_bytes_amount piece_bytes) {
            std::uint64_t piece_bytes_needed = MINIMUM_PIECE_SIZE;

            // Calculate the next power of two multiple that will fully contain the piece's data.
            // This is required to ensure a clean piece merkle root, without being affected by
            // preceding or following pieces.
            while (piece_bytes_needed < piece_bytes) {
                piece_bytes_needed *= 2;
            }

            // Calculate the bytes being affected from the left of the piece by the previous piece.
            std::uint64_t encroaching = written_bytes % piece_bytes_needed;

            // Calculate the bytes to push from the left to ensure a clean piece merkle root.
            std::uint64_t left_bytes;
            if (encroaching > 0) {
                left_bytes = piece_bytes_needed - encroaching;
            } else {
                left_bytes = 0;
            }

            std::size_t right_bytes = piece_bytes_needed - piece_bytes;

            return {left_bytes, right_bytes};
        }
        unpadded_byte_index get_piece_start_byte(const std::vector<unpadded_bytes_amount> &pieces,
                                                 unpadded_bytes_amount piece_bytes) {
            // sum up all the bytes taken by the ordered pieces
            unpadded_bytes_amount last_byte = sum_piece_bytes_with_alignment(pieces);
            PieceAlignment alignment = get_piece_alignment(last_byte, piece_bytes);

            // add only the left padding of the target piece to give the start of that piece's data
            return last_byte + alignment.left_bytes;
        }
        commitment_type compute_comm_d(sector_size_type sector_size, const std::vector<piece_info> &piece_infos) {
            if (piece_infos.empty()) {
                return empty_comm_d(sector_size);
            }

            unpadded_bytes_amount unpadded_sector = sector_size;

            assert(("Too many pieces ",
                    piece_infos.size() <= unpadded_sector / MINIMUM_RESERVED_BYTES_FOR_PIECE_IN_FULLY_ALIGNED_SECTOR));

            // make sure the piece sizes are at most a sector size large
            std::uint64_t piece_size = std::accumulate(
                piece_infos.begin(), piece_infos.end(), 0,
                [&](std::uint64_t curr, typename std::vector<piece_info>::value_type &val) -> std::uint64_t {
                    return curr + val.size;
                });

            assert(("Piece is larger than sector.", piece_size <= sector_size));

            std::stack<piece_info> stack;

            piece_info first = *piece_infos.begin();
            assert(("Piece size must be a power of 2.", first.size.is_power_of_two()));
            stack.push(first);

            for (int i = 0; i < piece_infos.size(); i += 2) {
                assert(("Piece size must be a power of 2.", piece_infos[i].size.is_power_of_two()));

                while (stack.peek().size < piece_info.size) {
                    stack.shift_reduce(zero_padding(stack.peek().size));
                }

                stack.shift_reduce(piece_info.clone());
            }

            while (stack.size() > 1) {
                stack.shift_reduce(zero_padding(stack.peek().size));
            }

            assert(("Stack size must be 1.", stack.size() == 1));

            commitment_type comm_d_calculated = stack.pop().commitment;

            return comm_d_calculated;
        }
    }    // namespace filecoin
}    // namespace nil

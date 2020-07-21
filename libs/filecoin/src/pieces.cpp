//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
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

#include <nil/filecoin/proofs/pieces.hpp>

namespace nil {
    namespace filecoin {
        commitment_type empty_comm_d(sector_size_type sector_size) {
            let map = &mut * COMMITMENTS.lock().unwrap();

            *map.entry(sector_size).or_insert_with(|| {
                unpadded_bytes_amount size = sector_size;
                let fr32_reader = Fr32Reader::new (EmptySource::new (size.into()));
                let mut commitment_reader = CommitmentReader::new (fr32_reader);
                io::copy(&mut commitment_reader, &mut io::sink()).unwrap();

                commitment_type comm;
                comm.copy_from_slice(commitment_reader.finish().expect("failed to create commitment").as_ref(), );
                return comm;
            })
        }
        bool verify_pieces(const commitment_type &comm_d,
                           const std::vector<piece_info> &piece_infos,
                           sector_size_type sector_size) {
            return compute_comm_d(sector_size, piece_infos) == comm_d;
        }
        piece_info zero_padding(unpadded_bytes_amount size) {
            padded_bytes_amount padded_size = size.into();
            commitment_type commitment = [0u8; 32];

            // TODO: cache common piece hashes
            std::size_t hashed_size = 64;
            let h1 = piece_hash(&commitment, &commitment);
            commitment.copy_from_slice(h1.as_ref());

            while (hashed_size < padded_size) {
                let h = piece_hash(&commitment, &commitment);
                commitment.copy_from_slice(h.as_ref());
                hashed_size *= 2;
            }

            assert(("Hashed size must equal padded size", hashed_size == padded_size));

            return {commitment, size};
        }
        piece_info join_piece_infos(const piece_info &left, const piece_info &right) {
            assert(("Piece sizes must be equal", left.size == right.size));
            let h = piece_hash(&left.commitment, &right.commitment);

            left.commitment.copy_from_slice(AsRef::<[u8]>::as_ref(&h));
            left.size = left.size + right.size;
            return left;
        }
        unpadded_bytes_amount sum_piece_bytes_with_alignment(const std::vector<unpadded_bytes_amount> &pieces) {
            pieces.iter().fold(0, | acc,
                               piece_bytes | {acc + get_piece_alignment(acc, *piece_bytes).sum(*piece_bytes)});
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
            info !("verifying {} pieces", piece_infos.size());
            if (piece_infos.empty()) {
                return empty_comm_d(sector_size);
            }

            unpadded_bytes_amount unpadded_sector = sector_size.into();

            assert(("Too many pieces ",
                    piece_infos.size() <= unpadded_sector / MINIMUM_RESERVED_BYTES_FOR_PIECE_IN_FULLY_ALIGNED_SECTOR));

            // make sure the piece sizes are at most a sector size large
            std::uint64_t piece_size = piece_infos.iter().map(| info | info.size).sum();

            assert(("Piece is larger than sector.", piece_size <= sector_size));

            let mut stack = Stack::new ();

            let first = piece_infos.first().unwrap().clone();
            ensure !(u64::from(PaddedBytesAmount::from(first.size)).is_power_of_two(),
                     "Piece size ({:?}) must be a power of 2.",
                     PaddedBytesAmount::from(first.size));
            stack.shift(first);

            for (const piece_info &piece_info : piece_infos.iter().skip(1)) {
                ensure !(u64::from(PaddedBytesAmount::from(piece_info.size)).is_power_of_two(),
                         "Piece size ({:?}) must be a power of 2.",
                         PaddedBytesAmount::from(piece_info.size));

                while (stack.peek().size < piece_info.size) {
                    stack.shift_reduce(zero_padding(stack.peek().size));
                }

                stack.shift_reduce(piece_info.clone());
            }

            while (stack.size() > 1) {
                stack.shift_reduce(zero_padding(stack.peek().size));
            }

            ensure !(stack.len() == 1, "Stack size ({}) must be 1.", stack.len());

            commitment_type comm_d_calculated = stack.pop() ?.commitment;

            return comm_d_calculated;
        }
    }    // namespace filecoin
}    // namespace nil

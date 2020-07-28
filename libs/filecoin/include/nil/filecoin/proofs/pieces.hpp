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

#ifndef FILECOIN_PROOFS_PIECES_HPP
#define FILECOIN_PROOFS_PIECES_HPP

#include <unordered_map>

#include <nil/filecoin/storage/proofs/core/fr32.hpp>
#include <nil/filecoin/storage/proofs/core/utilities.hpp>

#include <nil/filecoin/proofs/types/sector_size.hpp>
#include <nil/filecoin/proofs/types/piece_info.hpp>

namespace nil {
    namespace filecoin {
        static std::unordered_map<sector_size_type, commitment_type> COMMITMENTS;

        struct EmptySource {
            std::size_t read(std::vector<std::uint8_t> &target) {
                std::size_t to_read = std::min(size, target.size());
                size -= to_read;
                for (std::uint8_t &val : target) {
                    val = 0;
                }

                return to_read;
            }

            std::size_t size;
        };

        commitment_type empty_comm_d(sector_size_type sector_size);

        commitment_type compute_comm_d(sector_size_type sector_size, const std::vector<piece_info> &piece_infos);

        /// Verify that the provided `piece_infos` and `comm_d` match.
        bool verify_pieces(const commitment_type &comm_d, const std::vector<piece_info> &piece_infos,
                           sector_size_type sector_size);

        /// Stack used for piece reduction.
        struct Stack(Vec<piece_info>);

        impl Stack {
            /// Creates a new stack.
            fn new ()
                ->Self {Stack(Vec::new ())}

            /// Pushes a single element onto the stack.
            fn shift(&mut self, el
                     : piece_info) {self .0.push(el)}

            /// Look at the last element of the stack.
            fn peek(&self)
                ->&piece_info {&self .0 [self .0.len() - 1]}

            /// Look at the second to last element of the stack.
            fn peek2(&self)
                ->&piece_info {&self .0 [self .0.len() - 2]}

            /// Pop the last element of the stack.
            fn pop(&mut self)
                ->Result<piece_info> {self .0.pop().context("empty stack popped")}

            fn reduce1(&mut self)
                ->Result<bool> {
                if (self.size() < 2) {
                    return Ok(false);
                }

                if (self.peek().size == self.peek2().size) {
                    let right = self.pop() ? ;
                    let left = self.pop() ? ;
                    let joined = join_piece_infos(left, right) ? ;
                    self.shift(joined);
                    return Ok(true);
                }

                Ok(false)
            }

            fn reduce(&mut self)->Result<()> {
                while
                    self.reduce1() ? {
                    }
                Ok(())
            }

            fn shift_reduce(&mut self, piece : piece_info)->Result<()> {
                self.shift(piece);
                self.reduce()
            }

            fn len(&self)->usize {
                self .0.len()
            }
        }

        /// Create a padding `piece_info` of size `size`.
        piece_info zero_padding(unpadded_bytes_amount size);

        /// Join two equally sized `piece_info`s together, by hashing them and adding their sizes.
        piece_info join_piece_infos(const piece_info &left, const piece_info &right);

        template<typename FirstInputIterator, typename SecondInputIterator, typename PieceHash = DefaultPieceHasher>
        typename PieceHash::digest_type piece_hash(FirstInputIterator ffirst, FirstInputIterator flast,
                                                   SecondInputIterator sfirst, SecondInputIterator slast) {
            let mut buf = [0u8; NODE_SIZE * 2];
            buf[..NODE_SIZE].copy_from_slice(a);
            buf[NODE_SIZE..].copy_from_slice(b);
            <DefaultPieceHasher as Hasher>::Function::hash(&buf)
        }

        struct PieceAlignment {
            unpadded_bytes_amount sum(unpadded_bytes_amount piece_size) {
                return left_bytes + piece_size + right_bytes;
            }

            unpadded_bytes_amount left_bytes;
            unpadded_bytes_amount right_bytes;
        };

        /// Given a list of pieces, sum the number of bytes taken by those pieces in that order.
        unpadded_bytes_amount sum_piece_bytes_with_alignment(const std::vector<unpadded_bytes_amount> &pieces);

        /// Given a number of bytes already written to a staged sector (ignoring bit padding) and a number
        /// of bytes (before bit padding) to be added, return the alignment required to create a piece where
        /// len(piece) == len(sector size)/(2^n) and sufficient left padding to ensure simple merkle proof
        /// construction.
        PieceAlignment get_piece_alignment(unpadded_bytes_amount written_bytes,
                                           unpadded_bytes_amount piece_bytes);    // namespace filecoin

        /// Given a list of pieces, find the byte where a given piece does or would start.
        unpadded_byte_index get_piece_start_byte(const std::vector<unpadded_bytes_amount> &pieces,
                                                 unpadded_bytes_amount piece_bytes);

        /// Wraps a Readable source with null bytes on either end according to a provided PieceAlignment.
        template<typename Read>
        Read with_alignment(const Read &source, const PieceAlignment &piece_alignment) {
            PieceAlignment piece_alignment {left_bytes, right_bytes};

            let left_padding = Cursor::new (vec ![0; left_bytes.into()]);
            let right_padding = Cursor::new (vec ![0; right_bytes.into()]);

            left_padding.chain(source).chain(right_padding)
        }

        /// Given an enumeration of pieces in a staged sector and a piece to be added (represented by a Read
        /// and corresponding length, in UnpaddedBytesAmount) to the staged sector, produce a new Read and
        /// UnpaddedBytesAmount pair which includes the appropriate amount of alignment bytes for the piece
        /// to be written to the target staged sector.
        template<typename Read>
        std::tuple<unpadded_bytes_amount, PieceAlignment, Read>
            get_aligned_source(const Read &source, std::vector<unpadded_bytes_amount> &pieces,
                               unpadded_bytes_amount piece_bytes) {
            std::size_t written_bytes = sum_piece_bytes_with_alignment(pieces);
            PieceAlignment piece_alignment = get_piece_alignment(written_bytes, piece_bytes);
            unpadded_bytes_amount expected_num_bytes_written =
                piece_alignment.left_bytes + piece_bytes + piece_alignment.right_bytes;

            return std::make_tuple(expected_num_bytes_written, piece_alignment.clone(),
                                   with_alignment(source, piece_alignment));
        }
    }    // namespace filecoin
}    // namespace nil

#endif
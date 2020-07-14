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

#ifndef FILECOIN_COMMITMENT_READER_HPP
#define FILECOIN_COMMITMENT_READER_HPP

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/filecoin/proofs/constants.hpp>

namespace nil {
    namespace filecoin {
        namespace proofs {
            template<typename R>
            struct CommitmentReader<R> {
                /// Attempt to generate the next hash, but only if the buffers are full.
                void try_hash() {
                    if (buffer_pos < 63) {
                        return;
                    }

                    // WARNING: keep in sync with DefaultPieceHasher and its .node impl
                    typename DefaultPieceHasher::digest_type hash = crypto3::hash<DefaultPieceHasher>(buffer);
                    current_tree.push(hash);
                    buffer_pos = 0;

                    // TODO: reduce hashes when possible, instead of keeping them around.
                }

                typename DefaultPieceHasher::digest_type finish() {
                    assert(("not enough inputs provided", buffer_pos == 0));

                    let CommitmentReader {current_tree, ..} = self;

                    let mut current_row = current_tree;

                    while (current_row.size() > 1) {
                        let next_row =
                            current_row.par_chunks(2)
                                .map(| chunk | crate::pieces::piece_hash(chunk[0].as_ref(), chunk[1].as_ref()))
                                .collect::<Vec<_>>();

                        current_row = next_row;
                    }
                    debug_assert_eq !(current_row.len(), 1);

                    return current_row.into_iter().next().unwrap();
                }

                void read(std::vector<std::uint8_t> &buf) {
                    let start = buffer_pos;
                    let left = 64 - buffer_pos;
                    let end = start + std::min(left, buf.size());

                    // fill the buffer as much as possible
                    let r = source.read(&mut self.buffer[start..end]) ? ;

                    // write the data, we read
                    buf[..r].copy_from_slice(&buffer[start..start + r]);

                    buffer_pos += r;

                    // try to hash
                    try_hash();

                    Ok(r)
                }

                R source;
                std::array<std::uint8_t, 64> buffer;
                std::size_t buffer_pos;
                std::vector<typename DefaultPieceHasher::digest_type> current_tree;
            };
        }    // namespace proofs
    }        // namespace filecoin
}    // namespace nil

#endif

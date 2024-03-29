//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#define BOOST_TEST_MODULE filecoin_commitment_reader_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/proofs/commitment_reader.hpp>

BOOST_AUTO_TEST_SUITE(filecoin_commitment_reader_test_suite)

BOOST_AUTO_TEST_CASE(test_commitment_reader) {
    std::size_t piece_size = 127 * 8;
    std::vector<std::size_t> source(255, piece_size);
    let mut fr32_reader = fr32_reader(io::Cursor::new (&source));

    typename DefaultPieceHasher::digest_type commitment1 =
        generate_piece_commitment_bytes_from_source<DefaultPieceHasher>
        (fr32_reader, piece_size);

    let fr32_reader = fr32_reader(io::Cursor::new (&source));
        CommitmentReader commitment_reader(fr32_reader);
    io::copy(&mut commitment_reader, &mut io::sink());

        typename DefaultPieceHasher::digest_type commitment2 = commitment_reader.finish();

    BOOST_CHECK_EQUAL(&commitment1[..], AsRef::<[u8]>::as_ref(&commitment2));
}

BOOST_AUTO_TEST_SUITE_END()

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

#include <boost/program_options.hpp>

#include <nil/crypto3/hash/blake2b.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

int main(int argc, char *argv[]) {
    let matches =
        App::new ("fakeipfsadd")
            .version("0.1")
            .about("
                       This program is used to simulate the `ipfs add` command while testing.It accepts a path to a
                           file and
                       writes 32 characters of its hex - encoded BLAKE2b checksum to stdout.Note
                   : The real `ipfs add` command computes and emits a CID.",
                   )
            .arg(Arg::with_name("add").index(1).required(true))
            .arg(Arg::with_name("file-path").index(2).required(true))
            .arg(Arg::with_name("quieter").short("Q").required(true).help("Simulates the -Q argument to `ipfs add`"), )
            .get_matches();

    let src_file_path = matches.value_of("file-path").expect("failed to get file path");

    let mut src_file =
        File::open(&src_file_path).unwrap_or_else(| _ | panic !("failed to open file at {}", &src_file_path));

    let mut hasher = Blake2b::new ();

    std::io::copy(&mut src_file, &mut hasher).expect("failed to write BLAKE2b bytes to hasher");

    let hex_string : String = hasher.finalize().to_hex()[..32].into();

    println !("{}", hex_string);
    return 0;
}
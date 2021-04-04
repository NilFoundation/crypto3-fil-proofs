//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nemo@nil.foundation>
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

#include <vector>

#include <boost/filesystem/path.hpp>
#include <boost/interprocess/managed_mapped_file.hpp>

#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <nil/actor/core/file.hh>

namespace nil {
    namespace filecoin {
        template<typename CurveType>
        struct r1cs_gg_ppzksnark_mapped_scheme_params {
            typedef CurveType curve_type;
            typedef typename curve_type::g1_type g1_type;

            typedef typename crypto3::zk::snark::r1cs_gg_ppzksnark<CurveType>::verifying_key_type verifying_key_type;
            typedef typename crypto3::zk::snark::r1cs_gg_ppzksnark<CurveType>::processed_verifying_key_type
                processed_verifying_key_type;

            /// The parameter file we're reading from.
            boost::filesystem::path param_file_path;
            /// The file descriptor we have mmaped.
            actor::file_desc param_file;
            /// The actual mmap.
            boost::interprocess::managed_mapped_file params;

            /// This is always loaded (i.e. not lazily loaded).
            verifying_key_type vk;
            processed_verifying_key_type pvk;

            /// Elements of the form ((tau^i * t(tau)) / delta) for i between 0 and
            /// m-2 inclusive. Never contains points at infinity.
            std::vector<std::size_t> h;

            /// Elements of the form (beta * u_i(tau) + alpha v_i(tau) +
            /// w_i(tau)) / delta for all auxiliary inputs. Variables can never
            /// be unconstrained, so this never contains points at infinity.
            std::vector<std::size_t> l;

            /// QAP "A" polynomials evaluated at tau in the Lagrange basis. Never contains
            /// points at infinity: polynomials that evaluate to zero are omitted from
            /// the CRS and the prover can deterministically skip their evaluation.
            std::vector<std::size_t> a;

            /// QAP "B" polynomials evaluated at tau in the Lagrange basis. Needed in
            /// G1 and G2 for C/B queries, respectively. Never contains points at
            /// infinity for the same reason as the "A" polynomials.
            std::vector<std::size_t> b_g1;
            std::vector<std::size_t> b_g2;

            bool checked;
        };
    }    // namespace filecoin
}    // namespace nil

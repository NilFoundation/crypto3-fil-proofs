//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nemo@nil.foundation>

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

#include <boost/filesystem/path.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>

namespace nil {
    namespace filecoin {
        template<typename SchemeType>
        struct scheme_params {
            typedef SchemeType scheme_type;
        };

        template<typename CurveType>
        struct scheme_params<crypto3::zk::snark::r1cs_gg_ppzksnark<CurveType>> {
            typedef CurveType curve_type;
            typedef typename curve_type::template g1_type<> g1_type;

            typedef crypto3::zk::snark::r1cs_gg_ppzksnark<CurveType> scheme_type;
            typedef typename scheme_type::verifying_key_type verifying_key_type;

            verifying_key_type vk;

            // Elements of the form ((tau^i * t(tau)) / delta) for i between 0 and
            // m-2 inclusive. Never contains points at infinity.
            std::vector<typename g1_type::value_type> h;

            // Elements of the form (beta * u_i(tau) + alpha v_i(tau) + w_i(tau)) / delta
            // for all auxiliary inputs. Variables can never be unconstrained, so this
            // never contains points at infinity.
            std::vector<typename g1_type::value_type> l;

            // QAP "A" polynomials evaluated at tau in the Lagrange basis. Never contains
            // points at infinity: polynomials that evaluate to zero are omitted from
            // the CRS and the prover can deterministically skip their evaluation.
            std::vector<typename g1_type::value_type> a;

            // QAP "B" polynomials evaluated at tau in the Lagrange basis. Needed
            // in G1 and G2 for C/B queries, respectively. Never contains points at
            // infinity for the same reason as the "A" polynomials.
            std::vector<typename g1_type::value_type> b_g1;
            std::vector<typename g1_type::value_type> b_g2;
        };
    }    // namespace filecoin
}    // namespace nil

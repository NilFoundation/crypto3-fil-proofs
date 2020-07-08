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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_HPP

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/params.hpp>

namespace nil {
    namespace filecoin {
        template<typename H, typename G>
        struct PoRep {
            type Tau;
            type ProverAux;

            fn replicate(pub_params
                         : &'a Self::PublicParams, replica_id
                         : &H::Domain, data
                         : Data <'a>, data_tree
                         : Option<BinaryMerkleTree<G>>, config
                         : StoreConfig, replica_path
                         : PathBuf, )
                ->Result<(Self::Tau, Self::ProverAux)>;

            fn extract_all(pub_params
                           : &'a Self::PublicParams, replica_id
                           : &H::Domain, replica
                           : &[u8], config
                           : Option<StoreConfig>, )
                ->Result<Vec<u8>>;

            fn extract(pub_params
                       : &'a Self::PublicParams, replica_id
                       : &H::Domain, replica
                       : &[u8], node
                       : usize, config
                       : Option<StoreConfig>, )
                ->Result<Vec<u8>>;
        }
    }    // namespace filecoin
}    // namespace nil

#endif
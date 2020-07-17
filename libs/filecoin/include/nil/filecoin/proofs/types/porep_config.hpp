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

#ifndef FILECOIN_PROOFS_TYPES_POREP_CONFIG_HPP
#define FILECOIN_PROOFS_TYPES_POREP_CONFIG_HPP

#include <boost/filesystem/path.hpp>

#include <nil/filecoin/storage/proofs/core/parameter_cache.hpp>

#include <nil/filecoin/proofs/types/porep_proof_partitions.hpp>
#include <nil/filecoin/proofs/types/sector_size.hpp>

namespace nil {
    namespace filecoin {
        struct porep_config {
            typedef std::uint64_t sector_size;

            sector_size ss;
            porep_proof_partitions partitions;
            std::array<std::uint8_t, 32> porep_id;

            /// Returns the cache identifier as used by `storage-proofs::paramater_cache`.
            template<typename MerkleTreeType>
            std::string get_cache_identifier() {
                let params = parameters::public_params<MerkleTreeType>(sector_size.into(), partitions.into(), porep_id);

                Ok(<StackedCompound<MerkleTreeType, DefaultPieceHasher> as CacheableParameters<
                       StackedCircuit<Tree, DefaultPieceHasher>, _, >>::cache_identifier(&params));
            }

            template<typename MerkleTreeType>
            boost::filesystem::path get_cache_metadata_path() {
                return parameter_cache_metadata_path(get_cache_identifier<MerkleTreeType>());
            }

            template<typename MerkleTreeType>
            boost::filesystem::path get_cache_verifying_key_path() {
                return parameter_cache_verifying_key_path(get_cache_identifier<MerkleTreeType>());
            }    // namespace filecoin

            template<typename MerkleTreeType>
            boost::filesystem::path get_cache_params_path() {
                return parameter_cache_params_path(get_cache_identifier<MerkleTreeType>());
            }    // namespace filecoin
        };       // namespace filecoin
    }            // namespace filecoin
}    // namespace nil

#endif
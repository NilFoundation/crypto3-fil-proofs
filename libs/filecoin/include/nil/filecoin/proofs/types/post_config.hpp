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

#ifndef FILECOIN_PROOFS_TYPES_POST_CONFIG_HPP
#define FILECOIN_PROOFS_TYPES_POST_CONFIG_HPP

#include <nil/filecoin/storage/proofs/core/parameter_cache.hpp>

#include <nil/filecoin/proofs/types/sector_size.hpp>

namespace nil {
    namespace filecoin {
        enum class post_type { Winning, Window };

        struct post_config {
            sector_size_type ss;
            std::size_t challenge_count;
            std::size_t sector_count;
            post_type typ;
            /// High priority (always runs on GPU) == true
            bool priority;

            padded_bytes_amount padded_sector_size() {
                return ss;
            }

            unpadded_bytes_amount unpadded_sector_size() {
                return ss;
            }

            /// Returns the cache identifier as used by `storage-proofs::paramater_cache`.
            template<typename MerkleTreeType>
            std::string get_cache_identifier() {
                if (typ == post_type::Winning) {
                    let params = crate::parameters::winning_post_public_params<MerkleTreeType>(*this);

                    return <fallback::FallbackPoStCompound<MerkleTreeType> as CacheableParameters<
                        fallback::FallbackPoStCircuit<MerkleTreeType>, _, >>::cache_identifier(&params);
                } else if (typ == post_type::Window) {
                    let params = crate::parameters::window_post_public_params<MerkleTreeType>(*this);

                    return <fallback::FallbackPoStCompound<MerkleTreeType> as CacheableParameters<
                        fallback::FallbackPoStCircuit<MerkleTreeType>, _, >>::cache_identifier(&params);
                }
            }    // namespace nil

            template<typename MerkleTreeType>
            boost::filesystem::path get_cache_metadata_path() {
                return parameter_cache_metadata_path(get_cache_identifier<MerkleTreeType>());
            }    // namespace nil

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
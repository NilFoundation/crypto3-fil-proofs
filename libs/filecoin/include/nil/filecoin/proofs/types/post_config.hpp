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

#ifndef FILECOIN_PROOFS_TYPES_POST_CONFIG_HPP
#define FILECOIN_PROOFS_TYPES_POST_CONFIG_HPP

#include <nil/filecoin/proofs/types/sector_size.hpp>

namespace nil {
    namespace filecoin {
        enum class post_type { Winning, Window };

        struct post_config {
            sector_size ss;
            std::size_t challenge_count;
            std::size_t sector_count;
            post_type typ;
            /// High priority (always runs on GPU) == true
            bool priority;

            padded_bytes_amount padded_sector_size() {PaddedBytesAmount::from(self.sector_size)}

            unpadded_bytes_amount unpadded_sector_size() {
                PaddedBytesAmount::from(self.sector_size).into()
            }

            /// Returns the cache identifier as used by `storage-proofs::paramater_cache`.
            template<typename MerkleTreeType>
            std::string get_cache_identifier() {
                match self.typ {
                    PoStType::Winning = > {
                        let params = crate::parameters::winning_post_public_params::<Tree>(self) ? ;

                        Ok(<fallback::FallbackPoStCompound<Tree> as CacheableParameters<
                               fallback::FallbackPoStCircuit<Tree>, _, >>::cache_identifier(&params), )
                    }
                    PoStType::Window = > {
                        let params = crate::parameters::window_post_public_params::<Tree>(self) ? ;

                        Ok(<fallback::FallbackPoStCompound<Tree> as CacheableParameters<
                               fallback::FallbackPoStCircuit<Tree>, _, >>::cache_identifier(&params), )
                    }
                }    // namespace filecoin
            }        // namespace nil

            template<typename MerkleTreeType>
            boost::filesystem::path get_cache_metadata_path() {
                let id = self.get_cache_identifier::<Tree>() ? ;
                Ok(parameter_cache::parameter_cache_metadata_path(&id))
            }    // namespace nil

            template<typename MerkleTreeType>
            boost::filesystem::path get_cache_verifying_key_path() {
                let id = self.get_cache_identifier::<Tree>() ? ;
                Ok(parameter_cache::parameter_cache_verifying_key_path(&id))
            }    // namespace filecoin

            template<typename MerkleTreeType>
            boost::filesystem::path get_cache_params_path() {
                let id = self.get_cache_identifier::<Tree>() ? ;
                Ok(parameter_cache::parameter_cache_params_path(&id))
            }    // namespace filecoin
        };       // namespace filecoin
    }            // namespace filecoin
}    // namespace nil

#endif
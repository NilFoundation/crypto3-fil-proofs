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

#ifndef FILECOIN_PROOFS_PARAMETERS_HPP
#define FILECOIN_PROOFS_PARAMETERS_HPP

#include <nil/filecoin/storage/proofs/post/fallback/vanilla.hpp>

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/params.hpp>

#include <nil/filecoin/proofs/types/bytes_amount.hpp>
#include <nil/filecoin/proofs/types/post_config.hpp>

#include <nil/filecoin/proofs/constants.hpp>

namespace nil {
    namespace filecoin {
        typedef post::fallback::SetupParams WinningPostSetupParams;
        typedef post::fallback::PublicParams WinningPostPublicParams;

        typedef post::fallback::SetupParams WindowPostSetupParams;
        typedef post::fallback::PublicParams WindowPostPublicParams;

        template<typename MerkleTreeType>
        stacked::vanilla::PublicParams<MerkleTreeType> public_params(padded_bytes_amount sector_bytes,
                                                                     std::size_t partitions,
                                                                     const std::array<std::uint8_t, 32> &porep_id) {
            return StackedDrg<MerkleTreeType, DefaultPieceHasher>::setup(
                stacked::vanilla::SetupParams(sector_bytes, partitions, porep_id));
        }

        template<typename MerkleTreeType>
        WinningPostPublicParams winning_post_public_params(const post_config &config) {
            return post::fallback::FallbackPoSt<MerkleTreeType>::setup(WinningPostSetupParams(config));
        }

        WinningPostSetupParams winning_post_setup_params(const post_config &config) {
            assert(("sector count must divide challenge count", config.challenge_count % config.sector_count == 0));

            std::size_t param_sector_count = config.challenge_count / config.sector_count;
            std::size_t param_challenge_count = config.challenge_count / param_sector_count;

            assert(("invalid parameters calculated",
                    param_sector_count * param_challenge_count == config.challenge_count));

            return post::fallback::SetupParams {config.padded_sector_size(), param_challenge_count, param_sector_count};
        }

        template<typename MerkleTreeType>
        WindowPostPublicParams window_post_public_params(post_config &config) {
            return post::fallback::FallbackPoSt<MerkleTreeType>::setup(WindowPostSetupParams(config));
        }

        WindowPostSetupParams window_post_setup_params(post_config &config) {
            return post::fallback::SetupParams {config.padded_sector_size(), config.challenge_count,
                                                config.sector_count};
        }

        stacked::vanilla::SetupParams setup_params(padded_bytes_amount sector_bytes, std::size_t partitions,
                                                   const std::array<std::uint8_t, 32> &porep_id) {
            let layer_challenges =
                select_challenges(partitions,
                                  *POREP_MINIMUM_CHALLENGES.read()
                                       .unwrap()
                                       .get(&u64::from(sector_bytes))
                                       .expect("unknown sector size") as usize,
                                  *LAYERS.read().unwrap().get(&u64::from(sector_bytes)).expect("unknown sector size"));
            assert(("sector_bytes must be a multiple of 32", !sector_bytes % 32));

            return stacked::vanilla::SetupParams {(sector_bytes / 32), DRG_DEGREE, EXP_DEGREE, porep_id,
                                                  layer_challenges};
        }

        stacked::vanilla::LayerChallenges select_challenges(std::size_t partitions,
                                                            std::size_t minimum_total_challenges, std::size_t layers) {
            std::size_t count = 1;
            stacked::vanilla::LayerChallenges guess(layers, count);
            while (partitions * guess.challenges_count_all() < minimum_total_challenges) {
                count += 1;
                guess = stacked::vanilla::LayerChallenges(layers, count);
            }
            return guess;
        }
    }    // namespace filecoin
}    // namespace nil

#endif
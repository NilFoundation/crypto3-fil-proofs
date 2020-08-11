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

#ifndef FILECOIN_PROOFS_CACHES_HPP
#define FILECOIN_PROOFS_CACHES_HPP

#include <unordered_map>

#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include <nil/filecoin/proofs/parameters.hpp>

namespace nil {
    namespace filecoin {
        using namespace crypto3::zk::snark;

        template<typename Bls12>
        using Bls12GrothParams = groth16::MappedParameters<Bls12>;
        template<typename Bls12>
        using Bls12VerifyingKey = r1cs_ppzksnark_verification_key<Bls12>;

        template<typename T>
        using cache_type = std::unordered_map<std::string, T>;

        typedef Cache<Bls12GrothParams> GrothMemCache;
        typedef Cache<Bls12VerifyingKey> VerifyingKeyMemCache;

        static std::mutex<GrothMemCache> GROTH_PARAM_MEMORY_CACHE;
        static std::mutex<VerifyingKeyMemCache> VERIFYING_KEY_MEMORY_CACHE;

        template<typename CacheType, typename UnaryPredicate>
        inline typename std::enable_if<std::is_same<typename UnaryPredicate::result_type, Bls12GrothParams>::value,
                                       CacheType &>::type
            cache_lookup(std::mutex<CacheType> &cache_ref, const std::string &identifier, UnaryPredicated pred) {
        }

        template<typename UnaryPredicate>
        inline typename std::enable_if<std::is_same<typename UnaryPredicate::result_type, Bls12GrothParams>::value,
                                       Bls12GrothParams>::type
            lookup_groth_params(const std::string &identifier, UnaryPredicate generator) {
            cache_lookup(GROTH_PARAM_MEMORY_CACHE, identifier, generator)
        }

        template<typename UnaryPredicate>
        inline typename std::enable_if<std::is_same<typename UnaryPredicate::result_type, Bls12GrothParams>::value,
                                       Bls12GrothParams>::type
            lookup_verifying_key(const std::string &identifier, UnaryPredicate generator) {
            std::strgin vk_identifier = identifier + "-verifying-key";
            cache_lookup(VERIFYING_KEY_MEMORY_CACHE, vk_identifier, generator)
        }

        template<typename MerkleTreeType>
        Bls12GrothParams &stacked_params(const porep_config &config) {
            stacked::vanilla::PublicParams<MerkleTreeType> public_params = public_params<MerkleTreeType>(
                PaddedBytesAmount::from(config), PoRepProofPartitions::from(config), porep_config.porep_id);

            let parameters_generator = || {<StackedCompound<MerkleTreeType, DefaultPieceHasher>
                                                as CompoundProof<StackedDrg<MerkleTreeType, DefaultPieceHasher>, _, >>::
                                               groth_params::<rand::rngs::OsRng>(None, &public_params)
                                                   .map_err(Into::into)};

            return lookup_groth_params(format !("STACKED[{}]", PaddedBytesAmount::from(config)), parameters_generator);
        }

        template<typename MerkleTreeType>
        Bls12GrothParams &get_post_params(const post_config &config) {
            if (config.typ == PoStType::Winning) {
                WinningPostPublicParams post_public_params = winning_post_public_params<MerkleTreeType>(config);

                let parameters_generator =
                    || {<fallback::FallbackPoStCompound<MerkleTreeType> as CompoundProof<
                           fallback::FallbackPoSt<MerkleTreeType>, fallback::FallbackPoStCircuit<MerkleTreeType>, >>::
                            groth_params::<rand::rngs::OsRng>(None, &post_public_params)
                                .map_err(Into::into)};

                return lookup_groth_params(format !("WINNING_POST[{}]", config.padded_sector_size()),
                                           parameters_generator);
            } else if (config.typ == PoStType::Window) {
                WindowPostPublicParams post_public_params = window_post_public_params<MerkleTreeType>(config);

                let parameters_generator =
                    || {<fallback::FallbackPoStCompound<Tree> as CompoundProof<
                           fallback::FallbackPoSt<MerkleTreeType>, fallback::FallbackPoStCircuit<MerkleTreeType>>>::
                            groth_params::<rand::rngs::OsRng>(None, post_public_params)
                                .map_err(Into::into)};

                return lookup_groth_params(format !("Window_POST[{}]", config.padded_sector_size()),
                                           parameters_generator);
            }
        }

        template<typename MerkleTreeType>
        Bls12VerifyingKey &get_stacked_verifying_key(const porep_config &config) {
            stacked::vanilla::PublicParams<MerkleTreeType> public_params = public_params(
                PaddedBytesAmount::from(porep_config), PoRepProofPartitions::from(porep_config), porep_config.porep_id);

            let vk_generator =
                || {<StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
                       StackedDrg<Tree, DefaultPieceHasher>, _, >>::verifying_key::<rand::rngs::OsRng>(None,
                                                                                                       &public_params)
                        .map_err(Into::into)};

            return lookup_verifying_key(format !("STACKED[{}]", PaddedBytesAmount::from(porep_config)), vk_generator);
        }

        template<typename MerkleTreeType>
        Bls12VerifyingKey &get_post_verifying_key(const porep_config &config) {
            if (config.typ == PoStType::Winning) {
                WinningPostPublicParams post_public_params = winning_post_public_params<MerkleTreeType>(config);

                let vk_generator =
                    || {<fallback::FallbackPoStCompound<MerkleTreeType> as CompoundProof<
                           fallback::FallbackPoSt<MerkleTreeType>, fallback::FallbackPoStCircuit<MerkleTreeType>, >>::
                            verifying_key::<rand::rngs::OsRng>(None, &post_public_params)
                                .map_err(Into::into)};

                return lookup_verifying_key(format !("WINNING_POST[{}]", post_config.padded_sector_size()),
                                            vk_generator);
            } else if (config.typ == PoStType::Window) {
                WindowPostPublicParams post_public_params = window_post_public_params<MerkleTreeType>(config);

                let vk_generator =
                    || {<fallback::FallbackPoStCompound<MerkleTreeType> as CompoundProof<
                           fallback::FallbackPoSt<MerkleTreeType>, fallback::FallbackPoStCircuit<MerkleTreeType>, >>::
                            verifying_key::<rand::rngs::OsRng>(None, &post_public_params)
                                .map_err(Into::into)};

                return lookup_verifying_key(format !("WINDOW_POST[{}]", usize::from(post_config.padded_sector_size())),
                                            vk_generator);
            }
        }
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_CONSTANTS_HPP

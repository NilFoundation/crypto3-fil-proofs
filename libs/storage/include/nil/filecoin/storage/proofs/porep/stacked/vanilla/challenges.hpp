//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>

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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_CHALLENGES_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_CHALLENGES_HPP

#include <vector>
#include <string>

#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <nil/crypto3/detail/pack_numeric.hpp>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

namespace nil {
    namespace filecoin {
        namespace stacked {
            namespace vanilla {
                struct LayerChallenges {
                    /// How many layers we are generating challenges for.
                    std::size_t layers;
                    /// The maximum count of challenges
                    std::size_t max_count;

                    /// Derive all challenges.
                    template<typename Domain>
                    std::vector<std::size_t> derive(std::size_t leaves, Domain &replica_id,
                                                    const std::array<std::uint8_t, 32> &seed, std::uint8_t k) {
                        return derive_internal(max_count, leaves, replica_id, seed, k);
                    }

                    template<typename Domain, typename ChallengeHasher = crypto3::hashes::sha2<256>>
                    std::vector<std::size_t> derive_internal(std::size_t challenges_count, std::size_t leaves,
                                                             Domain &replica_id,
                                                             const std::array<std::uint8_t, 32> &seed, std::uint8_t k) {
                        BOOST_ASSERT_MSG(leaves > 2, "Too few leaves");

                        std::vector<std::size_t> result;

                        for (int i = 0; i < challenges_count; i++) {
                            std::uint32_t j = ((challenges_count * k) + i);

                            crypto3::accumulator_set<ChallengeHasher> acc;

                            crypto3::hash<ChallengeHasher>(replica_id, acc);
                            crypto3::hash<ChallengeHasher>(seed, acc);
                            crypto3::hash<ChallengeHasher>(j, acc);

                            typename ChallengeHasher::digest_type hash =
                                crypto3::accumulators::extract::hash<ChallengeHasher>(acc);

                            boost::endian::native_to_little_inplace(hash);
                            crypto3::multiprecision::cpp_int big_challenge;
                            crypto3::multiprecision::import_bits(big_challenge, hash);

                            result.push_back(static_cast<std::size_t>(big_challenge % (leaves - 1)) + 1);
                        }

                        return result;
                    }
                };

                struct ChallengeRequirements {
                    std::size_t minimum_challenges;
                };
            }    // namespace vanilla
        }        // namespace stacked
    }            // namespace filecoin
}    // namespace nil

#endif

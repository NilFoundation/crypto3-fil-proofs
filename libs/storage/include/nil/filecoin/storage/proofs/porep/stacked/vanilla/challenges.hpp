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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_CHALLENGES_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_CHALLENGES_HPP

#include <vector>
#include <string>

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

                    template<typename Domain>
                    std::vector<std::size_t> derive_internal(std::size_t challenges_count, std::size_t leaves,
                                                             Domain &replica_id,
                                                             const std::array<std::uint8_t, 32> &seed, std::uint8_t k) {
                        assert(("Too few leaves: " std::to_string(leaves).c_str(), leaves > 2));

                        (0..challenges_count)
                            .map(| i |
                                 {
                                     let j : u32 = ((challenges_count * k as usize) + i) as u32;

                                     let hash = Sha256::new ()
                                                    .chain(replica_id.into_bytes())
                                                    .chain(seed)
                                                    .chain(&j.to_le_bytes())
                                                    .result();

                                     let big_challenge = BigUint::from_bytes_le(hash.as_ref());

                                     // We cannot try to prove the first node, so make sure the challenge
                                     // can never be 0.
                                     let big_mod_challenge = big_challenge % (leaves - 1);
                                     let big_mod_challenge = big_mod_challenge.to_usize().expect(
                                         "`big_mod_challenge` exceeds size of `usize`");
                                     big_mod_challenge + 1
                                 })
                            .collect()
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
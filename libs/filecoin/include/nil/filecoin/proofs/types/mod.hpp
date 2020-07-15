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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_MOD_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_MOD_HPP

#include <cstdint>

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/params.hpp>

#include <nil/filecoin/proofs/constants.hpp>

namespace nil {
    namespace filecoin {
        /// Arity for oct trees, used for comm_r_last.
        constexpr static const std::size_t oct_arity = 8;

        /// Arity for binary trees, used for comm_d.
        constexpr static const std::size_t binary_arity = 2;

        typedef std::array<std::uint8_t, 32> commitment_type;
        typedef std::array<std::uint8_t, 32> challenge_seed;
        typedef std::array<std::uint8_t, 32> proved_id;
        typedef std::array<std::uint8_t, 32> ticket_type;

        struct seal_pre_commit_output {
            commitment_type comm_r;
            commitment_type comm_d;
        };

        template<typename MerkleTreeType, typename PieceHasherType = default_piece_hasher_type>
        using vanilla_seal_proof = proof<MerkleTreeType, PieceHasherType>;

        template<typename MerkleTreeType>
        struct seal_commit_phase1_output {
            std::vector<std::vector<vanilla_seal_proof<MerkleTreeType>>> vanilla_proofs;
            commitment_type comm_r;
            commitment_type comm_d;
            typename MerkleTreeType::hash_type::digest_type replica_id;
            ticket_type seed;
            ticket_type tckt;
        };

        struct seal_commit_output {
            std::vector<std::uint8_t> proof;
        };

        template<typename MerkleTreeType>
        struct seal_precommit_phase1_output {
            labels<MerkleTreeType> labels;
            StoreConfig config;
            commitment_type comm_d;
        };
    }    // namespace filecoin
}    // namespace nil

#endif
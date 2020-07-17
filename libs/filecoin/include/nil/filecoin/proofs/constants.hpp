//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020 Gokuyun Moscow Algorithm Lab
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"}, to deal
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

#ifndef FILECOIN_CONSTANTS_HPP
#define FILECOIN_CONSTANTS_HPP

#include <unordered_map>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/filecoin/proofs/param.hpp>

#include <nil/filecoin/proofs/types/bytes_amount.hpp>
#include <nil/filecoin/proofs/types/sector_size.hpp>

#include <nil/filecoin/storage/proofs/core/utilities.hpp>
#include <nil/filecoin/storage/proofs/core/drgraph.hpp>

namespace nil {
    namespace filecoin {
        constexpr static const sector_size_type sector_size_2kb = 1ULL << 11;
        constexpr static const sector_size_type sector_size_4kb = 1ULL << 12;
        constexpr static const sector_size_type sector_size_16kb = 1ULL << 14;
        constexpr static const sector_size_type sector_size_32kb = 1ULL << 15;
        constexpr static const sector_size_type sector_size_8mb = 1ULL << 23;
        constexpr static const sector_size_type sector_size_16mb = 1ULL << 24;
        constexpr static const sector_size_type sector_size_512mb = 1ULL << 29;
        constexpr static const sector_size_type sector_size_1gb = 1ULL << 30;
        constexpr static const sector_size_type sector_size_32gb = 1ULL << 35;
        constexpr static const sector_size_type sector_size_64gb = 1ULL << 36;

        constexpr static const std::size_t winning_post_challenge_count = 66;
        constexpr static const std::size_t winning_post_sector_count = 1;

        constexpr static const std::size_t window_post_challenge_count = 10;

        constexpr static const std::size_t DRG_DEGREE = BASE_DEGREE;
        constexpr static const std::size_t EXP_DEGREE = EXP_DEGREE;

        static parameter_map PARAMETERS =
            serde_json::from_str(include_str !("../parameters.json")).expect("Invalid parameters.json");

        static std::unordered_map<sector_size_type, std::uint64_t> POREP_MINIMUM_CHALLENGES = {
            {sector_size_2kb, 2},    {sector_size_4kb, 2},   {sector_size_16kb, 2},  {sector_size_32kb, 2},
            {sector_size_8mb, 2},    {sector_size_16mb, 2},  {sector_size_512mb, 2}, {sector_size_1gb, 2},
            {sector_size_32gb, 176}, {sector_size_64gb, 176}};

        static std::unordered_map<sector_size_type, std::uint64_t> POREP_PARTITIONS = {
            {sector_size_2kb, 1},   {sector_size_4kb, 1},  {sector_size_16kb, 1},  {sector_size_32kb, 1},
            {sector_size_8mb, 1},   {sector_size_16mb, 1}, {sector_size_512mb, 1}, {sector_size_1gb, 1},
            {sector_size_32gb, 10}, {sector_size_64gb, 10}};

        static std::unordered_map<sector_size_type, std::uint64_t> LAYERS = {
            {sector_size_2kb, 2},   {sector_size_4kb, 2},  {sector_size_16kb, 2},  {sector_size_32kb, 2},
            {sector_size_8mb, 2},   {sector_size_16mb, 2}, {sector_size_512mb, 2}, {sector_size_1gb, 2},
            {sector_size_32gb, 11}, {sector_size_64gb, 11}};

        /*!
         * @brief These numbers must match those used for Window PoSt scheduling in the miner actor.
         * Please coordinate changes with actor code.
         * https://github.com/filecoin-project/specs-actors/blob/master/actors/abi/sector.go
         */
        static std::unordered_map<sector_size_type, std::uint64_t> WINDOW_POST_SECTOR_COUNT = {
            {sector_size_2kb, 2},     {sector_size_4kb, 2},  {sector_size_16kb, 2},  {sector_size_32kb, 2},
            {sector_size_8mb, 2},     {sector_size_16mb, 2}, {sector_size_512mb, 2}, {sector_size_1gb, 2},
            {sector_size_32gb, 2349},    // this gives 125,279,217 constraints, fitting in a single partition
            {sector_size_64gb, 2300}     // this gives 129,887,900 constraints, fitting in a single partition
        };

        /// The size of a single snark proof.
        constexpr static const std::size_t SINGLE_PARTITION_PROOF_LEN = 192;

        constexpr static const std::uint64_t MINIMUM_RESERVED_LEAVES_FOR_PIECE_IN_SECTOR = 4;

        // Bit padding causes bytes to only be aligned at every 127 bytes (for 31.75 bytes).
        constexpr static const std::uint64_t MINIMUM_RESERVED_BYTES_FOR_PIECE_IN_FULLY_ALIGNED_SECTOR =
            (MINIMUM_RESERVED_LEAVES_FOR_PIECE_IN_SECTOR * NODE_SIZE) - 1;

        /// The minimum size a single piece must have before padding.
        constexpr static const unpadded_bytes_amount MIN_PIECE_SIZE = unpadded_bytes_amount(127);

        /// The hasher used for creating comm_d.
        typedef crypto3::hashes::sha2<256> DefaultPieceHasher;
        typedef typename crypto3::hashes::sha2<256>::digest_type DefaultPieceDomain;

        /// The default hasher for merkle trees currently in use.
        typedef crypto3::hashes::poseidon DefaultTreeHasher;
        typedef typename crypto3::hashes::poseidon::digest_type DefaultTreeDomain;

        typedef storage_proofs::merkle::BinaryMerkleTree<DefaultTreeHasher> DefaultBinaryTree;
        typedef storage_proofs::merkle::OctMerkleTree<DefaultTreeHasher> DefaultOctTree;
        typedef storage_proofs::merkle::OctLCMerkleTree<DefaultTreeHasher> DefaultOctLCTree;

        typedef LCTree<DefaultTreeHasher, U8, U0, U0> SectorShape2KiB;
        typedef LCTree<DefaultTreeHasher, U8, U2, U0> SectorShape4KiB;
        typedef LCTree<DefaultTreeHasher, U8, U8, U0> SectorShape16KiB;
        typedef LCTree<DefaultTreeHasher, U8, U8, U2> SectorShape32KiB;
        typedef LCTree<DefaultTreeHasher, U8, U0, U0> SectorShape8MiB;
        typedef LCTree<DefaultTreeHasher, U8, U2, U0> SectorShape16MiB;
        typedef LCTree<DefaultTreeHasher, U8, U0, U0> SectorShape512MiB;
        typedef LCTree<DefaultTreeHasher, U8, U2, U0> SectorShape1GiB;
        typedef LCTree<DefaultTreeHasher, U8, U8, U0> SectorShape32GiB;
        typedef LCTree<DefaultTreeHasher, U8, U8, U2> SectorShape64GiB;

        bool is_sector_shape_base(sector_size_type sector_size) {
            return sector_size == sector_size_2kb || sector_size == sector_size_8mb || sector_size == sector_size_512mb;
        }

        bool is_sector_shape_sub2(sector_size_type sector_size) {
            return sector_size == sector_size_4kb || sector_size == sector_size_16mb || sector_size == sector_size_1gb;
        }

        bool is_sector_shape_sub8(sector_size_type sector_size) {
            return sector_size == sector_size_16kb || sector_size == sector_size_32gb;
        }

        bool is_sector_shape_top2(sector_size_type sector_size) {
            return sector_size == sector_size_32kb || sector_size == sector_size_64gb;
        }

        inline std::string parameter_id(const std::string &cache_id) {
            return std::string("v") + std::to_string(VERSION) + "-" + cache_id + ".params";
        }

        /// Get the correct parameter data for a given cache id.
        inline parameter_data get_parameter_data(const std::string &cache_id) {
            return PARAMETERS[parameter_id(cache_id)];
        }
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_CONSTANTS_HPP

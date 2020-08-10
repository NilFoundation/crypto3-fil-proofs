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

#ifndef FILECOIN_SEAL_API_MOD_HPP
#define FILECOIN_SEAL_API_MOD_HPP

#include <string>

#include <nil/filecoin/storage/proofs/core/sector.hpp>

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/params.hpp>

#include <nil/filecoin/proofs/types/bytes_amount.hpp>
#include <nil/filecoin/proofs/types/piece_info.hpp>
#include <nil/filecoin/proofs/types/porep_config.hpp>
#include <nil/filecoin/proofs/types/mod.hpp>

#include <nil/filecoin/proofs/api/seal.hpp>
#include <nil/filecoin/proofs/api/post.hpp>

namespace nil {
    namespace filecoin {
        /// Unseals the sector at `sealed_path` and returns the bytes for a piece
        /// whose first (unpadded) byte begins at `offset` and ends at `offset` plus
        /// `num_bytes`, inclusive. Note that the entire sector is unsealed each time
        /// this function is called.
        ///
        /// # Arguments
        ///
        /// * `porep_config` - porep configuration containing the sector size.
        /// * `cache_path` - path to the directory in which the sector data's Merkle Tree is written.
        /// * `sealed_path` - path to the sealed sector file that we will unseal and read a byte range.
        /// * `output_path` - path to a file that we will write the requested byte range to.
        /// * `prover_id` - the prover-id that sealed the sector.
        /// * `sector_id` - the sector-id of the sealed sector.
        /// * `comm_d` - the commitment to the sector's data.
        /// * `ticket` - the ticket that was used to generate the sector's replica-id.
        /// * `offset` - the byte index in the unsealed sector of the first byte that we want to read.
        /// * `num_bytes` - the number of bytes that we want to read.
        template<typename MerkleTreeType>
        unpadded_bytes_amount
            get_unsealed_range(const porep_config &config, const boost::filesystem::path &cache_path,
                               const boost::filesystem::path &sealed_path, const boost::filesystem::path &output_path,
                               prover_id_type prover_id, sector_id_type sector_id, const commitment_type &comm_d,
                               const ticket_type &ticket, unpadded_byte_index offset, unpadded_bytes_amount num_bytes) {
            std::ifstream f_in(sealed_path, std::ios::binary);
            std::ofstream f_out(output_path, std::ios::binary);

            return unseal_range<MerkleTreeType>(config, cache_path, f_in, buf_f_out, prover_id, sector_id, comm_d,
                                                ticket, offset, num_bytes);
        }

        /// Unseals the sector read from `sealed_sector` and returns the bytes for a
        /// piece whose first (unpadded) byte begins at `offset` and ends at `offset`
        /// plus `num_bytes`, inclusive. Note that the entire sector is unsealed each
        /// time this function is called.
        ///
        /// # Arguments
        ///
        /// * `porep_config` - porep configuration containing the sector size.
        /// * `cache_path` - path to the directory in which the sector data's Merkle Tree is written.
        /// * `sealed_sector` - a byte source from which we read sealed sector data.
        /// * `unsealed_output` - a byte sink to which we write unsealed, un-bit-padded sector bytes.
        /// * `prover_id` - the prover-id that sealed the sector.
        /// * `sector_id` - the sector-id of the sealed sector.
        /// * `comm_d` - the commitment to the sector's data.
        /// * `ticket` - the ticket that was used to generate the sector's replica-id.
        /// * `offset` - the byte index in the unsealed sector of the first byte that we want to read.
        /// * `num_bytes` - the number of bytes that we want to read.
        template<typename Read, typename Write, typename MerkleTreeType>
        unpadded_bytes_amount unseal_range(const porep_config &config, const boost::filesystem::path &cache_path,
                                           const Read &sealed_sector, const Write &unsealed_output,
                                           const prover_id_type &prover_id, const sector_id_type &sector_id,
                                           const commitment_type &comm_d, const ticket_type &ticket,
                                           unpadded_byte_index offset, unpadded_bytes_amount num_bytes) {
            info !("unseal_range:start");
            assert(("Invalid all zero commitment (comm_d)",
                    !std::accumulate(comm_d.begin(), comm_d.end(), false,
                                     [&](bool state, typename commitment_type::value_type &v) -> bool {
                                         return state * (v != 0);
                                     })));

            commitment_type comm_d = as_safe_commitment<typename DefaultPieceHasher::digest_type>(comm_d, "comm_d");

            replica_id_type replica_id = generate_replica_id<typename MerkleTreeType::hash_type>(
                prover_id, sector_id, ticket, comm_d, config.porep_id);

            std::vector<std::uint8_t> data;
            sealed_sector.read_to_end(&mut data);

            std::size_t base_tree_size = get_base_tree_size<DefaultBinaryTree>(config.sector_size);
            std::size_t base_tree_leafs = get_base_tree_leafs<DefaultBinaryTree>(base_tree_size);
            // MT for original data is always named tree-d, and it will be
            // referenced later in the process as such.
            StoreConfig config =
                StoreConfig(cache_path.as_ref(), cache_key::CommDTree.to_string(),
                            default_rows_to_discard(base_tree_leafs, <DefaultBinaryTree as MerkleTreeTrait>::Arity));
            let pp =
                public_params(PaddedBytesAmount::from(config), PoRepProofPartitions::from(config), config.porep_id);

            padded_bytes_amount offset_padded = unpadded_bytes_amount::from(offset);
            padded_bytes_amount num_bytes_padded = num_bytes;

            let unsealed_all =
                StackedDrg<MerkleTreeType, DefaultPieceHasher>::extract_all(pp, replica_id, data, config);
            std::size_t start = offset_padded;
            std::size_t end = start + num_bytes_padded;
            let unsealed = &unsealed_all[start..end];

            // If the call to `extract_range` was successful, the `unsealed` vector must
            // have a length which equals `num_bytes_padded`. The byte at its 0-index
            // byte will be the the byte at index `offset_padded` in the sealed sector.
            std::size_t written =
                write_unpadded(unsealed, unsealed_output, 0, num_bytes.into()).context("write_unpadded failed");

            info !("unseal_range:finish");
            return written;
        }    // namespace filecoin

        /// Generates a piece commitment for the provided byte source. Returns an error
        /// if the byte source produced more than `piece_size` bytes.
        ///
        /// # Arguments
        ///
        /// * `source` - a readable source of unprocessed piece bytes. The piece's commitment will be
        /// generated for the bytes read from the source plus any added padding.
        /// * `piece_size` - the number of unpadded user-bytes which can be read from source before EOF.
        template<typename Read>
        piece_info generate_piece_commitment(const Read &source, unpadded_bytes_amount piece_size) {
            info !("generate_piece_commitment:start");

            let result = measure_op(
                Operation::GeneratePieceCommitment, || {
                    ensure_piece_size(piece_size);

                    // send the source through the preprocessor
                    let source = std::io::BufReader::new (source);
                    let mut fr32_reader = crate::fr32_reader::Fr32Reader::new (source);

                    let commitment = generate_piece_commitment_bytes_from_source::<DefaultPieceHasher>(
                        fr32_reader, PaddedBytesAmount::from(piece_size).into());

                    return PieceInfo(commitment, piece_size);
                });

            info !("generate_piece_commitment:finish");
            return result;
        }

        /// Computes a NUL-byte prefix and/or suffix for `source` using the provided
        /// `piece_lengths` and `piece_size` (such that the `source`, after
        /// preprocessing, will occupy a subtree of a merkle tree built using the bytes
        /// from `target`), runs the resultant byte stream through the preprocessor,
        /// and writes the result to `target`. Returns a tuple containing the number of
        /// bytes written to `target` (`source` plus alignment) and the commitment.
        ///
        /// WARNING: Depending on the ordering and size of the pieces in
        /// `piece_lengths`, this function could write a prefix of NUL bytes which
        /// wastes ($SIZESECTORSIZE/2)-$MINIMUM_PIECE_SIZE space. This function will be
        /// deprecated in favor of `write_and_preprocess`, and miners will be prevented
        /// from sealing sectors containing more than $TOOMUCH alignment bytes.
        ///
        /// # Arguments
        ///
        /// * `source` - a readable source of unprocessed piece bytes.
        /// * `target` - a writer where we will write the processed piece bytes.
        /// * `piece_size` - the number of unpadded user-bytes which can be read from source before EOF.
        /// * `piece_lengths` - the number of bytes for each previous piece in the sector.
        template<typename Read, typename Write>
        std::tuple<piece_info, unpadded_bytes_amount>
            add_piece(const Read &source, const Write &target, unpadded_bytes_amount piece_size,
                      const std::vector<unpadded_bytes_amount> &piece_lengths) {
            info !("add_piece:start");

            let result = measure_op(
                Operation::AddPiece, || {
                    ensure_piece_size(piece_size);

                    let source = std::io::BufReader::new (source);
                    let mut target = std::io::BufWriter::new (target);

                    std::size_t written_bytes = crate::pieces::sum_piece_bytes_with_alignment(&piece_lengths);
                    let piece_alignment = crate::pieces::get_piece_alignment(written_bytes, piece_size);
                    Fr32Reader fr32_reader(source);

                    // write left alignment
                    for (int i = 0; i < piece_alignment.left_bytes; i++) {
                        target.write_all(&[0u8][..]);
                    }

                    CommitmentReader commitment_reader(fr32_reader);
                    let n = std::io::copy(&mut commitment_reader, &mut target)
                                .context("failed to write and preprocess bytes");

                    assert(("add_piece: read 0 bytes before EOF from source", n != 0));
                    assert(("add_piece: invalid bytes amount written", n == piece_size));

                    // write right alignment
                    for (int i = 0; i < piece_alignment.right_bytes; i++) {
                        target.write_all(&[0u8][..]);
                    }

                    let commitment = commitment_reader.finish();
                    std::array<std::uint8_t, 32> comm;
                    comm.fill(0);
                    comm.copy_from_slice(commitment.as_ref());

                    std::size_t written = piece_alignment.left_bytes + piece_alignment.right_bytes + piece_size;

                    return std::make_tuple(piece_info(comm, n), written);
                });

            info !("add_piece:finish");
            result
        }

        void ensure_piece_size(unpadded_bytes_amount piece_size);

        /// Writes bytes from `source` to `target`, adding bit-padding ("preprocessing")
        /// as needed. Returns a tuple containing the number of bytes written to
        /// `target` and the commitment.
        ///
        /// WARNING: This function neither prepends nor appends alignment bytes to the
        /// `target`; it is the caller's responsibility to ensure properly sized
        /// and ordered writes to `target` such that `source`-bytes occupy whole
        /// subtrees of the final merkle tree built over `target`.
        ///
        /// # Arguments
        ///
        /// * `source` - a readable source of unprocessed piece bytes.
        /// * `target` - a writer where we will write the processed piece bytes.
        /// * `piece_size` - the number of unpadded user-bytes which can be read from source before EOF.
        template<typename Read, typename Write>
        inline std::tuple<piece_info, unpadded_bytes_amount>
            write_and_preprocess(const Read &source, const Write &target, unpadded_bytes_amount piece_size) {
            return add_piece(source, target, piece_size);
        }

        // Verifies if a DiskStore specified by a config (or set of 'required_configs' is consistent).
        void verify_store(StoreConfig &config, std::size_t arity, std::size_t required_configs);

        // Verifies if a LevelCacheStore specified by a config is consistent.
        template<typename MerkleTreeType>
        void verify_level_cache_store(const StoreConfig &config) {
            StoreConfig store_path = StoreConfig::data_path(config.path, config.id);
            if (!boost::filesystem::exists(store_path)) {
                std::size_t required_configs = get_base_tree_count<MerkleTreeType>();

                // Configs may have split due to sector size, so we need to
                // check deterministic paths from here.
                boost::filesystem::path orig_path = store_path;
                std::vector<StoreConfig> configs(required_configs);
                for (int i = 0; i < required_configs; i++) {
                    boost::filesystem::path cur_path =
                        orig_path.clone().replace(".dat", format !("-{}.dat", i).as_str());

                    if (boost::filesystem::exists(cur_path)) {
                        std::string path_str = cur_path.str();
                        std::vector<std::string> tree_names = {"tree-d", "tree-c", "tree-r-last"};
                        for (const std::string &name : tree_names) {
                            if (path_str.find(name).is_some()) {
                                configs.push_back(StoreConfig::from_config(config, format !("{}-{}", name, i), None));
                                break;
                            }
                        }
                    }
                }

                assert(("Missing store file (or associated split paths)", configs.size() == required_configs));

                std::size_t store_len = config.size;
                for (const StoreConfig &config : configs) {
                    assert(LevelCacheStore<DefaultPieceDomain, std::fs::File>::is_consistent(
                        store_len, MerkleTreeType::Arity, &config));
                }
            } else {
                assert(LevelCacheStore<DefaultPieceDomain, std::fs::File>::is_consistent(
                    config.size, MerkleTreeType::Arity, config));
            }
        }

        // Checks for the existence of the tree d store, the replica, and all generated labels.
        template<typename MerkleTreeType>
        seal_precommit_phase1_output<MerkleTreeType> validate_cache_for_precommit_phase2(
            const boost::filesystem::path &cache_path, const boost::filesystem::path &replica_path,
            const seal_precommit_phase1_output<MerkleTreeType> &seal_precommit_phase1_output) {
            info !("validate_cache_for_precommit_phase2:start");

            assert(("Missing replica", boost::filesystem::exists(replica_path)));

            // Verify all stores/labels within the Labels object, but
            // respecting the current cache_path.
            boost::filesystem::path cache = cache_path;
            seal_precommit_phase1_output.labels.verify_stores(verify_store, cache);

            // Update the previous phase store path to the current cache_path.
            StoreConfig config =
                StoreConfig::from_config(seal_precommit_phase1_output.config, seal_precommit_phase1_output.config.id,
                                         seal_precommit_phase1_output.config.size);
            config.path = cache_path;

            seal_precommit_phase1_output result =
                verify_store(config, DefaultBinaryTree::Arity, get_base_tree_count<MerkleTreeType>());

            info !("validate_cache_for_precommit_phase2:finish");
            return result;
        }

        // Checks for the existence of the replica data and t_aux, which in
        // turn allows us to verify the tree d, tree r, tree c, and the
        // labels.
        template<typename MerkleTreeType>
        void validate_cache_for_commit(const boost::filesystem::path &cache_path,
                                       const boost::filesystem::path &replica_path) {
            info !("validate_cache_for_precommit:start");

            // Verify that the replica exists and is not empty.
            assert(("Missing replica", replica_path.as_ref().exists()));

            std::ifstream replica_file(replica_path, std::ios::binary);
            assert(("Replica exists, but is empty!", replica_file.peek() != std::ifstream::traits_type::eof()));

            boost::filesystem::path cache = cache_path;

            // Make sure p_aux exists and is valid.
            boost::filesystem::path p_aux_path = cache / std::to_string(cache_key::PAux);
            std::vector<std::uint8_t> p_aux_bytes =
                std::fs::read(&p_aux_path).with_context(|| format !("could not read file p_aux={:?}", p_aux_path));

            PersistentAux<typename MerkleTreeType::hash_type::digest_type> = deserialize(p_aux_bytes);
            drop(p_aux_bytes);

            // Make sure t_aux exists and is valid.
            boost::filesystem::path t_aux_path = cache / std::to_string(cache_key::TAux);
            std::vector<std::uint8_t> t_aux_bytes =
                std::fs::read(&t_aux_path).with_context(|| format !("could not read file t_aux={:?}", t_aux_path));

            TemporaryAux<MerkleTreeType, DefaultPieceHasher> t_aux = deserialize(t_aux_bytes);

            // Switch t_aux to the passed in cache_path
            t_aux.set_cache_path(cache_path);

            // Verify all stores/labels within the Labels object.
            boost::filesystem::path cache = cache_path;
            t_aux.labels.verify_stores(verify_store, cache);

            // Verify each tree disk store.
            verify_store(t_aux.tree_d_config, DefaultBinaryTree::Arity, get_base_tree_count<MerkleTreeType>());
            verify_store(t_aux.tree_c_config, DefaultOctTree::Arity, get_base_tree_count<MerkleTreeType>());
            verify_level_cache_store<DefaultOctTree>(t_aux.tree_r_last_config);

            info !("validate_cache_for_precommit:finish");
        }    // namespace filecoin
    }        // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_SEAL_HPP

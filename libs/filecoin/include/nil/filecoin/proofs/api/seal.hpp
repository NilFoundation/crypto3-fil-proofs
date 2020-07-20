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

#ifndef FILECOIN_SEAL_API_HPP
#define FILECOIN_SEAL_API_HPP

#include <nil/filecoin/proofs/caches.hpp>

#include <nil/filecoin/proofs/types/mod.hpp>
#include <nil/filecoin/proofs/types/piece_info.hpp>
#include <nil/filecoin/proofs/types/porep_config.hpp>

namespace nil {
    namespace filecoin {
        template<typename MerkleTreeType>
        seal_commit_phase1_output<MerkleTreeType> seal_pre_commit_phase1(const porep_config &config,
                                                                         const boost::filesystem::path &cache_path,
                                                                         const boost::filesystem::path &in_path,
                                                                         const boost::filesystem::path &out_path,
                                                                         prover_id_type prover_id,
                                                                         sector_id_type sector_id,
                                                                         ticket_type ticket,
                                                                         const std::vector<piece_info> &piece_infos) {
            // Sanity check all input path types.
            assert(("in_path must be a file", metadata(in_path.as_ref()).is_file()));
            assert(("out_path must be a file", metadata(out_path.as_ref()).is_file()));
            assert(("cache_path must be a directory", metadata(cache_path.as_ref()).is_dir()));

            std::size_t sector_bytes = PaddedBytesAmount::from(config);
            fs::metadata(&in_path).with_context(||
                                                format !("could not read in_path={:?})", in_path.as_ref().display()));

            fs::metadata(&out_path).with_context(||
                                                 format !("could not read out_path={:?}", out_path.as_ref().display()));

            // Copy unsealed data to output location, where it will be sealed in place.
            fs::copy(&in_path, &out_path)
                .with_context(|| {format !("could not copy in_path={:?} to out_path={:?}",
                                           in_path.as_ref().display(),
                                           out_path.as_ref().display())});

            let f_data = OpenOptions::new ().read(true).write(true).open(&out_path).with_context(
                || format !("could not open out_path={:?}", out_path.as_ref().display()));

            // Zero-pad the data to the requested size by extending the underlying file if needed.
            f_data.set_len(sector_bytes as u64);

            let data = unsafe {MmapOptions::new ().map_mut(&f_data).with_context(
                || format !("could not mmap out_path={:?}", out_path.as_ref().display())) ? };

            compound_proof::SetupParams compound_setup_params = {
                setup_params(PaddedBytesAmount::from(config), PoRepProofPartitions::from(config), config.porep_id),
                PoRepProofPartitions::from(config), false};

            PublicParams<StackedDrg<MerkleTreeType, DefaultPieceHasher>> compound_public_params =
                <StackedCompound<MerkleTreeType, DefaultPieceHasher> as CompoundProof<
                    StackedDrg<MerkleTreeType, DefaultPieceHasher>, _, >>::setup(&compound_setup_params);

            std::tuple<StoreConfig, commitment_type> let(config, comm_d) = measure_op(
                CommD, ||->Result<_> {
                    std::size_t base_tree_size = get_base_tree_size<DefaultBinaryTree>(config.sector_size);
                    let base_tree_leafs = get_base_tree_leafs<DefaultBinaryTree>(base_tree_size);
                    assert(("graph size and leaf size don't match",
                            compound_public_params.vanilla_params.graph.size() == base_tree_leafs));

                    trace !("seal phase 1: sector_size {}, base tree size {}, base tree leafs {}", config.sector_size,
                            base_tree_size, base_tree_leafs);

                    // MT for original data is always named tree-d, and it will be
                    // referenced later in the process as such.
                    let mut config = StoreConfig::new (cache_path.as_ref(), CacheKey::CommDTree.to_string(),
                                                       default_rows_to_discard(base_tree_leafs, BINARY_ARITY));
                    BinaryMerkleTree<DefaultPieceHasher> data_tree =
                        create_base_merkle_tree<BinaryMerkleTree<DefaultPieceHasher>>(Some(config.clone()),
                                                                                      base_tree_leafs, &data);
                    drop(data);

                    config.size = Some(data_tree.size());
                    Fr comm_d_root = data_tree.root().into();
                    commitment_type comm_d = commitment_from_fr(comm_d_root);

                    drop(data_tree);

                    return std::make_tuple(config, comm_d);
                });

            info("verifying pieces");

            assert(("pieces and comm_d do not match", verify_pieces(comm_d, piece_infos, config)));

            auto replica_id = generate_replica_id<typename MerkleTreeType::hash_type>(prover_id, sector_id.into(),
                                                                                      ticket, comm_d, config.porep_id);

            Labels<MerkleTreeType> labels = StackedDrg<MerkleTreeType, DefaultPieceHasher>::replicate_phase1(
                compound_public_params.vanilla_params, replica_id, config.clone());

            seal_precommit_phase1_output<MerkleTreeType> out = {labels, config, comm_d};

            info !("seal_pre_commit_phase1:finish");
            return out;
        }

        template<typename MerkleTreeType>
        seal_precommit_output seal_pre_commit_phase2(const porep_config &config,
                                                     const seal_precommit_phase1_output<MerkleTreeType> &phase1_output,
                                                     const boost::filesystem::path &cache_path,
                                                     const boost::filesystem::path &replica_path) {
            info !("seal_pre_commit_phase2:start");

            // Sanity check all input path types.
            assert(("cache_path must be a directory", metadata(cache_path.as_ref()).is_dir()));
            assert(("replica_path must be a file", metadata(replica_path.as_ref()).is_file()));

            seal_precommit_phase1_output<MerkleTreeType> {labels, config, comm_d, ..} = phase1_output;

            labels.update_root(cache_path.as_ref());
            config.path = cache_path.as_ref().into();

            let f_data =
                OpenOptions::new ()
                    .read(true)
                    .write(true)
                    .open(&replica_path)
                    .with_context(|| {format !("could not open replica_path={:?}", replica_path.as_ref().display())});
            let data = unsafe {MmapOptions::new ().map_mut(&f_data).with_context(
                || {format !("could not mmap replica_path={:?}", replica_path.as_ref().display())})};
            storage_proofs::Data data = (data, PathBuf::from(replica_path.as_ref())).into();

            // Load data tree from disk

            std::size_t base_tree_size = get_base_tree_size<DefaultBinaryTree>(config.sector_size);
            std::size_t base_tree_leafs = get_base_tree_leafs<DefaultBinaryTree>(base_tree_size);

            trace !("seal phase 2: base tree size {}, base tree leafs {}, rows to discard {}",
                    base_tree_size,
                    base_tree_leafs,
                    default_rows_to_discard(base_tree_leafs, BINARY_ARITY));
            assert(("Invalid cache size specified",
                    config.rows_to_discard == default_rows_to_discard(base_tree_leafs, BINARY_ARITY)));

            DiskStore<DefaultPieceDomain> store = DiskStore::new_from_disk(base_tree_size, BINARY_ARITY, config);
            BinaryMerkleTree<DefaultPieceHasher> data_tree =
                BinaryMerkleTree<DefaultPieceHasher>::from_data_store(store, base_tree_leafs);

            compound_proof::SetupParams compound_setup_params = {
                setup_params(config, PoRepProofPartitions::from(config), config.porep_id),
                PoRepProofPartitions::from(config), false};

            PublicParams<StackedDrg<MerkleTreeType, DefaultPieceHasher>> compound_public_params =
                <StackedCompound<Tree, DefaultPieceHasher>
                     as CompoundProof<StackedDrg<Tree, DefaultPieceHasher>, _, >>::setup(&compound_setup_params);

            let(tau, (p_aux, t_aux)) = StackedDrg<MerkleTreeType, DefaultPieceHasher>::replicate_phase2(
                compound_public_params.vanilla_params, labels, data, data_tree, config,
                replica_path.as_ref().to_path_buf());

            commitment_type comm_r = commitment_from_fr(tau.comm_r.into());

            // Persist p_aux and t_aux here
            boost::filesystem::path p_aux_path = cache_path.as_ref().join(CacheKey::PAux.to_string());
            let mut f_p_aux =
                File::create(&p_aux_path).with_context(|| format !("could not create file p_aux={:?}", p_aux_path));
            std::vector<std::uint8_t> p_aux_bytes = serialize(p_aux);
            f_p_aux.write_all(&p_aux_bytes).with_context(|| format !("could not write to file p_aux={:?}", p_aux_path));

            boost::filesystem::path t_aux_path = cache_path.as_ref().join(CacheKey::TAux.to_string());
            let mut f_t_aux =
                File::create(&t_aux_path).with_context(|| format !("could not create file t_aux={:?}", t_aux_path));
            std::vector<std::uint8_t> t_aux_bytes = serialize(t_aux);
            f_t_aux.write_all(&t_aux_bytes).with_context(|| format !("could not write to file t_aux={:?}", t_aux_path));

            info !("seal_pre_commit_phase2:finish");
            return {comm_r, comm_d};
        }    // namespace filecoin

        template<typename MerkleTreeType>
        SealCommitPhase1Output<MerkleTreeType>
            seal_commit_phase1(const porep_config &config, const boost::filesystem::path &cache_path,
                               const boost::filesystem::path &replica_path, prover_id_type prover_id,
                               sector_id_type sector_id, ticket_type ticket, ticket_type seed,
                               const seal_precommit_output &pre_commit, const std::vector<PieceInfo> &piece_infos) {
            info !("seal_commit_phase1:start");

            // Sanity check all input path types.
            assert(("cache_path must be a directory", metadata(cache_path.as_ref()).is_dir()));
            assert(("replica_path must be a file", metadata(replica_path.as_ref()).is_file()));

            let seal_precommit_output {comm_d, comm_r} = pre_commit;

            assert(("Invalid all zero commitment (comm_d)",
                    !std::accumulate(comm_d.begin(), comm_d.end(), false,
                                     [&](bool state, typename commitment_type::value_type &v) -> bool {
                                         return state * (v != 0);
                                     })));
            assert(("Invalid all zero commitment (comm_r)",
                    !std::accumulate(comm_r.begin(), comm_r.end(), false,
                                     [&](bool state, typename commitment_type::value_type &v) -> bool {
                                         return state * (v != 0);
                                     })));
            assert(("pieces and comm_d do not match", verify_pieces(comm_d, piece_infos, config)));

            boost::filesystem::path p_aux_path = cache_path.as_ref().join(CacheKey::PAux.to_string());
            let p_aux_bytes =
                std::fs::read(&p_aux_path).with_context(|| format !("could not read file p_aux={:?}", p_aux_path));

            PersistentAux<typename MerkleTreeType::hash_type::digest_type> p_aux = deserialize(p_aux_bytes);

            boost::filesystem::path t_aux_path = cache_path.as_ref().join(CacheKey::TAux.to_string());
            let t_aux_bytes =
                std::fs::read(&t_aux_path).with_context(|| format !("could not read file t_aux={:?}", t_aux_path));

            TemporaryAux<MerkleTreeType, DefaultPieceHasher> res = deserialize(t_aux_bytes);

            // Switch t_aux to the passed in cache_path
            res.set_cache_path(cache_path);
            TemporaryAux<MerkleTreeType, DefaultPieceHasher> t_aux = res;

            // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
            // elements based on the configs stored in TemporaryAux.
            TemporaryAuxCache<MerkleTreeType, DefaultPieceHasher>
                t_aux_cache(t_aux, replica_path.as_ref().to_path_buf()).context("failed to restore contents of t_aux");

            commitment_type comm_r_safe = as_safe_commitment(comm_r, "comm_r");
            commitment_type comm_d_safe = DefaultPieceDomain::try_from_bytes(comm_d);

            typename MerkleTreeType::hash_type::digest_type replica_id =
                generate_replica_id<typename MerkleTreeType::hash_type>(prover_id, sector_id.into(), ticket,
                                                                        comm_d_safe, config.porep_id);

            stacked::PublicInputs public_inputs = {replica_id, stacked::Tau(comm_d_safe, comm_r_safe), k : None, seed};

            stacked::PrivateInputs<MerkleTreeType, DefaultPieceHasher> private_inputs = {p_aux, t_aux_cache};

            compound_proof::SetupParams compound_setup_params = {
                setup_params(config, PoRepProofPartitions::from(config), config.porep_id),
                PoRepProofPartitions::from(config), false};

            PublicParams<StackedDrg<MerkleTreeType, DefaultPieceHasher>> compound_public_params =
                <StackedCompound<MerkleTreeType, DefaultPieceHasher> as CompoundProof<
                    StackedDrg<MerkleTreeType, DefaultPieceHasher>, _, >>::setup(compound_setup_params);

            std::vector<Proof> vanilla_proofs =
                StackedDrg::prove_all_partitions(compound_public_params.vanilla_params, public_inputs, private_inputs,
                                                 StackedCompound::partition_count(compound_public_params));

            bool sanity_check = StackedDrg<MerkleTreeType, DefaultPieceHasher>::verify_all_partitions(
                compound_public_params.vanilla_params, public_inputs, vanilla_proofs);

            assert(("Invalid vanilla proof generated", sanity_check));

            SealCommitPhase1Output out = {vanilla_proofs, comm_r, comm_d, replica_id, seed, ticket};

            info !("seal_commit_phase1:finish");
            return out;
        }    // namespace nil

        template<typename MerkleTreeType>
        SealCommitOutput seal_commit_phase2(const porep_config &config,
                                            const SealCommitPhase1Output<MerkleTreeType> &phase1_output,
                                            prover_id_type prover_id,
                                            sector_id_type sector_id) {
            info !("seal_commit_phase2:start");

            let SealCommitPhase1Output {
                vanilla_proofs, comm_d, comm_r, replica_id, seed, ticket,
            } = phase1_output;

            assert(("Invalid all zero commitment (comm_d)",
                    !std::accumulate(comm_d.begin(), comm_d.end(), false,
                                     [&](bool state, typename commitment_type::value_type &v) -> bool {
                                         return state * (v != 0);
                                     })));
            assert(("Invalid all zero commitment (comm_r)",
                    !std::accumulate(comm_r.begin(), comm_r.end(), false,
                                     [&](bool state, typename commitment_type::value_type &v) -> bool {
                                         return state * (v != 0);
                                     })));

            commitment_type comm_r_safe = as_safe_commitment(comm_r, "comm_r");
            commitment_type comm_d_safe = DefaultPieceDomain::try_from_bytes(comm_d);

            stacked::PublicInputs public_inputs = {replica_id, stacked::Tau {comm_d_safe, comm_r_safe}, k : None, seed};

            let groth_params = get_stacked_params<MerkleTreeType>(config);

            info !("got groth params ({}) while sealing", u64::from(PaddedBytesAmount::from(config)));

            compound_proof::SetupParams compound_setup_params = {
                setup_params(PaddedBytesAmount::from(config), PoRepProofPartitions::from(config), config.porep_id),
                Some(PoRepProofPartitions::from(config)), false};

            PublicParams<StackedDrg<MerkleTreeType, DefaultPieceHasher>> compound_public_params =
                <StackedCompound<Tree, DefaultPieceHasher>
                     as CompoundProof<StackedDrg<Tree, DefaultPieceHasher>, _, >>::setup(&compound_setup_params);

            info !("snark_proof:start");
            std::vector<Proof<Bls12>> groth_proofs =
                StackedCompound<MerkleTreeType, DefaultPieceHasher>::circuit_proofs(
                    public_inputs, vanilla_proofs, compound_public_params.vanilla_params, groth_params,
                    compound_public_params.priority);
            info !("snark_proof:finish");

            MultiProof proof(groth_proofs, groth_params.vk);

            std::vector<std::uint8_t> buf(SINGLE_PARTITION_PROOF_LEN * PoRepProofPartitions::from(config));

            proof.write(buf);

            // Verification is cheap when parameters are cached,
            // and it is never correct to return a proof which does not verify.
            verify_seal<MerkleTreeType>(porep_config, comm_r, comm_d, prover_id, sector_id, ticket, seed, buf)
                .context("post-seal verification sanity check failed");

            info !("seal_commit_phase2:finish");
            return {buf};
        }

        /// Computes a sectors's `comm_d` given its pieces.
        ///
        /// # Arguments
        ///
        /// * `porep_config` - this sector's porep config that contains the number of bytes in the sector.
        /// * `piece_infos` - the piece info (commitment and byte length) for each piece in this sector.
        commitment_type compute_comm_d(sector_size_type sector_size, const std::vector<piece_info> &piece_infos) {
            info !("compute_comm_d:start");

            commitment_type result = pieces::compute_comm_d(sector_size, piece_infos);

            info !("compute_comm_d:finish");
            return result;
        }

        /// Verifies the output of some previously-run seal operation.
        ///
        /// # Arguments
        ///
        /// * `porep_config` - this sector's porep config that contains the number of bytes in this sector.
        /// * `comm_r_in` - commitment to the sector's replica (`comm_r`).
        /// * `comm_d_in` - commitment to the sector's data (`comm_d`).
        /// * `prover_id` - the prover-id that sealed this sector.
        /// * `sector_id` - this sector's sector-id.
        /// * `ticket` - the ticket that was used to generate this sector's replica-id.
        /// * `seed` - the seed used to derive the porep challenges.
        /// * `proof_vec` - the porep circuit proof serialized into a vector of bytes.
        template<typename MerkleTreeType>
        bool verify_seal(const porep_config &config,
                         const commitment_type &comm_r_in,
                         const commitment_type &comm_d_in,
                         prover_id_type prover_id,
                         sector_id_type sector_id,
                         ticket_type ticket,
                         ticket_tyoe seed,
                         const std::vector<std::uint8_t> &proof_vec) {
            info !("verify_seal:start");
            assert(("Invalid all zero commitment (comm_d)",
                    !std::accumulate(comm_d_in.begin(), comm_d_in.end(), false,
                                     [&](bool state, typename commitment_type::value_type &v) -> bool {
                                         return state * (v != 0);
                                     })));
            assert(("Invalid all zero commitment (comm_r)",
                    !std::accumulate(comm_r_in.begin(), comm_r_in.end(), false,
                                     [&](bool state, typename commitment_type::value_type &v) -> bool {
                                         return state * (v != 0);
                                     })));

            padded_bytes_amount sector_bytes(config);
            typename MerkleTreeType::hash_type::digest_type comm_r = as_safe_commitment(&comm_r_in, "comm_r");
            DefaultPieceDomain comm_d = as_safe_commitment(&comm_d_in, "comm_d");

            replica_id_type replica_id = generate_replica_id<typename MerkleTreeType::hash_type>(
                prover_id, sector_id, ticket, comm_d, config.porep_id);

            compound_proof::SetupParams compound_setup_params = {setup_params(PaddedBytesAmount::from(config),
                                                                              PoRepProofPartitions::from(porep_config),
                                                                              config.porep_id),
                                                                 PoRepProofPartitions::from(config), false};

            compound_proof::PublicParams<StackedDrg<MerkleTreeType, DefaultPieceHasher>> compound_public_params =
                StackedCompound::setup(compound_setup_params);

            stacked::PublicInputs<typename MerkleTreeType::hash_type::digest_type, DefaultPieceDomain> public_inputs
                = {replica_id, Tau {comm_r, comm_d}), seed};

            Bls12VerifyingKey verifying_key = get_stacked_verifying_key<MerkleTreeType>(config);

            info !("got verifying key ({}) while verifying seal", sector_bytes);

            MultiProof proof =
                MultiProof::new_from_reader(Some(PoRepProofPartitions::from(config)), proof_vec, verifying_key);

            bool result = StackedCompound::verify(compound_public_params, public_inputs, proof, ChallengeRequirements {
                              minimum_challenges : *POREP_MINIMUM_CHALLENGES.read()
                                  .unwrap()
                                  .get(&u64::from(SectorSize::from(porep_config)))
                                  .expect("unknown sector size") as usize,
                          })
                              .map_err(Into::into);

            info !("verify_seal:finish");
            return result;
        }

        /// Verifies a batch of outputs of some previously-run seal operations.
        ///
        /// # Arguments
        ///
        /// * `porep_config` - this sector's porep config that contains the number of bytes in this sector.
        /// * `[comm_r_ins]` - list of commitments to the sector's replica (`comm_r`).
        /// * `[comm_d_ins]` - list of commitments to the sector's data (`comm_d`).
        /// * `[prover_ids]` - list of prover-ids that sealed this sector.
        /// * `[sector_ids]` - list of the sector's sector-id.
        /// * `[tickets]` - list of tickets that was used to generate this sector's replica-id.
        /// * `[seeds]` - list of seeds used to derive the porep challenges.
        /// * `[proof_vecs]` - list of porep circuit proofs serialized into a vector of bytes.
        template<typename MerkleTreeType>
        bool verify_batch_seal(const porep_config &config, const std::vector<commitment_type> &comm_r_ins,
                               const std::vector<commitment_type> &comm_d_ins,
                               const std::vector<prover_id_type> &prover_ids,
                               const std::vector<sector_id_type> &sector_ids, const std::vector<ticket_type> &tickets,
                               const std::vector<ticket_type> &seeds,
                               const std::vector<std::vector<std::uint8_t>> &proof_vecs) {
            info !("verify_batch_seal:start");
            assert(("Cannot prove empty batch", !comm_r_ins.empty()));
            std::size_t l = comm_r_ins.size();
            assert(("Inconsistent inputs", l == comm_d_ins.size()));
            assert(("Inconsistent inputs", l == prover_ids.size()));
            assert(("Inconsistent inputs", l == prover_ids.size()));
            assert(("Inconsistent inputs", l == sector_ids.size()));
            assert(("Inconsistent inputs", l == tickets.size()));
            assert(("Inconsistent inputs", l == seeds.size()));
            assert(("Inconsistent inputs", l == proof_vecs.size()));

            for (const commitment_type &comm_d_in : comm_d_ins) {
                assert(("Invalid all zero commitment (comm_d)",
                        !std::accumulate(comm_d_in.begin(), comm_d_in.end(), false,
                                         [&](bool state, typename commitment_type::value_type &v) -> bool {
                                             return state * (v != 0);
                                         })));
            }
            for (const commitment_type &comm_r_in : comm_r_ins) {
                assert(("Invalid all zero commitment (comm_r)",
                        !std::accumulate(comm_r_in.begin(), comm_r_in.end(), false,
                                         [&](bool state, typename commitment_type::value_type &v) -> bool {
                                             return state * (v != 0);
                                         })));
            }

            padded_bytes_amount sector_bytes = PaddedBytesAmount::from(config);

            let verifying_key = get_stacked_verifying_key<MerkleTreeType>(config);
            info !("got verifying key ({}) while verifying seal", sector_bytes);

            compound_proof::SetupParams compound_setup_params = {setup_params(PaddedBytesAmount::from(config),
                                                                              PoRepProofPartitions::from(config),
                                                                              porep_config.porep_id),
                                                                 PoRepProofPartitions::from(config), false};

            compound_proof::PublicParams<StackedDrg<MerkleTreeType, DefaultPieceHasher>> compound_public_params =
                StackedCompound::setup(compound_setup_params);

            std::vector<PublicInputs<typename MerkleTreeType::hash_type::digest_type, DefaultPieceDomain>>
                public_inputs(l);
            std::vector<MultiProof> proofs(l);

            for (int i = 0; i < l; i++) {
                commitment_type comm_r = as_safe_commitment(&comm_r_ins[i], "comm_r");
                commitment_type comm_d = as_safe_commitment(&comm_d_ins[i], "comm_d");

                typename MerkleTreeType::hash_type::digest_type replica_id =
                    generate_replica_id<typename MerkleTreeType::hash_type>(prover_ids[i], sector_ids[i].into(),
                                                                            tickets[i], comm_d, config.porep_id);

                public_inputs.push_back(
                    stacked::PublicInputs<typename MerkleTreeType::hash_type::digest_type, DefaultPieceDomain> {
                        replica_id, {comm_r, comm_d}, seeds[i]});
                proofs.push_back(
                    MultiProof::new_from_reader(PoRepProofPartitions::from(config), proof_vecs[i], verifying_key));
            }

            let result = StackedCompound<MerkleTreeType, DefaultPieceHasher>::batch_verify(
                             compound_public_params, public_inputs, proofs, ChallengeRequirements {
                                 minimum_challenges : *POREP_MINIMUM_CHALLENGES.read()
                                     .unwrap()
                                     .get(&u64::from(SectorSize::from(porep_config)))
                                     .expect("unknown sector size") as usize,
                             })
                             .map_err(Into::into);

            info !("verify_batch_seal:finish");
            return result;
        }

        template<typename MerkleTreeType>
        commitment_type fauxrep(const porep_config &config, const boost::filesystem::path &cache_path,
                                const boost::filesystem::path &out_path) {
            let mut rng = rand::thread_rng();
            return fauxrep_aux(rng, config, cache_path, out_path);
        }

        template<typename MerkleTreeType, typename UniformRandomGenerator>
        commitment_type fauxrep_aux(UniformRandomGenerator &rng, const porep_config &config,
                                    const boost::filesystem::path &cache_path,
                                    const boost::filesystem::path &out_path) {
            std::size_t sector_bytes = PaddedBytesAmount::from(config);

            {
                // Create a sector full of null bytes at `out_path`.
                let file = File::create(out_path);
                file.set_len(sector_bytes);
            }

            typename MerkleTreeType::hash_type::digest_type fake_comm_c = random(rng);
            let(comm_r, p_aux) = StackedDrg<MerkleTreeType, DefaultPieceHasher>::fake_replicate_phase2(
                fake_comm_c, out_path, cache_path, sector_bytes);

            let p_aux_path = cache_path.as_ref().join(CacheKey::PAux.to_string());
            let mut f_p_aux =
                File::create(p_aux_path).with_context(|| format !("could not create file p_aux={:?}", p_aux_path));
            let p_aux_bytes = serialize(p_aux);
            f_p_aux.write_all(p_aux_bytes).with_context(|| format !("could not write to file p_aux={:?}", p_aux_path));

            std::array<std::uint8_t, 32> commitment;
            commitment.fill(0);
            commitment[..].copy_from_slice(&comm_r.into_bytes()[..]);
            return commitment;
        }
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_SEAL_HPP

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
            info("seal_pre_commit_phase1:start");

            // Sanity check all input path types.
            assert(("in_path must be a file", metadata(in_path.as_ref()).is_file()));
            assert(("out_path must be a file", metadata(out_path.as_ref()).is_file()));
            assert(("cache_path must be a directory", metadata(cache_path.as_ref()).is_dir()));

            std::size_t sector_bytes = PaddedBytesAmount::from(porep_config);
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

                setup_params(PaddedBytesAmount::from(porep_config), PoRepProofPartitions::from(porep_config),
                             porep_config.porep_id),
                partitions : Some(PoRepProofPartitions::from(porep_config)),
                priority : false
            };

            let compound_public_params =
                <StackedCompound<Tree, DefaultPieceHasher>
                     as CompoundProof<StackedDrg<Tree, DefaultPieceHasher>, _, >>::setup(&compound_setup_params) ?
                ;

            info !("building merkle tree for the original data");
            let(config, comm_d) = measure_op(
                CommD, ||->Result<_> {
                    let base_tree_size = get_base_tree_size::<DefaultBinaryTree>(porep_config.sector_size) ? ;
                    let base_tree_leafs = get_base_tree_leafs::<DefaultBinaryTree>(base_tree_size) ? ;
                    ensure !(compound_public_params.vanilla_params.graph.size() == base_tree_leafs,
                             "graph size and leaf size don't match");

                    trace !("seal phase 1: sector_size {}, base tree size {}, base tree leafs {}",
                            u64::from(porep_config.sector_size), base_tree_size, base_tree_leafs, );

                    // MT for original data is always named tree-d, and it will be
                    // referenced later in the process as such.
                    let mut config = StoreConfig::new (cache_path.as_ref(), CacheKey::CommDTree.to_string(),
                                                       default_rows_to_discard(base_tree_leafs, BINARY_ARITY), );
                    let data_tree = create_base_merkle_tree<BinaryMerkleTree<DefaultPieceHasher>>(
                        Some(config.clone()), base_tree_leafs, &data);
                    drop(data);

                    config.size = Some(data_tree.len());
                    let comm_d_root : Fr = data_tree.root().into();
                    let comm_d = commitment_from_fr(comm_d_root);

                    drop(data_tree);

                    return std::make_tuple(config, comm_d);
                });

            info("verifying pieces");

            ensure !(verify_pieces(&comm_d, piece_infos, porep_config.into()), "pieces and comm_d do not match");

            let replica_id = generate_replica_id<typename MerkleTreeType::hash_type>(
                prover_id, sector_id.into(), ticket, comm_d, porep_config.porep_id);

            let labels = StackedDrg<MerkleTreeType, DefaultPieceHasher>::replicate_phase1(
                &compound_public_params.vanilla_params, &replica_id, config.clone());

            SealPreCommitPhase1Output out = {labels, config, comm_d};

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

            let SealPreCommitPhase1Output {mut labels, mut config, comm_d, ..} = phase1_output;

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

            std::size_t base_tree_size = get_base_tree_size<DefaultBinaryTree>(porep_config.sector_size);
            std::size_t base_tree_leafs = get_base_tree_leafs<DefaultBinaryTree>(base_tree_size);

            trace !("seal phase 2: base tree size {}, base tree leafs {}, rows to discard {}",
                    base_tree_size,
                    base_tree_leafs,
                    default_rows_to_discard(base_tree_leafs, BINARY_ARITY));
            assert(("Invalid cache size specified",
                    config.rows_to_discard == default_rows_to_discard(base_tree_leafs, BINARY_ARITY)));

            DiskStore<DefaultPieceDomain> store = DiskStore::new_from_disk(base_tree_size, BINARY_ARITY, &config);
            BinaryMerkleTree<DefaultPieceHasher> data_tree =
                BinaryMerkleTree<DefaultPieceHasher>::from_data_store(store, base_tree_leafs);

            compound_proof::SetupParams compound_setup_params = {
                setup_params(porep_config, PoRepProofPartitions::from(porep_config), porep_config.porep_id),
                PoRepProofPartitions::from(porep_config), false};

            let compound_public_params =
                <StackedCompound<Tree, DefaultPieceHasher>
                     as CompoundProof<StackedDrg<Tree, DefaultPieceHasher>, _, >>::setup(&compound_setup_params);

            let(tau, (p_aux, t_aux)) = StackedDrg<MerkleTreeType, DefaultPieceHasher>::replicate_phase2(
                compound_public_params.vanilla_params, labels, data, data_tree, config,
                replica_path.as_ref().to_path_buf());

            let comm_r = commitment_from_fr(tau.comm_r.into());

            // Persist p_aux and t_aux here
            let p_aux_path = cache_path.as_ref().join(CacheKey::PAux.to_string());
            let mut f_p_aux =
                File::create(&p_aux_path).with_context(|| format !("could not create file p_aux={:?}", p_aux_path)) ?
                ;
            let p_aux_bytes = serialize(&p_aux) ? ;
            f_p_aux.write_all(&p_aux_bytes)
                .with_context(|| format !("could not write to file p_aux={:?}", p_aux_path)) ?
                ;

            let t_aux_path = cache_path.as_ref().join(CacheKey::TAux.to_string());
            let mut f_t_aux =
                File::create(&t_aux_path).with_context(|| format !("could not create file t_aux={:?}", t_aux_path)) ?
                ;
            let t_aux_bytes = serialize(&t_aux) ? ;
            f_t_aux.write_all(&t_aux_bytes)
                .with_context(|| format !("could not write to file t_aux={:?}", t_aux_path)) ?
                ;

            let out = SealPreCommitOutput {comm_r, comm_d};

            info !("seal_pre_commit_phase2:finish");
            return out;
        }    // namespace filecoin

        template<typename MerkleTreeType>
        SealCommitPhase1Output<MerkleTreeType>
            seal_commit_phase1(const porep_config &config, , const boost::filesystem::path &cache_path,
                               const boost::filesystem::path &replica_path, prover_id_type prover_id,
                               sector_id_type sector_id, ticket_type ticket, ticket_type seed,
                               SealPreCommitOutput pre_commit, const std::vector<PieceInfo> &piece_infos) {
            info !("seal_commit_phase1:start");

            // Sanity check all input path types.
            assert(("cache_path must be a directory", metadata(cache_path.as_ref()).is_dir()));
            assert(("replica_path must be a file", metadata(replica_path.as_ref()).is_file()));

            let SealPreCommitOutput {comm_d, comm_r} = pre_commit;

            ensure !(comm_d != [0; 32], "Invalid all zero commitment (comm_d)");
            ensure !(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");
            ensure !(verify_pieces(&comm_d, piece_infos, porep_config.into()), "pieces and comm_d do not match");

            let p_aux = { let p_aux_path = cache_path.as_ref().join(CacheKey::PAux.to_string());
            let p_aux_bytes =
                std::fs::read(&p_aux_path).with_context(|| format !("could not read file p_aux={:?}", p_aux_path));

            deserialize(&p_aux_bytes)
        };

        let t_aux = { let t_aux_path = cache_path.as_ref().join(CacheKey::TAux.to_string());
        let t_aux_bytes =
            std::fs::read(&t_aux_path).with_context(|| format !("could not read file t_aux={:?}", t_aux_path));

        let mut res : TemporaryAux<_, _> = deserialize(&t_aux_bytes);

        // Switch t_aux to the passed in cache_path
        res.set_cache_path(cache_path);
        res
    };    // namespace filecoin

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
    // elements based on the configs stored in TemporaryAux.
    TemporaryAuxCache<MerkleTreeType, DefaultPieceHasher>
        t_aux_cache(t_aux, replica_path.as_ref().to_path_buf()).context("failed to restore contents of t_aux");

    let comm_r_safe = as_safe_commitment(comm_r, "comm_r");
    let comm_d_safe = DefaultPieceDomain::try_from_bytes(comm_d);

    let replica_id = generate_replica_id<typename MerkleTreeType::hash_type>(prover_id, sector_id.into(), ticket,
                                                                             comm_d_safe, porep_config.porep_id);

    stacked::PublicInputs public_inputs = {replica_id, stacked::Tau(comm_d_safe, comm_r_safe), k : None, seed};

    stacked::PrivateInputs<MerkleTreeType, DefaultPieceHasher> private_inputs = {p_aux, t_aux_cache};

    compound_proof::SetupParams compound_setup_params = {
        setup_params(porep_config, PoRepProofPartitions::from(porep_config), porep_config.porep_id),
        PoRepProofPartitions::from(porep_config), false};

    let compound_public_params =
        <StackedCompound<MerkleTreeType, DefaultPieceHasher>
             as CompoundProof<StackedDrg<MerkleTreeType, DefaultPieceHasher>, _, >>::setup(&compound_setup_params);

    let vanilla_proofs =
        StackedDrg::prove_all_partitions(compound_public_params.vanilla_params, public_inputs, private_inputs,
                                         StackedCompound::partition_count(compound_public_params));

    let sanity_check = StackedDrg<MerkleTreeType, DefaultPieceHasher>::verify_all_partitions(
        compound_public_params.vanilla_params, public_inputs, &vanilla_proofs);

    ensure !(sanity_check, "Invalid vanilla proof generated");

    let out = SealCommitPhase1Output {vanilla_proofs, comm_r, comm_d, replica_id, seed, ticket};

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

    ensure !(comm_d != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure !(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");

    let comm_r_safe = as_safe_commitment(&comm_r, "comm_r") ? ;
    let comm_d_safe = DefaultPieceDomain::try_from_bytes(&comm_d) ? ;

    let public_inputs = stacked::PublicInputs {
        replica_id,
        tau : Some(stacked::Tau {
            comm_d : comm_d_safe,
            comm_r : comm_r_safe,
        }),
        k : None,
        seed,
    };

    let groth_params = get_stacked_params::<Tree>(porep_config) ? ;

    info !("got groth params ({}) while sealing", u64::from(PaddedBytesAmount::from(porep_config)));

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params : setup_params(PaddedBytesAmount::from(porep_config),
                                      usize::from(PoRepProofPartitions::from(porep_config)), porep_config.porep_id, ) ?
        ,
        partitions :
        Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority : false,
    };

    let compound_public_params =
        <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<StackedDrg<Tree, DefaultPieceHasher>, _, >>::setup(
            &compound_setup_params) ?
        ;

    info !("snark_proof:start");
    let groth_proofs = StackedCompound::<Tree, DefaultPieceHasher>::circuit_proofs(
        &public_inputs, vanilla_proofs, &compound_public_params.vanilla_params, &groth_params,
        compound_public_params.priority, ) ?
        ;
    info !("snark_proof:finish");

    let proof = MultiProof::new (groth_proofs, &groth_params.vk);

    let mut buf =
        Vec::with_capacity(SINGLE_PARTITION_PROOF_LEN * usize::from(PoRepProofPartitions::from(porep_config)), );

    proof.write(&mut buf) ? ;

    // Verification is cheap when parameters are cached,
    // and it is never correct to return a proof which does not verify.
    verify_seal::<Tree>(porep_config, comm_r, comm_d, prover_id, sector_id, ticket, seed, &buf, )
        .context("post-seal verification sanity check failed") ?
        ;

    let out = SealCommitOutput {proof : buf};

    info !("seal_commit_phase2:finish");
    Ok(out)
}

/// Computes a sectors's `comm_d` given its pieces.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in the sector.
/// * `piece_infos` - the piece info (commitment and byte length) for each piece in this sector.
pub fn compute_comm_d(sector_size : SectorSize, piece_infos : &[PieceInfo])->Result<Commitment> {
    info !("compute_comm_d:start");

    let result = pieces::compute_comm_d(sector_size, piece_infos);

    info !("compute_comm_d:finish");
    result
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
#[allow(clippy::too_many_arguments)]
pub fn verify_seal<Tree: 'static + MerkleTreeTrait>(
porep_config: PoRepConfig,
comm_r_in: Commitment,
comm_d_in: Commitment,
prover_id: ProverId,
sector_id: SectorId,
ticket: Ticket,
seed: Ticket,
proof_vec: &[u8],
) -> Result<bool> {
    info !("verify_seal:start");
    ensure !(comm_d_in != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure !(comm_r_in != [0; 32], "Invalid all zero commitment (comm_r)");

    let sector_bytes = PaddedBytesAmount::from(porep_config);
    let comm_r : <Tree::Hasher as Hasher>::Domain = as_safe_commitment(&comm_r_in, "comm_r") ? ;
    let comm_d : DefaultPieceDomain = as_safe_commitment(&comm_d_in, "comm_d") ? ;

    let replica_id =
        generate_replica_id::<Tree::Hasher, _>(&prover_id, sector_id.into(), &ticket, comm_d, &porep_config.porep_id, );

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params : setup_params(PaddedBytesAmount::from(porep_config),
                                      usize::from(PoRepProofPartitions::from(porep_config)), porep_config.porep_id, ) ?
        ,
        partitions :
        Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority : false,
    };

    let compound_public_params : compound_proof::PublicParams<'_, StackedDrg<'_, Tree, DefaultPieceHasher>,
                                 > = StackedCompound::setup(&compound_setup_params) ?
        ;

    let public_inputs = stacked::PublicInputs:: << Tree::Hasher as Hasher > ::Domain, DefaultPieceDomain > {
        replica_id,
        tau : Some(Tau {comm_r, comm_d}),
        seed,
        k : None,
    };

    let verifying_key = get_stacked_verifying_key::<Tree>(porep_config) ? ;

    info !("got verifying key ({}) while verifying seal", u64::from(sector_bytes));

    let proof = MultiProof::new_from_reader(Some(usize::from(PoRepProofPartitions::from(porep_config))), proof_vec,
                                            &verifying_key, ) ?
        ;

    let result = StackedCompound::verify(&compound_public_params, &public_inputs, &proof, &ChallengeRequirements {
                     minimum_challenges : *POREP_MINIMUM_CHALLENGES.read()
                         .unwrap()
                         .get(&u64::from(SectorSize::from(porep_config)))
                         .expect("unknown sector size") as usize,
                 }, )
                     .map_err(Into::into);

    info !("verify_seal:finish");
    result
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
#[allow(clippy::too_many_arguments)]
pub fn verify_batch_seal<Tree: 'static + MerkleTreeTrait>(
porep_config: PoRepConfig,
comm_r_ins: &[Commitment],
comm_d_ins: &[Commitment],
prover_ids: &[ProverId],
sector_ids: &[SectorId],
tickets: &[Ticket],
seeds: &[Ticket],
proof_vecs: &[&[u8]],
) -> Result<bool> {
    info !("verify_batch_seal:start");
    ensure !(!comm_r_ins.is_empty(), "Cannot prove empty batch");
    let l = comm_r_ins.len();
    ensure !(l == comm_d_ins.len(), "Inconsistent inputs");
    ensure !(l == prover_ids.len(), "Inconsistent inputs");
    ensure !(l == prover_ids.len(), "Inconsistent inputs");
    ensure !(l == sector_ids.len(), "Inconsistent inputs");
    ensure !(l == tickets.len(), "Inconsistent inputs");
    ensure !(l == seeds.len(), "Inconsistent inputs");
    ensure !(l == proof_vecs.len(), "Inconsistent inputs");

for
    comm_d_in in comm_d_ins {
        ensure !(comm_d_in != &[0; 32], "Invalid all zero commitment (comm_d)");
    }
for
    comm_r_in in comm_r_ins {
        ensure !(comm_r_in != &[0; 32], "Invalid all zero commitment (comm_r)");
    }

let sector_bytes = PaddedBytesAmount::from(porep_config);

let verifying_key = get_stacked_verifying_key::<Tree>(porep_config) ? ;
info !("got verifying key ({}) while verifying seal", u64::from(sector_bytes));

let compound_setup_params = compound_proof::SetupParams {
    vanilla_params : setup_params(PaddedBytesAmount::from(porep_config),
                                  usize::from(PoRepProofPartitions::from(porep_config)), porep_config.porep_id, ) ?
    ,
    partitions :
    Some(usize::from(PoRepProofPartitions::from(porep_config))),
    priority : false,
};

let compound_public_params : compound_proof::PublicParams<'_, StackedDrg<'_, Tree, DefaultPieceHasher>,
                             > = StackedCompound::setup(&compound_setup_params);

let mut public_inputs = Vec::with_capacity(l);
let mut proofs = Vec::with_capacity(l);

for
    i in 0..l {
        let comm_r = as_safe_commitment(&comm_r_ins[i], "comm_r") ? ;
        let comm_d = as_safe_commitment(&comm_d_ins[i], "comm_d") ? ;

        let replica_id = generate_replica_id::<Tree::Hasher, _>(&prover_ids[i], sector_ids[i].into(), &tickets[i],
                                                                comm_d, &porep_config.porep_id, );

        public_inputs.push(stacked::PublicInputs:: << Tree::Hasher as Hasher > ::Domain, DefaultPieceDomain, > {
            replica_id,
            tau : Some(Tau {comm_r, comm_d}),
            seed : seeds[i],
            k : None,
        });
proofs.push(MultiProof::new_from_reader(
    Some(usize::from(PoRepProofPartitions::from(porep_config))),
    proof_vecs[i],
    &verifying_key,
)?);
    }

let result = StackedCompound::<Tree, DefaultPieceHasher>::batch_verify(
                 &compound_public_params, &public_inputs, &proofs, &ChallengeRequirements {
                     minimum_challenges : *POREP_MINIMUM_CHALLENGES.read()
                         .unwrap()
                         .get(&u64::from(SectorSize::from(porep_config)))
                         .expect("unknown sector size") as usize,
                 }, )
                 .map_err(Into::into);

info !("verify_batch_seal:finish");
result
}

pub fn fauxrep<R: AsRef<Path>, S: AsRef<Path>, Tree: 'static + MerkleTreeTrait>(
porep_config: PoRepConfig,
cache_path: R,
out_path: S,
) -> Result<Commitment> {
    let mut rng = rand::thread_rng();
    fauxrep_aux::<_, R, S, Tree>(&mut rng, porep_config, cache_path, out_path)
}

pub fn fauxrep_aux<Rng : rand::Rng, R : AsRef<Path>, S : AsRef<Path>, Tree : 'static + MerkleTreeTrait, >(mut rng
                                                                                                          : &mut Rng,
                                                                                                            porep_config
                                                                                                          : PoRepConfig,
                                                                                                            cache_path
                                                                                                          : R, out_path
                                                                                                          : S, )
    ->Result<Commitment> {
    let sector_bytes = PaddedBytesAmount::from(porep_config) .0;

    {
        // Create a sector full of null bytes at `out_path`.
        let file = File::create(&out_path) ? ;
        file.set_len(sector_bytes) ? ;
    }

    let fake_comm_c = <Tree::Hasher as Hasher>::Domain::random(&mut rng);
    let(comm_r, p_aux) = StackedDrg::<Tree, DefaultPieceHasher>::fake_replicate_phase2(
        fake_comm_c, out_path, &cache_path, sector_bytes as usize, ) ?
        ;

    let p_aux_path = cache_path.as_ref().join(CacheKey::PAux.to_string());
    let mut f_p_aux =
        File::create(&p_aux_path).with_context(|| format !("could not create file p_aux={:?}", p_aux_path)) ?
        ;
    let p_aux_bytes = serialize(&p_aux) ? ;
    f_p_aux.write_all(&p_aux_bytes).with_context(|| format !("could not write to file p_aux={:?}", p_aux_path)) ? ;

    let mut commitment = [0u8; 32];
    commitment[..].copy_from_slice(&comm_r.into_bytes()[..]);
    Ok(commitment)
}
}
}

#endif    // FILECOIN_SEAL_HPP

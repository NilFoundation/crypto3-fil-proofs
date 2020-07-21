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

#ifndef FILECOIN_SEAL_API_POST_HPP
#define FILECOIN_SEAL_API_POST_HPP

#include <nil/filecoin/storage/proofs/core/btree/map.hpp>

#include <nil/filecoin/proofs/api/utilities.hpp>

#include <nil/filecoin/proofs/types/post_config.hpp>

#include <nil/filecoin/proofs/parameters.hpp>

namespace nil {
    namespace filecoin {
        /// The minimal information required about a replica, in order to be able to generate
        /// a PoSt over it.
        template<typename MerkleTreeType>
        struct PrivateReplicaInfo {
            PrivateReplicaInfo(const boost::filesystem::path &replica, const commitment_type &comm_r,
                               const boost::filesystem::path &cache_dir) :
                cache_dir(cache_dir),
                replica(replica), comm_r(comm_r) {
                assert(("Invalid all zero commitment (comm_r)",
                        !std::accumulate(comm_r.begin(), comm_r.end(), false,
                                         [&](bool state, typename commitment_type::value_type &v) -> bool {
                                             return state * (v != 0);
                                         })));

                let f_aux_path = cache_dir.join(CacheKey::PAux.to_string());
                let aux_bytes =
                    std::fs::read(&f_aux_path).with_context(|| format !("could not read from path={:?}", f_aux_path));

                aux = deserialize(aux_bytes);

                assert(("Sealed replica does not exist", replica.exists()));
            }

            boost::filesystem::path cache_dir_path() const {
                return cache_dir.as_path();
            }

            boost::filesystem::path replica_path() const {
                return replica.as_path();
            }

            typename MerkleTreeType::hash_type::digest_type safe_comm_r() const {
                return as_safe_commitment(comm_r, "comm_r");
            }

            typename MerkleTreeType::hash_type::digest_type safe_comm_c() const {
                return aux.comm_c;
            }

            typename MerkleTreeType::hash_type::digest_type safe_comm_r_last() const {
                return aux.comm_r_last;
            }

            /// Generate the merkle tree of this particular replica.
            MerkleTreeWrapper<typename MerkleTreeType::hash_type, MerkleTreeType::Store, MerkleTreeType::Arity,
                              MerkleTreeType::SubTreeArity, MerkleTreeType::TopTreeArity>
                merkle_tree(sector_size_type sector_size) {
                std::size_t base_tree_size = get_base_tree_size<MerkleTreeType>(sector_size);
                std::size_t base_tree_leafs = get_base_tree_leafs<MerkleTreeType>(base_tree_size);
                trace !("post: base tree size {}, base tree leafs {}, rows_to_discard {}, arities [{}, {}, {}]",
                        base_tree_size, base_tree_leafs,
                        default_rows_to_discard(base_tree_leafs, MerkleTreeType::Arity), MerkleTreeType::Arity,
                        MerkleTreeType::SubTreeArity, MerkleTreeType::TopTreeArity);

                StoreConfg config(cache_dir_path(), CacheKey::CommRLastTree.to_string(),
                                  default_rows_to_discard(base_tree_leafs, MerkleTreeType::Arity));
                config.size = Some(base_tree_size);

                std::size_t tree_count = get_base_tree_count<MerkleTreeType>();
                let(configs, replica_config) =
                    split_config_and_replica(config, replica_path().to_path_buf(), base_tree_leafs, tree_count);

                return create_tree<MerkleTreeType>(base_tree_size, configs, replica_config);
            }

            /// Path to the replica.
            boost::filesystem::path replica;
            /// The replica commitment.
            commitment_type comm_r;
            /// Persistent Aux.
            PersistentAux<typename MerkleTreeType::hash_type::digest_type> aux;
            /// Contains sector-specific (e.g. merkle trees) assets
            boost::filesystem::path cache_dir;
        };    // namespace filecoin
    }         // namespace filecoin
}    // namespace nil

namespace std {
    template<typename MerkleTreeType>
    struct hash<nil::filecoin::PrivateReplicaInfo<MerkleTreeType>> {
        int operator()(const nil::filecoin::PrivateReplicaInfo<MerkleTreeType> &v) {
            return hash()(v.replica) ^ hash()(v.comm_r) ^ hash()(v.aux) ^ hash()(v.cache_dir);
        }
    };
}    // namespace std

namespace nil {
    namespace filecoin {

        /// The minimal information required about a replica, in order to be able to verify
        /// a PoSt over it.
        struct PublicReplicaInfo {
            PublicReplicaInfo(const commitment_type &comm_r);

            template<typename Domain>
            Domain safe_comm_r() const {
                return as_safe_commitment(comm_r, "comm_r");
            }

            /// The replica commitment.
            commitment_type comm_r;
        };

        // Ensure that any associated cached data persisted is discarded.
        template<typename MerkleTreeType>
        void clear_cache(const boost::filesystem::path &cache_dir) {
            info !("clear_cache:start");

            TemporaryAux<MerkleTreeType> t_aux;
            let f_aux_path = cache_dir.to_path_buf().join(CacheKey::TAux.to_string());
            let aux_bytes =
                std::fs::read(&f_aux_path).with_context(|| format !("could not read from path={:?}", f_aux_path));

            deserialize(aux_bytes);

            TemporaryAux<MerkleTreeType> result = TemporaryAux<MerkleTreeType, DefaultPieceHasher>::clear_temp(t_aux);

            info !("clear_cache:finish");

            return result;
        }    // namespace filecoin

        // Ensure that any associated cached data persisted is discarded.
        template<typename MerkleTreeType>
        void clear_caches(const btree::map<sector_id_type, PrivateReplicaInfo<MerkleTreeType>> &replicas) {
            info !("clear_caches:start");

            for (const typename btree::map<sector_id_type, PrivateReplicaInfo<MerkleTreeType>>::value_type &replica :
                 replicas) {
                clear_cache<MerkleTreeType>(replica.second().cache_dir.as_path());
            }

            info !("clear_caches:finish");
        }

        typedef std::vector<std::uint8_t> SnarkProof;

        /// Generates a Winning proof-of-spacetime.
        template<typename MerkleTreeType>
        SnarkProof generate_winning_post(const post_config &config, const challenge_seed_type &randomness,
                                         const btree::map<sector_id_type, PrivateReplicaInfo<MerkleTreeType>> &replicas,
                                         prover_id_type prover_id) {
            info !("generate_winning_post:start");
            assert(("invalid post config type", config.typ == PoStType::Winning));
            assert(("invalid amount of replicas", replicas.size() == post_config.sector_count));

            typename MerkleTreeType::hash_type::digest_type randomness_safe =
                as_safe_commitment(randomness, "randomness");
            typename MerkleTreeType::hash_type::digest_type prover_id_safe =
                as_safe_commitment(&prover_id, "prover_id");

            WinningPostSetupParams vanilla_params = winning_post_setup_params(config);
            std::size_t param_sector_count = vanilla_params.sector_count;

            compound_proof::SetupParams setup_params {vanilla_params, partitions : None, config.priority};

            compound_proof::PublicParams<fallback::FallbackPoSt<MerkleTreeType>> pub_params =
                fallback::FallbackPoStCompound::setup(setup_params);
            let groth_params = get_post_params<MerkleTreeType>(config);

            let trees = replicas.iter()
                            .map(| (_, replica) | replica.merkle_tree(config.sector_size))
                            .collect::<Result<Vec<_>>>();

            std::vector<fallback::PublicSector> pub_sectors(param_sector_count);
            std::vector<fallback::PrivateSector> priv_sectors(param_sector_count);

            for (int i = 0; i < param_sector_count; i++) {
                for (((id, replica), tree) : replicas.iter().zip(trees.iter())) {
                    typename MerkleTreeType::hash_type::digest_type comm_r = replica.safe_comm_r();
                    typename MerkleTreeType::hash_type::digest_type comm_c = replica.safe_comm_c();
                    typename MerkleTreeType::hash_type::digest_type comm_r_last = replica.safe_comm_r_last();

                    pub_sectors.push_back(
                        fallback::PublicSector<typename MerkleTreeType::hash_type::digest_type> {id : *id, comm_r});
                    priv_sectors.push_back(fallback::PrivateSector {tree, comm_c, comm_r_last});
                }
            }

            fallback::PublicInputs<typename MerkleTreeType::hash_type::digest_type> pub_inputs =
                {randomness_safe, prover_id_safe, pub_sectors, k : None};

            fallback::PrivateInputs<MerkleTreeType> priv_inputs = {priv_sectors};

            let proof = fallback::FallbackPoStCompound<MerkleTreeType>::prove(pub_params, pub_inputs, priv_inputs,
                                                                              groth_params);
            let proof = proof.to_vec();

            info !("generate_winning_post:finish");

            return proof;
        }

        /// Given some randomness and a the length of available sectors, generates the challenged sector.
        ///
        /// The returned values are indicies in the range of `0..sector_set_size`, requiring the caller
        /// to match the index to the correct sector.
        template<typename MerkleTreeType>
        std::vector<std::uint64_t>
            generate_winning_post_sector_challenge(const post_config &config, const challenge_seed_type &randomness,
                                                   std::uint64_t sector_set_size, const commitment_type &prover_id) {
            info !("generate_winning_post_sector_challenge:start");
            ensure !(sector_set_size != 0, "empty sector set is invalid");
            ensure !(post_config.typ == PoStType::Winning, "invalid post config type");

            typename MerkleTreeType::hash_type::digest_type prover_id_safe = as_safe_commitment(prover_id, "prover_id");

            typename MerkleTreeType::hash_type::digest_type randomness_safe =
                as_safe_commitment(randomness, "randomness");
            std::vector<std::uint64_t> result = fallback::generate_sector_challenges(
                randomness_safe, config.sector_count, sector_set_size, prover_id_safe);

            info !("generate_winning_post_sector_challenge:finish");

            return result;
        }

        /// Verifies a winning proof-of-spacetime.
        ///
        /// The provided `replicas` must be the same ones as passed to `generate_winning_post`, and be based on
        /// the indices generated by `generate_winning_post_sector_challenge`. It is the responsibility of the
        /// caller to ensure this.
        template<typename MerkleTreeType>
        bool verify_winning_post(const post_config &config, const challenge_seed_type &randomness,
                                 const btree::map<sector_id_type, PublicReplicaInfo> &replicas,
                                 prover_id_type prover_id, const std::vector<std::uint8_t> &proof) {
            info !("verify_winning_post:start");

            assert(("invalid post config type", config.typ == PoStType::Winning));
            assert(("invalid amount of replicas provided", config.sector_count == replicas.size()));

            typename MerkleTreeType::hash_type::digest_type randomness_safe =
                as_safe_commitment(randomness, "randomness");
            typename MerkleTreeType::hash_type::digest_type prover_id_safe = as_safe_commitment(prover_id, "prover_id");

            WinningPostSetupParams vanilla_params = winning_post_setup_params(config);
            std::size_t param_sector_count = vanilla_params.sector_count;

            compound_proof::SetupParams setup_params = {vanilla_params, partitions : None, priority : false};
            compound_proof::PublicParams<fallback::FallbackPoSt<MerkleTreeType>> pub_params =
                fallback::FallbackPoStCompound::setup(&setup_params);

            let verifying_key = get_post_verifying_key<MerkleTreeType>(config);

            MultiProof proof = MultiProof::new_from_reader(None, &proof[..], &verifying_key);
            if (proof.size() != 1) {
                return false;
            }

            std::vector<fallback::PublicSector> pub_sectors(param_sector_count);
            for (int i = 0; i < param_sector_count; i++) {
                for ((id, replica) : replicas.iter()) {
                    typename MerkleTreeType::hash_type::digest_type comm_r = replica.safe_comm_r();
                    pub_sectors.push_back({*id, comm_r});
                }
            }

            fallback::PublicInputs pub_inputs =
                {randomness : randomness_safe, prover_id : prover_id_safe, sectors : pub_sectors, k : None};

            bool is_valid = fallback::FallbackPoStCompound::verify(pub_params, pub_inputs, proof,
                                                                   {config.challenge_count * config.sector_count});

            if (!is_valid) {
                return false;
            }

            info !("verify_winning_post:finish");

            return true;
        }

        /// Generates a Window proof-of-spacetime.
        template<typename MerkleTreeType>
        SnarkProof generate_window_post(const post_config &config, const challenge_seed_type &randomness,
                                        const btree::map<sector_id_type, PrivateReplicaInfo<MerkleTreeType>> &replicas,
                                        prover_id_type prover_id) {
            info !("generate_window_post:start");
            assert(("invalid post config type", post_config.typ == PoStType::Window));

            typename MerkleTreeType::hash_type::digest_type randomness_safe =
                as_safe_commitment(randomness, "randomness");
            typename MerkleTreeType::hash_type::digest_type prover_id_safe = as_safe_commitment(prover_id, "prover_id");

            let vanilla_params = window_post_setup_params(config);
            let partitions = get_partitions_for_window_post(replicas.size(), config);

            std::size_t sector_count = vanilla_params.sector_count;
            compound_proof::SetupParams setup_params = {vanilla_params, partitions, priority : config.priority};

            compound_proof::PublicParams<fallback::FallbackPoSt<MerkleTreeType>> pub_params =
                fallback::FallbackPoStCompound::setup(setup_params);
            let groth_params = get_post_params<MerkleTreeType>(config);

            std::vector<MerkleTreeType> trees =
                replicas.iter().map(| (_id, replica) | replica.merkle_tree(config.sector_size)).collect::<Result<_>>();

            std::vector<fallback::PublicSector> pub_sectors(sector_count);
            std::vector<fallback::PrivateSector> priv_sectors(sector_count);

            for (((sector_id, replica), tree) : replicas.iter().zip(trees.iter())) {
                typename MerkleTreeType::hash_type::digest_type comm_r = replica.safe_comm_r();
                typename MerkleTreeType::hash_type::digest_type comm_c = replica.safe_comm_c();
                typename MerkleTreeType::hash_type::digest_type comm_r_last = replica.safe_comm_r_last();

                pub_sectors.push_back(fallback::PublicSector {id : *sector_id, comm_r});
                priv_sectors.push_back(fallback::PrivateSector {tree, comm_c, comm_r_last});
            }

            fallback::PublicInputs pub_inputs =
                {randomness : randomness_safe, prover_id : prover_id_safe, sectors : pub_sectors, k : None};

            fallback::PrivateInputs<MerkleTreeType> priv_inputs = {sectors : priv_sectors};

            let proof = fallback::FallbackPoStCompound::prove(&pub_params, &pub_inputs, &priv_inputs, &groth_params, );

            info !("generate_window_post:finish");

            return proof.to_vec();
        }

        /// Verifies a window proof-of-spacetime.
        template<typename MerkleTreeType>
        bool verify_window_post(const post_config &config,
                                const challenge_seed_type &randomness,
                                const btree::map<sector_id_type, PublicReplicaInfo> &replicas,
                                prover_id_type prover_id,
                                const std::vector<std::uint8_t> &proof) {
            info !("verify_window_post:start");

            assert(("invalid post config type", post_config.typ == PoStType::Window));

            typename MerkleTreeType::hash_type::digest_type randomness_safe =
                as_safe_commitment(randomness, "randomness");
            typename MerkleTreeType::hash_type::digest_type prover_id_safe = as_safe_commitment(prover_id, "prover_id");

            WindowPostSetupParams vanilla_params = window_post_setup_params(config);
            let partitions = get_partitions_for_window_post(replicas.size(), config);

            compound_proof::SetupParams setup_params = {vanilla_params, partitions, priority : false};
            compound_proof::PublicParams<fallback::FallbackPoSt<Tree>> pub_params =
                fallback::FallbackPoStCompound::setup(setup_params);

            let verifying_key = get_post_verifying_key<MerkleTreeType>(config);

            MultiProof proof = MultiProof::new_from_reader(partitions, &proof[..], &verifying_key);

            std::vector<PublicSector> pub_sectors = replicas.iter()
                                                        .map(| (sector_id, replica) |
                                                             {
                                                                 let comm_r = replica.safe_comm_r() ? ;
                                                                 Ok(fallback::PublicSector {
                                                                     id : *sector_id,
                                                                     comm_r,
                                                                 })
                                                             })
                                                        .collect::<Result<_>>();

            fallback::PublicInputs pub_inputs =
                {randomness : randomness_safe, prover_id : prover_id_safe, sectors : pub_sectors, k : None};

            bool is_valid =
                fallback::FallbackPoStCompound::verify(pub_params, pub_inputs, proof, fallback::ChallengeRequirements {
                    minimum_challenge_count : post_config.challenge_count * post_config.sector_count
                });

            if (!is_valid) {
                return false;
            }

            info !("verify_window_post:finish");

            return true;
        }

        boost::optional<std::size_t> get_partitions_for_window_post(std::size_t total_sector_count,
                                                                    const post_config &config);
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_SEAL_HPP

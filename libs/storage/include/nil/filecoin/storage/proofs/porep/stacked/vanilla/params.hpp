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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_PARAMS_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_PARAMS_HPP

#include <array>
#include <string>

#include <boost/filesystem/path.hpp>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/challenges.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/column_proof.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/labelling_proof.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/encoding_proof.hpp>

#include <nil/filecoin/storage/proofs/core/merkle/proof.hpp>

namespace nil {
    namespace filecoin {
        namespace stacked {
            namespace vanilla {

                constexpr static const std::size_t BINARY_ARITY = 2;
                constexpr static const std::size_t QUAD_ARITY = 4;
                constexpr static const std::size_t OCT_ARITY = 8;

                struct SetupParams {
                    // Number of nodes
                    std::size_t nodes;

                    // Base degree of DRG
                    std::size_t degree;

                    std::size_t expansion_degree;

                    std::array<std::uint8_t, 32> porep_id;
                    LayerChallenges layer_challenges;
                };

                template<typename MerkleTreeType>
                struct PublicParams {
                    typedef MerkleTreeType tree_type;
                    typedef typename tree_type::hash_type hash_type;

                    std::string identifier() {
                        return std::string("layered_drgporep::PublicParams{{ graph:") +
                               std::to_string(graph.identifier()) +
                               ", challenges: " + std::to_string(layer_challenges) +
                               ", tree: " + std::to_string(MerkleTreeType::display()) + "}}";
                    }

                    std::uint64_t sector_size() {
                        return graph.sector_size();
                    }

                    StackedBucketGraph<hash_type> graph;
                    LayerChallenges layer_challenges;
                };

                /// Tau for a single parition.
                template<typename DDomain, typename EDomain>
                struct Tau {
                    EDomain comm_d;
                    DDomain comm_r;
                };

                /// Stored along side the sector on disk.
                template<typename D>
                struct PersistentAux {
                    D comm_c;
                    D comm_r_last;
                };

                typedef std::function<void(const StoreConfig &, std::size_t, std::size_t)> VerifyCallback;

                template<typename MerkleTreeType>
                struct Labels {
                    Labels(const std::vector<StoreConfig> &labels) : labels(labels) {
                    }

                    void verify_stores(VerifyCallback callback, const boost::filesystem::path &cache_dir) {
                        std::vector<StoreConfig> updated_path_labels = labels;
                        std::size_t required_configs = get_base_tree_count<MerkleTreeType>();
                        for (const StoreConfig &label : updated_path_labels) {
                            label.path = cache_dir;
                            callback(label, BINARY_ARITY, required_configs);
                        }
                    }

                    DiskStore<typename MerkleTreeType::hash_type::digest_type> labels_for_layer(std::size_t layer) {
                        assert(("Layer cannot be 0", layer != 0));
                        assert(("Layer {} is not available (only {} layers available)", layer <= layers()));

                        std::size_t row_index = layer - 1;
                        StoreConfig config = labels[row_index];
                        assert(config.size.is_some());

                        DiskStore::new_from_disk(config.size, MerkleTreeType::base_arity, config);
                    }

                    /// Returns label for the last layer.
                    DiskStore<typename MerkleTreeType::hash_type::digest_type> labels_for_last_layer() {
                        return labels_for_layer(labels.size() - 1);
                    }

                    /// How many layers are available.
                    std::size_t layers() {
                        return labels.size();
                    }

                    /// Build the column for the given node.
                    Column<typename MerkleTreeType::hash_type> column(std::uint32_t node) {
                        std::vector<typename MerkleTreeType::hash_type::digest_type> rows;

                        for (const StoreConfig &label : labels) {
                            assert(label.size.is_some());
                            DiskStore store =
                                DiskStore::new_from_disk(label.size, MerkleTreeType::base_arity, label);
                            rows.push_back(store.read_at(node));
                        }

                        return {node, rows};
                    }

                    /// Update all configs to the new passed in root cache path.
                    void update_root(const boost::filesystem::path &root) {
                        for (StoreConfig &config : labels) {
                            config.path = root;
                        }
                    }

                    std::vector<StoreConfig> labels;
                };

                template<typename MerkleTreeType, typename Hash>
                struct TemporaryAux {
                    void set_cache_path(const boost::filesystem::path &cache_path) {
                        for (StoreConfig &label : labels.labels) {
                            label.path = cache_path;
                        }
                        tree_d_config.path = cache_path;
                        tree_r_last_config.path = cache_path;
                        tree_c_config.path = cache_path;
                    }

                    DiskStore<typename MerkleTreeType::hash_type::digest_type> labels_for_layer(std::size_t layer) {
                        return labels.labels_for_layer(layer);
                    }

                    typename MerkleTreeType::hash_type::digest_type domain_node_at_layer(std::size_t layer,
                                                                                         std::uint32_t node_index) {
                        return labels_for_layer(layer).read_at(node_index);
                    }

                    Column<typename MerkleTreeType::hash_type> column(std::uint32_t column_index) {
                        return labels.column(column_index);
                    }

                    // 'clear_temp' will discard all persisted merkle and layer data
                    // that is no longer required.
                    void clear_temp(TemporaryAux<MerkleTreeType, Hash> t_aux) {
                        auto cached = [&](const StoreConfig &config) -> bool {
                            return boost::filesystem::path(StoreConfig::data_path(config.path, config.id)).exists();
                        };

                        auto delete_tree_c_store = [&](const StoreConfig &config, std::size_t tree_c_size) {
                            DiskStore<typename MerkleTreeType::hash_type::digest_type> tree_c_store =
                                DiskStore<typename MerkleTreeType::hash_type::digest_type>::new_from_disk(
                                    tree_c_size, MerkleTreeType::base_arity, config)
                                    .context("tree_c");
                            // Note: from_data_store requires the base tree leaf count
                            DiskTree<MerkleTreeType::Hasher, MerkleTreeType::base_arity, MerkleTreeType::sub_tree_arity,
                                     MerkleTreeType::top_tree_arity>
                                tree_c =
                                    DiskTree<MerkleTreeType::Hasher, MerkleTreeType::base_arity,
                                             MerkleTreeType::sub_tree_arity,
                                             MerkleTreeType::top_tree_arity>::from_data_store(tree_c_store,
                                                                                            get_merkle_tree_leafs(
                                                                                                tree_c_size,
                                                                                                MerkleTreeType::base_arity))
                                        .context("tree_c");
                            tree_c.delete(config.clone()).context("tree_c");
                        };

                        if (cached(&t_aux.tree_d_config)) {
                            std::size_t tree_d_size = t_aux.tree_d_config.size.context("tree_d config has no size");
                            DiskStore<typename Hash::digest_type> tree_d_store =
                                DiskStore::new_from_disk(tree_d_size, BINARY_ARITY, &t_aux.tree_d_config)
                                    .context("tree_d");
                            // Note: from_data_store requires the base tree leaf count
                            BinaryMerkleTree<Hash> tree_d =
                                BinaryMerkleTree<Hash>::from_data_store(
                                    tree_d_store, get_merkle_tree_leafs(tree_d_size, BINARY_ARITY))
                                    .context("tree_d");

                            tree_d.delete(t_aux.tree_d_config).context("tree_d");
                            trace !("tree d deleted");
                        }

                        std::size_t tree_count = get_base_tree_count<MerkleTreeType>();
                        std::size_t tree_c_size = t_aux.tree_c_config.size.context("tree_c config has no size");
                        let configs = split_config(t_aux.tree_c_config.clone(), tree_count);

                        if (cached(&t_aux.tree_c_config)) {
                            delete_tree_c_store(&t_aux.tree_c_config, tree_c_size);
                        } else if (cached(configs[0])) {
                            for (const StoreConfig &config : configs) {
                                // Trees with sub-trees cannot be instantiated and deleted via the existing tree
                                // interface since knowledge of how the base trees are split exists outside of merkle
                                // light.  For now, we manually remove each on disk tree file since we know where they
                                // are here.
                                boost::filesystem::path tree_c_path = StoreConfig::data_path(config.path, config.id);
                                remove_file(tree_c_path)
                                    .with_context(|| format !("Failed to delete {:?}", tree_c_path));
                            }
                        }
                        trace !("tree c deleted");

                        for (int i = 0; i < t_aux.labels.labels.size(); i++) {
                            StoreConfig cur_config = t_aux.labels.labels[i].clone();
                            if (cached(cur_config)) {
                                DiskStore<typename MerkleTreeType::hash_type::digest_type>::delete (cur_config)
                                    .with_context(|| format !("labels {}", i));
                                trace !("layer {} deleted", i);
                            }
                        }
                    }

                    Labels<MerkleTreeType> labels;
                    StoreConfig tree_d_config;
                    StoreConfig tree_r_last_config;
                    StoreConfig tree_c_config;
                };

                template<typename T, typename S>
                struct PublicInputs {
                    typedef Tau<T, S> tau_type;
                    typedef std::size_t challenge_type;

                    std::vector<std::size_t> challenges(const LayerChallenges &layer_challenges, std::size_t leaves,
                                                        std::size_t partition_k) {
                        std::size_t k = partition_k.unwrap_or(0);

                        return layer_challenges.derive<T>(leaves, replica_id, seed, k);
                    }

                    T replica_id;

                    std::array<std::uint8_t, 32> seed;

                    Tau<T, S> tau;

                    /// Partition index
                    std::size_t k;
                };

                template<typename MerkleTreeType>
                struct LabelsCache {
                    typedef MerkleTreeType tree_type;
                    typedef typename tree_type::hash_type tree_hash_type;

                    LabelsCache(const Labels<MerkleTreeType> &labels) {
                        std::vector<DiskStore<typename tree_hash_type::digest_type>> disk_store_labels(labels.size());
                        for (int i = 0; i < labels.size(); i++) {
                            disk_store_labels.emplace_back(labels.labels_for_layer(i + 1));
                        }

                        return {disk_store_labels};
                    }

                    std::size_t size() {
                        return labels.size();
                    }

                    bool empty() {
                        return labels.empty();
                    }

                    const DiskStore<typename tree_hash_type::digest_type> &labels_for_layer(std::size_t layer) {
                        assert(("Layer cannot be 0", layer != 0));
                        assert(layer <= layers());

                        std::size_t row_index = layer - 1;
                        return labels[row_index];
                    }

                    /// Returns the labels on the last layer.
                    const DiskStore<typename tree_hash_type::digest_type> &labels_for_last_layer() {
                        return labels[labels.size() - 1];
                    }

                    /// How many layers are available.
                    std::size_t layers() {
                        return labels.size();
                    }

                    /// Build the column for the given node.
                    Column<typename MerkleTreeType::hash_type> column(std::uint32_t node) {
                        std::vector<typename MerkleTreeType::hash_type::digest_type> rows;

                        for (const DiskStore<typename MerkleTreeType::hash_type::digest_type> &l : labels) {
                            rows.push_back(l.read_at(node));
                        }

                        return {node, rows};
                    }

                    std::vector<DiskStore<typename MerkleTreeType::hash_type::digest_type>> labels;
                };

                template<typename MerkleTreeType, typename Hash>
                struct TemporaryAuxCache {
                    typedef MerkleTreeType tree_type;
                    typedef Hash hash_type;

                    typedef typename tree_type::hash_type tree_hash_type;

                    /// The encoded nodes for 1..layers.
                    LabelsCache<tree_type> labels;
                    BinaryMerkleTree<hash_type> tree_d;

                    // Notably this is a LevelCacheTree instead of a full merkle.
                    LCTree<typename tree_type::hash_type, typename tree_type::Arity, typename tree_type::SubTreeArity,
                           typename tree_type::TopTreeArity>
                        tree_r_last;

                    // Store the 'rows_to_discard' value from the tree_r_last
                    // StoreConfig for later use (i.e. proof generation).
                    std::size_t tree_r_last_config_rows_to_discard;

                    DiskTree<tree_hash_type, typename tree_type::Arity, typename tree_type::SubTreeArity,
                             typename tree_type::TopTreeArity>
                        tree_c;
                    TemporaryAux<tree_type, hash_type> t_aux;
                    boost::filesystem::path replica_path;

                    TemporaryAuxCache(const TemporaryAux<tree_type, hash_type> &t_aux,
                                      const boost::filesystem::path &replica_path) {
                        // tree_d_size stored in the config is the base tree size
                        std::size_t tree_d_size = t_aux.tree_d_config.size();
                        std::size_t tree_d_leafs = get_merkle_tree_leafs(tree_d_size, BINARY_ARITY);
                        trace !("Instantiating tree d with size {} and leafs {}", tree_d_size, tree_d_leafs);
                        DiskStore<typename Hash::digest_type> tree_d_store =
                            DiskStore::new_from_disk(tree_d_size, BINARY_ARITY, &t_aux.tree_d_config)
                                .context("tree_d_store");
                        BinaryMerkleTree<hash_type> tree_d =
                            BinaryMerkleTree<Hash>::from_data_store(tree_d_store, tree_d_leafs).context("tree_d");

                        std::size_t tree_count = get_base_tree_count<MerkleTreeType>();
                        std::vector<StoreConfig> configs = split_config(t_aux.tree_c_config.clone(), tree_count);

                        // tree_c_size stored in the config is the base tree size
                        std::size_t tree_c_size = t_aux.tree_c_config.size;
                        trace !("Instantiating tree c [count {}] with size {} and arity {}", tree_count, tree_c_size,
                                MerkleTreeType::base_arity);
                        DiskTree<typename MerkleTreeType::hash_type, MerkleTreeType::base_arity,
                                 MerkleTreeType::sub_tree_arity, MerkleTreeType::top_tree_arity>
                            tree_c =
                                create_disk_tree<DiskTree<typename MerkleTreeType::hash_type, MerkleTreeType::base_arity,
                                                          MerkleTreeType::sub_tree_arity, MerkleTreeType::top_tree_arity>>(
                                    tree_c_size, configs);

                        // tree_r_last_size stored in the config is the base tree size
                        std::size_t tree_r_last_size = t_aux.tree_r_last_config.size;
                        std::size_t tree_r_last_config_rows_to_discard = t_aux.tree_r_last_config.rows_to_discard;
                        let(configs, replica_config) =
                            split_config_and_replica(t_aux.tree_r_last_config.clone(),
                                                     replica_path.clone(),
                                                     get_merkle_tree_leafs(tree_r_last_size, MerkleTreeType::base_arity),
                                                     tree_count);

                        trace !("Instantiating tree r last [count {}] with size {} and arity {}, {}, {}", tree_count,
                                tree_r_last_size, MerkleTreeType::base_arity, MerkleTreeType::sub_tree_arity,
                                MerkleTreeType::top_tree_arity);
                        LCTree<MerkleTreeType::Hasher, MerkleTreeType::base_arity, MerkleTreeType::sub_tree_arity,
                               MerkleTreeType::top_tree_arity>
                            tree_r_last =
                                create_lc_tree<LCTree<MerkleTreeType::Hasher, MerkleTreeType::base_arity,
                                                      MerkleTreeType::sub_tree_arity, MerkleTreeType::top_tree_arity>>(
                                    tree_r_last_size, configs, replica_config);

                        return {{(&t_aux.labels).context("labels_cache")},
                                tree_d,
                                tree_r_last,
                                tree_r_last_config_rows_to_discard,
                                tree_c,
                                replica_path,
                                t_aux};
                    }

                    DiskStore<typename MerkleTreeType::hash_type::digest_type> &labels_for_layer(std::size_t layer) {
                        return labels.labels_for_layer(layer);
                    }

                    typename MerkleTreeType::hash_type::digest_type domain_node_at_layer(std::size_t layer,
                                                                                         std::uint32_t node_index) {
                        return labels_for_layer(layer).read_at(node_index);
                    }

                    Column<typename MerkleTreeType::hash_type> column(std::uint32_t column_index) {
                        return labels.column(column_index);
                    }
                };

                template<typename MerkleTreeType, typename Hash>
                struct PrivateInputs {
                    PersistentAux<typename MerkleTreeType::hash_type::digest_type> p_aux;
                    TemporaryAuxCache<MerkleTreeType, Hash> t_aux;
                };

                template<typename MerkleTreeType, typename Hash>
                struct Proof {
                    typedef Hash hash_type;
                    typedef MerkleTreeType tree_type;
                    typedef typename tree_type::hash_type tree_hash_type;

                    MerkleProof<hash_type, MerkleTreeType::base_arity, MerkleTreeType::sub_tree_arity,
                                MerkleTreeType::top_tree_arity>
                        comm_d_proofs;
                    MerkleProof<tree_hash_type, MerkleTreeType::base_arity, MerkleTreeType::sub_tree_arity,
                                MerkleTreeType::top_tree_arity>
                        comm_r_last_proof;
                    ReplicaColumnProof<MerkleProof<tree_hash_type, MerkleTreeType::base_arity, MerkleTreeType::sub_tree_arity,
                                                   MerkleTreeType::top_tree_arity>>
                        replica_column_proofs;

                    /// Indexed by layer in 1..layers.
                    std::vector<LabelingProof<typename MerkleTreeType::hash_type>> labeling_proofs;
                    EncodingProof<typename MerkleTreeType::hash_type> encoding_proof;

                    typename tree_hash_type::digest_type comm_r_last() {
                        return comm_r_last_proof.root();
                    }

                    typename tree_hash_type::digest_type comm_c() {
                        return replica_column_proofs.c_x.root();
                    }

                    /// Verify the full proof.
                    bool verify(const PublicParams<MerkleTreeType> &pub_params,
                                const PublicInputs<typename tree_hash_type::digest_type,
                                                   typename hash_type::digest_type> &pub_inputs,
                                std::size_t challenge, const StackedBucketGraph<tree_hash_type> &graph) {
                        typename MerkleTreeType::hash_type::digest_type replica_id = pub_inputs.replica_id;

                        bool result = challenge < graph.size() && pub_inputs.tau.is_some();

                        // Verify initial data layer
                        trace !("verify initial data layer");

                        result |= comm_d_proofs.proves_challenge(challenge);

                        if (pub_inputs.tau) {
                            assert(comm_d_proofs.root() == pub_inputs.tau.comm_d);
                        } else {
                            return false;
                        }

                        // Verify replica column openings
                        trace !("verify replica column openings");
                        std::vector<std::uint32_t> parents(graph.degree());
                        graph.parents(challenge, parents);    // FIXME: error handling
                        assert(replica_column_proofs.verify(challenge, parents));
                        assert(verify_final_replica_layer(challenge));
                        assert(verify_labels(replica_id, pub_params.layer_challenges));

                        trace !("verify encoding");

                        assert(encoding_proof.verify<Hash>(replica_id, comm_r_last_proof.leaf(), comm_d_proofs.leaf()));

                        return result;
                    }

                    /// Verify all labels.
                    bool verify_labels(const typename tree_hash_type::digest_type &replica_id,
                                       const LayerChallenges &layer_challenges) {
                        // Verify Labels Layer 1..layers
                        for (std::size_t layer = 1; layer < layer_challenges.layers; layer++) {
                            trace !("verify labeling (layer: {})", layer);

                            assert(labeling_proofs.get(layer - 1).is_some());
                            LabellingProof<typename MerkleTreeType::hash_type> labeling_proof =
                                labeling_proofs.get(layer - 1);
                            auto labeled_node = replica_column_proofs.c_x.get_node_at_layer(layer);
                            assert(labeling_proof.verify(replica_id, labeled_node));
                        }

                        return true;
                    }

                    /// Verify final replica layer openings
                    bool verify_final_replica_layer(std::size_t challenge) {
                        trace !("verify final replica layer openings");
                        assert(comm_r_last_proof.proves_challenge(challenge));

                        return true;
                    }
                };

                template<typename MerkleProofType>
                struct ReplicaColumnProof {
                    typedef MerkleProofType proof_type;

                    template<typename InputParentsRange>
                    typename std::enable_if<
                        std::is_same<typename std::iterator_traits<typename InputParentsRange::iterator>::value_type,
                                     std::uint32_t>::value,
                        bool>::type
                        verify(std::size_t challenge, const InputParentsRange &parents) {
                        typename MerkleProofType::tree_type::hash_type::digest_type expected_comm_c = c_x.root();

                        trace !("  verify c_x");
                        assert((c_x.verify(challenge, &expected_comm_c)));

                        trace !("  verify drg_parents");
                        for ((proof, parent) : drg_parents.iter().zip(parents.iter())) {
                            assert((proof.verify(parent, expected_comm_c)));
                        }

                        trace !("  verify exp_parents");
                        for ((proof, parent) : exp_parents.iter().zip(parents.iter().skip(drg_parents.size()))) {
                            assert((proof.verify(parent, expected_comm_c)));
                        }
                    }

                    ColumnProof<proof_type> c_x;
                    std::vector<ColumnProof<proof_type>> drg_parents;
                    std::vector<ColumnProof<proof_type>> exp_parents;
                };

                template<typename MerkleTreeType, typename Hash>
                using TransformedLayers =
                    std::tuple<Tau<typename MerkleTreeType::hash_type::digest_type, typename Hash::digest_type>,
                               PersistentAux<typename MerkleTreeType::hash_type::digest_type>,
                               TemporaryAux<MerkleTreeType, Hash>>;

                template<typename Hash, typename InputDataRange>
                typename Hash::digest_type get_node(const InputDataRange &data, std::size_t index) {
                    return Hash::digest_type::try_from_bytes(data_at_node(data, index).expect("invalid node math"));
                }

                /// Generate the replica id as expected for Stacked DRG.
                template<typename InputDataRange, typename Hash = crypto3::hashes::sha2<256>>
                typename Hash::digest_type
                    generate_replica_id(const std::array<std::uint8_t, 32> &prover_id, std::uint64_t sector_id,
                                        const std::array<std::uint8_t, 32> &ticket, const InputDataRange &comm_d,
                                        const std::array<std::uint8_t, 32> &porep_seed) {
                    using namespace nil::crypto3;

                    accumulator_set<Hash> acc;

                    hash<Hash>(prover_id, acc);
                    hash<Hash>(sector_id, acc);
                    hash<Hash>(ticket, acc);
                    hash<Hash>(comm_d, acc);
                    hash<Hash>(porep_seed, acc);

                    return accumulators::extract::hash<Hash>(acc);
                }
            }    // namespace vanilla
        }        // namespace stacked
    }            // namespace filecoin
}    // namespace nil

#endif
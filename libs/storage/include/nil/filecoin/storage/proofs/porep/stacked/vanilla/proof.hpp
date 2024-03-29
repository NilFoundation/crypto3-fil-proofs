//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nemo@nil.foundation>

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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_PROOF_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_PROOF_HPP

#include <boost/filesystem/path.hpp>
#include <boost/assert.hpp>
#include <boost/log/trivial.hpp>

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/column.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/params.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/porep.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/challenges.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/create_label.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/encoding_proof.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/labelling_proof.hpp>

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/detail/processing/naive/params.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/detail/processing/naive/labelling_proof.hpp>

namespace nil {
    namespace filecoin {
        namespace stacked {
            namespace vanilla {
                constexpr static const std::size_t TOTAL_PARENTS = 37;

                template<typename MerkleTreeType, typename Hash>
                struct StackedDrg {
                    typedef MerkleTreeType tree_type;
                    typedef Hash hash_type;

                    typedef typename tree_type::hash_type tree_hash_type;

                    using merkle_proof_type = merkletree::MerkleProof<merkletree::MerkleTree<hash_type>::Hasher,
                                                                      merkletree::MerkleTree<hash_type>::Arity,
                                                                      merkletree::MerkleTree<hash_type>::SubTreeArity,
                                                                      merkletree::MerkleTree<hash_type>::TopTreeArity>;

                    std::vector<std::vector<Proof<tree_type, hash_type>>> prove_layers(
                        const StackedBucketGraph<tree_hash_type> &graph,
                        const PublicInputs<typename tree_hash_type::digest_type, typename hash_type::digest_type>
                            &pub_inputs,
                        const PersistentAux<typename tree_hash_type::digest_type> &p_aux,
                        const TemporaryAuxCache<tree_type, hash_type> &t_aux,
                        const LayerChallenges &layer_challenges,
                        std::size_t layers,
                        std::size_t total_layers,
                        std::size_t partition_count) {

                        assert(layers > 0);
                        assert(t_aux.labels.size() == layers);

                        std::size_t graph_size = graph.size();

                        // Sanity checks on restored trees.
                        assert(pub_inputs.tau.is_some());
                        assert(pub_inputs.tau.comm_d == t_aux.tree_d.root());

                        auto get_drg_parents_columns = [&](std::size_t x) -> std::vector<Column<tree_hash_type>> {
                            std::size_t base_degree = graph.base_graph().degree();

                            std::vector<Column<tree_hash_type>> columns(base_degree);

                            std::vector<std::uint64_t> parents(0, base_degree);
                            graph.base_parents(x, parents);

                            for (parents::iterator parent_it = parents.begin(); parent_it != parents.end();
                                 ++parent_it) {
                                columns.push_back(t_aux.column(*parent_it));
                            }

                            assert(columns.size() == base_degree);

                            return columns;
                        };

                        std::vector<Column<tree_hash_type>> get_exp_parents_columns(std::size_t x) {
                            std::vector<auto> parents(graph.expansion_degree(), 0);
                            graph.expanded_parents(x, parents);

                            std::vector<Column<tree_hash_type>> result;
                            result.reserve(parents.size());

                            for (parents::iterator parent_it = parents.begin(); parent_it != parents.end();
                                 ++parent_it) {
                                result.push_back(t_aux.column(*parent_it));
                            }

                            return result;
                        }

                        std::vector<std::vector<>> result;

                        for (std::size_t k = 0; k < partition_count; k++) {
                            std::vector<auto> result_k;
                            result_k.reserve(challenges.size());    // not sure about actual size of result_k

                            BOOST_LOG_TRIVIAL(trace) << std::format("proving partition %d/%d", k + 1, partition_count);

                            // Derive the set of challenges we are proving over.
                            std::vector<std::size_t> challenges =
                                pub_inputs.challenges(layer_challenges, graph_size, Some(k));

                            // Stacked commitment specifics
                            for (std::size_t challenge_index = 0,
                                             challenges::iterator challenge_it = challenges.begin();
                                 challenge_it != challenges.end(); ++challenge_index, ++challenge_it) {

                                BOOST_LOG_TRIVIAL(trace)
                                    << std::format(" challenge %d (%d)", *challenge_it, challenge_index);
                                BOOST_ASSERT_MSG(*challenge_it < graph.size(), "Invalid challenge");
                                BOOST_ASSERT_MSG(*challenge_it > 0, "Invalid challenge");

                                // Initial data layer openings (c_X in Comm_D)
                                merkle_proof_type<auto> comm_d_proof =
                                    merkletree::processing::naive::MerkleTree_gen_proof(t_aux.tree_d, *challenge_it);

                                BOOST_ASSERT(comm_d_proof.validate(*challenge_it));

                                // Stacked replica column openings
                                BOOST_ASSERT(p_aux.comm_c == t_aux.tree_c.root());
                                auto tree_c = &t_aux.tree_c;

                                // All labels in C_X
                                BOOST_LOG_TRIVIAL(trace) << "  c_x";
                                auto c_x = t_aux.column(std::uint32_t(*challenge_it)).into_proof(tree_c);

                                // All labels in the DRG parents.
                                BOOST_LOG_TRIVIAL(trace) << "  drg_parents";
                                std::vector<auto> drg_parents;
                                drg_parents.reserve();

                                std::vector<auto> drg_parents_columns = get_drg_parents_columns(*challenge_it);

                                for (drg_parents_columns::iterator column_it = drg_parents_columns.begin();
                                     column_it != drg_parents_columns.end();
                                     ++column_it) {
                                    drg_parents.push((*column_it).into_proof(tree_c));
                                }

                                // Labels for the expander parents
                                BOOST_LOG_TRIVIAL(trace) << "  exp_parents";
                                std::vector<auto> exp_parents;
                                exp_parents.reserve();

                                std::vector<auto> exp_parents_columns = get_exp_parents_columns(*challenge_it);

                                for (exp_parents_columns::iterator column_it = exp_parents_columns.begin();
                                     column_it != exp_parents_columns.end();
                                     ++column_it) {
                                    exp_parents.push((*column_it).into_proof(tree_c));
                                }

                                ReplicaColumnProof rcp = {c_x, drg_parents, exp_parents};

                                // Final replica layer openings
                                BOOST_LOG_TRIVIAL(trace) << "final replica layer openings";

                                merkle_proof_type<auto> comm_r_last_proof =
                                    merkletree::processing::naive::MerkleTree_gen_cached_proof(
                                        t_aux.tree_r_last, *challenge_it,
                                        Some(t_aux.tree_r_last_config_rows_to_discard), );

                                BOOST_ASSERT(comm_r_last_proof.validate(*challenge_it));

                                // Labeling Proofs Layer 1..l
                                std::vector<auto> labeling_proofs;
                                labeling_proofs.reserve(layers);
                                auto encoding_proof = None;

                                for (int layer = 1; layer != layers; layer++) {
                                    BOOST_LOG_TRIVIAL(trace) << std::format("  encoding proof layer %d", layer);
                                    std::vector<typename tree_hash_type::digest_type> parents_data;

                                    if (layer == 1) {
                                        std::vector<auto> parents(graph.base_graph().degree(), 0);
                                        graph.base_parents(*challenge_it, parents);

                                        parents_data.reserve(parents.size());

                                        for (parents::iterator parent_it = parents.begin(); parent_it != parents.end();
                                             ++parent_it) {

                                            parents_data.push_back(t_aux.domain_node_at_layer(layer, *parent_it));
                                        }
                                    } else {
                                        std::vector<auto> parents(graph.degree(), 0);
                                        graph.parents(*challenge_it, parents);
                                        auto base_parents_count = graph.base_graph().degree();

                                        parents_data.reserve(parents.size());

                                        for (std::size_t i = 0, parents::iterator parent_it = parents.begin();
                                             parent_it != parents.end(); ++i, ++parent_it) {

                                            if (i < base_parents_count) {
                                                // parents data for base parents is from the current
                                                // layer
                                                parents_data.push_back(t_aux.domain_node_at_layer(layer, *parent_it));
                                            } else {
                                                // parents data for exp parents is from the previous
                                                // layer
                                                parents_data.push_back(
                                                    t_aux.domain_node_at_layer(layer - 1, *parent_it));
                                            }
                                        }
                                    }

                                    // repeat parents
                                    std::vector<auto> parents_data_full(TOTAL_PARENTS, Default::default());
                                    for (chunk : parents_data_full.chunks_mut(parents_data.size())) {
                                        chunk.copy_from_slice(&parents_data[..chunk.size()]);
                                    }

                                    const LabelingProof<typename MerkleTreeType::hash_type> labeling_proof(
                                        std::uint32_t(layer), std::uint64_t(*challenge_it), parents_data_full.clone());

                                    const auto labeled_node = rcp.c_x.get_node_at_layer(layer);
                                    BOOST_ASSERT_MSG(
                                        LabelingProof_naive_verify(labeling_proof, &pub_inputs.replica_id,
                                                                   &labeled_node),
                                        std::format("Invalid encoding proof generated at layer {}", layer));
                                    BOOST_LOG_TRIVIAL(trace)
                                        << std::format("Valid encoding proof generated at layer %d", layer);

                                    labeling_proofs.push(labeling_proof);

                                    if (layer == layers) {
                                        encoding_proof = Some(EncodingProof(
                                            std::uint32_t(layer), std::uint64_t(*challenge_it), parents_data_full));
                                    }
                                }

                                result_k.push_back(Proof({.comm_d_proofs = comm_d_proof,
                                                          .replica_column_proofs = rcp,
                                                          .comm_r_last_proof,
                                                          .labeling_proofs,
                                                          .encoding_proof = encoding_proof}));
                            }
                            result.push_back(result_k);
                        }
                    }

                    void extract_and_invert_transform_layers(const StackedBucketGraph<tree_hash_type> &graph,
                                                             const LayerChallenges &layer_challenges,
                                                             const typename tree_hash_type::digest_type &replica_id,
                                                             const std::vector<std::uint8_t> &data,
                                                             const StoreConfig &config) {
                        BOOST_LOG_TRIVIAL(trace) << "extract_and_invert_transform_layers";

                        const auto layers = layer_challenges.layers();
                        assert(layers > 0);

                        // generate labels
                        const auto labels = std::get<0>(generate_labels(graph, layer_challenges, replica_id, config));

                        const auto last_layer_labels = labels.labels_for_last_layer();
                        const auto size = merkletree::store::Store::len(last_layer_labels);

                        for ((key, encoded_node_bytes) :
                             last_layer_labels.read_range(0..size).into_iter().zip(data.chunks_mut(NODE_SIZE))) {

                            const auto encoded_node =
                                MerkleTreeType::hash_type::digest_type::try_from_bytes(encoded_node_bytes);
                            const auto data_node =
                                decode::<typename MerkleTreeType::hash_type::digest_type>(key, encoded_node);

                            // store result in the data
                            encoded_node_bytes.copy_from_slice(AsRef::<[u8]>::as_ref(&data_node));
                        }
                    }

                    std::tuple<LabelsCache<tree_type>, Labels<tree_type>> generate_labels(
                        const StackedBucketGraph<tree_hash_type> &graph, const LayerChallenges &layer_challenges,
                        const typename tree_hash_type::digest_type &replica_id, const StoreConfig &config) {

                        BOOST_LOG_TRIVIAL(info) << "generate labels";

                        const auto layers = layer_challenges.layers();
                        // For now, we require it due to changes in encodings structure.
                        std::vector<DiskStore<typename MerkleTreeType::hash_type::digest_type>> labels;
                        labels.reserve(layers);

                        std::vector<StoreConfig> label_configs;
                        label_configs.reserve(layers);

                        const auto layer_size = graph.size() * NODE_SIZE;
                        // NOTE: this means we currently keep 2x sector size around, to improve speed.
                        std::vector<auto> labels_buffer(2 * layer_size, 0u8);

                        const auto use_cache = settings::SETTINGS.lock().maximize_caching;
                        auto cache = use_cache ? Some(graph.parent_cache()) : None;

                        for (std::size_t layer = 1; layer <= layers; ++layer) {
                            BOOST_LOG_TRIVIAL(info) << std::format("generating layer: %d", layer);
                            if (const auto Some(ref mut cache) = cache) {
                                cache.reset();
                            }

                            if (layer == 1) {
                                const auto layer_labels = labels_buffer[..layer_size];
                                for (std::size_t node = 0; node < graph.size(); ++node) {
                                    create_label(graph, cache, replica_id, layer_labels, layer, node);
                                }
                            } else {
                                const auto(layer_labels, exp_labels) = labels_buffer.split_at_mut(layer_size);
                                for (std::size_t node = 0; node < graph.size(); ++node) {
                                    create_label_exp(graph, cache, replica_id, exp_labels, layer_labels, layer, node);
                                }
                            }

                            BOOST_LOG_TRIVIAL(info) << "  setting exp parents";
                            labels_buffer.copy_within(..layer_size, layer_size);

                            // Write the result to disk to avoid keeping it in memory all the time.
                            const auto layer_config =
                                StoreConfig::from_config(&config, cache_key::label_layer(layer), Some(graph.size()));

                            BOOST_LOG_TRIVIAL(info) << "  storing labels on disk";
                            // Construct and persist the layer data.
                            DiskStore<typename tree_hash_type::digest_type> layer_store =
                                DiskStore::new_from_slice_with_config(graph.size(), MerkleTreeType::base_arity,
                                                                      &labels_buffer[..layer_size],
                                                                      layer_config.clone());
                            BOOST_LOG_TRIVIAL(info)
                                << std::format("  generated layer {} store with id {}", layer, layer_config.id);

                            // Track the layer specific store and StoreConfig for later retrieval.
                            labels.push(layer_store);
                            label_configs.push(layer_config);
                        }

                        BOOST_ASSERT_MSG(labels.len() == layers, "Invalid amount of layers encoded expected");

                        return (LabelsCache<Tree> {labels}, Labels<Tree> {.labels = label_configs});
                    }

                    template<typename TreeHash>
                    BinaryMerkleTree<TreeHash> build_binary_tree(const std::vector<std::uint8_t> &tree_data,
                                                                 const StoreConfig &config) {
                        BOOST_LOG_TRIVIAL(trace) << std::format("building tree (size: %d)", tree_data.len());

                        std::size_t leafs = tree_data.size() / NODE_SIZE;
                        assert(tree_data.size() % NODE_SIZE == 0);

                        std::vector<auto> build_tree_vector;
                        build_tree_vector.reserve(leafs);

                        for (std::size_t i = 0; i < leafs; ++i) {
                            build_tree_vector.push(get_node::<K>(tree_data, i));
                        }

                        return MerkleTree::from_par_iter_with_config(build_tree_vector, config);
                    }

                    template<typename MerkleTreeType>
                    DiskTree<typename MerkleTreeType::hash_type, MerkleTreeType::base_arity,
                             MerkleTreeType::sub_tree_arity, MerkleTreeType::top_tree_arity>
                        generate_tree_c(std::size_t layers, std::size_t nodes_count, std::size_t tree_count,
                                        const std::vector<StoreConfig> &configs, const LabelsCache<tree_type> &labels) {
                        if (settings ::SETTINGS.lock().use_gpu_column_builder) {
                            return generate_tree_c_gpu<MerkleTreeType>(layers, nodes_count, tree_count, configs,
                                                                       labels);
                        } else {
                            return generate_tree_c_cpu<MerkleTreeType>(layers, nodes_count, tree_count, configs,
                                                                       labels);
                        }
                    }

                    // gather all layer data in parallel.
                    static auto generate_tree_c_gpu_spawn_0 (???) {
                        for (std::size_t layer_index = 0, layer_data::iterator layer_elements_it = layer_data.begin();
                             layer_elements_it != layer_data.end(); ++layer_index, ++layer_elements_it) {

                            const auto store = labels.labels_for_layer(layer_index + 1);
                            const auto start = (i * nodes_count) + node_index;
                            const auto end = start + chunked_nodes_count;
                            const std::vector<typename MerkleTreeType::hash_type::digest_type> elements =
                                store.read_range(std::ops::Range {start, end});
                            (*layer_elements_it).extend(elements);
                        }
                    }

                    static auto generate_tree_c_gpu_spawn_1 (???) {

                        auto column_tree_builder = ColumnTreeBuilder::<ColumnArity, TreeArity>(
                            Some(BatcherType::GPU), nodes_count, max_gpu_column_batch_size, max_gpu_tree_batch_size);

                        std::size_t i = 0;
                        auto config = &configs[i];

                        // Loop until all trees for all configs have been built.
                        while (i < configs.size()) {
                            std::vector<GenericArray<Fr, ColumnArity>> columns;
                            bool is_final;

                            std::tie(columns, is_final) = builder_rx.recv();

                            // Just add non-final column batches.
                            if (!is_final) {
                                column_tree_builder.add_columns(&columns);
                                continue;
                            };

                            // If we get here, this is a final column: build a sub-tree.
                            auto base_data, tree_data;

                            std::tie(base_data, tree_data) = column_tree_builder.add_final_columns(&columns);
                            BOOST_LOG_TRIVIAL(trace)
                                << std::format("base data len {}, tree data len {}", base_data.len(), tree_data.len());

                            const auto tree_len = base_data.len() + tree_data.len();

                            BOOST_LOG_TRIVIAL(info) << std::format("persisting base tree_c {}/{} of length {}", i + 1,
                                                                   tree_count, tree_len);
                            BOOST_ASSERT(base_data.len() == nodes_count);
                            BOOST_ASSERT(tree_len == config.size);

                            // Persist the base and tree data to disk based using the current store config.
                            const auto tree_c_store =
                                DiskStore::<typename MerkleTreeType::hash_type::digest_type>::new_with_config(
                                    tree_len, MerkleTreeType::base_arity, config.clone());

                            const auto store = Arc(RwLock(tree_c_store));
                            const auto batch_size = std::cmp::min(base_data.len(), column_write_batch_size);
                            const auto flatten_and_write_store = | data : &Vec<Fr>,
                                       offset | {data.into_par_iter()
                                                     .chunks(column_write_batch_size)
                                                     .enumerate()
                                                     .try_for_each(| (index, fr_elements) | {
                                                         std::vector<auto> buf buf.reserve(batch_size * NODE_SIZE);

                                                         for (fr_elements::iterator fr_it = fr_elements.begin();
                                                              fr_it != fr_elements.end();
                                                              ++fr_it) {

                                                             buf.extend(fr_into_bytes(*fr_it));
                                                         }
                                                         store.write().copy_from_slice(&buf[..],
                                                                                       offset + (batch_size * index))
                                                     })};

                            BOOST_LOG_TRIVIAL(trace)
                                << std::format("flattening tree_c base data of {} nodes using batch size {}",
                                               base_data.len(),
                                               batch_size);
                            flatten_and_write_store(&base_data, 0);
                            BOOST_LOG_TRIVIAL(trace) << "done flattening tree_c base data";

                            const auto base_offset = base_data.len();
                            BOOST_LOG_TRIVIAL(trace) << std::format(
                                "flattening tree_c tree data of {} nodes using batch size {} and base "
                                "offset "
                                "{}",
                                tree_data.len(), batch_size, base_offset);
                            flatten_and_write_store(&tree_data, base_offset);
                            BOOST_LOG_TRIVIAL(trace) << "done flattening tree_c tree data";

                            BOOST_LOG_TRIVIAL(trace) << "writing tree_c store data";
                            store.write().sync();
                            BOOST_LOG_TRIVIAL(trace) << "done writing tree_c store data";

                            // Move on to the next config.
                            i += 1;
                            if (i == configs.size()) {
                                break;
                            }
                            config = &configs[i];
                        }

                        return ? ? ? ;
                    }

                    static auto generate_tree_c_gpu_spawn_2 (???) {

                        for (int i = 0; i < config_count; ++i) {
                            auto node_index = 0;
                            const auto builder_tx = builder_tx.clone();
                            while (node_index != nodes_count) {
                                const auto chunked_nodes_count =
                                    std::cmp::min(nodes_count - node_index, max_gpu_column_batch_size);
                                BOOST_LOG_TRIVIAL(trace) << std::format("processing config {}/{} with column nodes {}",
                                                                        i + 1, tree_count, chunked_nodes_count);
                                std::vector<GenericArray<Fr, ColumnArity>> columns(
                                    chunked_nodes_count,
                                    GenericArray::<Fr, ColumnArity>::generate(| _i
                                                                              : usize | Fr::zero()));

                                // Allocate layer data array and insert a placeholder for each layer.
                                std::vector<std::vector<Fr>> layer_data(layers);
                                std::vector<Fr> layer_data_internal;
                                layer_data_internal.reserve(chunked_nodes_count);
                                layer_data.fill(layer_data.begin(), layer_data.end(), layer_data_internal);

                                auto ? ? ? = generate_tree_c_gpu_spawn_0(? ? ?);

                                // Copy out all layer data arranged into columns.
                                for (int layer_index = 0; layer_index < layer; layer_index++) {
                                    for (int index = 0; index < chunked_nodes_count) {
                                        columns[index][layer_index] = layer_data[layer_index][index];
                                    }
                                }

                                drop(layer_data);

                                node_index += chunked_nodes_count;
                                BOOST_LOG_TRIVIAL(trace)
                                    << std::format("node index {}/{}/{}", node_index, chunked_nodes_count, nodes_count);

                                const auto is_final = node_index == nodes_count;
                                builder_tx.send((columns, is_final));
                            }
                        }

                        auto ? ? ? = generate_tree_c_gpu_spawn_1(? ? ?);

                        return ? ? ? ;
                    }

                    template<typename MerkleTreeType>
                    DiskTree<typename MerkleTreeType::hash_type, MerkleTreeType::base_arity,
                             MerkleTreeType::sub_tree_arity, MerkleTreeType::top_tree_arity>
                        generate_tree_c_gpu(std::size_t layers, std::size_t nodes_count, std::size_t tree_count,
                                            const std::vector<StoreConfig> &configs,
                                            const LabelsCache<tree_type> &labels) {
                        BOOST_LOG_TRIVIAL(info) << "generating tree c using the GPU";
                        // Build the tree for CommC

                        BOOST_LOG_TRIVIAL(info) << "Building column hashes";

                        // NOTE: The max number of columns we recommend sending to the GPU at once is
                        // 400000 for columns and 700000 for trees (conservative soft-limits discussed).
                        //
                        // 'column_write_batch_size' is how many nodes to chunk the base layer of data
                        // into when persisting to disk.
                        //
                        // Override these values with care using environment variables:
                        // FIL_PROOFS_MAX_GPU_COLUMN_BATCH_SIZE, FIL_PROOFS_MAX_GPU_TREE_BATCH_SIZE, and
                        // FIL_PROOFS_COLUMN_WRITE_BATCH_SIZE respectively.
                        const auto max_gpu_column_batch_size = settings::SETTINGS.lock().max_gpu_column_batch_size;
                        const auto max_gpu_tree_batch_size = settings::SETTINGS.lock().max_gpu_tree_batch_size;
                        const auto column_write_batch_size = settings::SETTINGS.lock().column_write_batch_size;

                        // This channel will receive batches of columns and add them to the ColumnTreeBuilder.
                        const auto(builder_tx, builder_rx) = mpsc::sync_channel(0);
                        mpsc::sync_channel::<(std::vector<GenericArray<Fr, ColumnArity>>, bool)>(
                            max_gpu_column_batch_size * ColumnArity::to_usize() * 32);

                        const auto config_count = configs.len();    // Don't move config into closure below.

                        auto ? ? ? = generate_tree_c_gpu_spawn_2(? ? ?);

                        return create_disk_tree<
                            DiskTree<typename MerkleTreeType::hash_type, MerkleTreeType::base_arity,
                                     MerkleTreeType::sub_tree_arity, MerkleTreeType::top_tree_arity>>(configs[0].size,
                                                                                                      &configs);
                    }

                    static void generate_tree_c_cpu_spawn_0(stf::size_t chunk, auto &hashes_chunk) {
                        for (std::size_t j = 0, hashes_chunk::iterator hash_it = hashes_chunk.begin();
                             hash_it != hashes_chunk.end(); ++j, ++hash_it) {

                            const std::vector<auto> data;
                            data.reserve(layers);

                            for (std::size_t layer = 1; layer <= layers; ++layer) {
                                const auto store = labels.labels_for_layer(layer);
                                const typename MerkleTreeType::hash_type::digest_type el =
                                    store.read_at((i * nodes_count) + j + chunk * chunk_size);
                                data.push(el);
                            }

                            (*hash_it) = hash_single_column(data.begin(), data.end());
                        }
                    }

                    template<typename MerkleTreeType>
                    DiskTree<typename MerkleTreeType::hash_type, MerkleTreeType::base_arity,
                             MerkleTreeType::sub_tree_arity, MerkleTreeType::top_tree_arity>
                        generate_tree_c_cpu(std::size_t layers, std::size_t nodes_count, std::size_t tree_count,
                                            const std::vector<StoreConfig> &configs,
                                            const LabelsCache<tree_type> &labels) {
                        BOOST_LOG_TRIVIAL(info) << "generating tree c using the CPU";

                        BOOST_LOG_TRIVIAL(info) << "Building column hashes";

                        std::vector<auto> trees;
                        trees.reserve(tree_count);

                        for (std::size_t i = 0, configs::iterator config_it = configs.begin();
                             config_it != configs.end(); ++i, ++config_it) {

                            std::vector<typename MerkleTreeType::hash_type::digest_type> hashes(
                                nodes_count, MerkleTreeType::hash_type::digest_type::default());

                            const auto n = num_cpus::get();

                            // only split if we have at least two elements per thread
                            std::size_t num_chunks = (n > nodes_count * 2) ? 1 : n;

                            // chunk into n chunks
                            std::size_t chunk_size =
                                std::ceil(static_cast<double>(nodes_count) / static_cast<double>(num_chunks));

                            // calculate all n chunks in parallel
                            for ((chunk, hashes_chunk) : hashes.chunks_mut(chunk_size).enumerate()) {

                                generate_tree_c_cpu_spawn_0(chunk, hashes_chunk);
                            }

                            BOOST_LOG_TRIVIAL(info) << std::format("building base tree_c %d/%d", i + 1, tree_count);
                            trees.push(DiskTree<typename MerkleTreeType::hash_type, MerkleTreeType::base_arity,
                                                MerkleTreeType::sub_tree_arity, MerkleTreeType::top_tree_arity>::
                                           from_par_iter_with_config(hashes.into_par_iter(), (*config_it).clone()));
                        }

                        BOOST_ASSERT(tree_count == trees.len());
                        return create_disk_tree<
                            DiskTree<typename MerkleTreeType::hash_type, MerkleTreeType::base_arity,
                                     MerkleTreeType::sub_tree_arity, MerkleTreeType::top_tree_arity>>(configs[0].size,
                                                                                                      &configs);
                    }

                    static auto generate_tree_r_last_spawn_0(
                            const DiskStore<typename MerkleTreeType::hash_type::digest_type> last_layer_labels,
                            ???){

                        for (int i = 0; i < config_count; i++) {
                            std::size_t node_index = 0;
                            while (node_index != nodes_count) {
                                const std::size_t chunked_nodes_count =
                                    std::cmp::min(nodes_count - node_index, max_gpu_tree_batch_size);
                                const std::size_t start = (i * nodes_count) + node_index;
                                const std::size_t end = start + chunked_nodes_count;

                                BOOST_LOG_TRIVIAL(trace) << std::format(
                                    "processing config %d/%d with leaf nodes {} [%d, %d, %d-%d]", i + 1, tree_count,
                                    chunked_nodes_count, node_index, nodes_count, start, end);

                                const auto encoded_data =
                                    last_layer_labels.read_range(start..end)
                                        .into_par_iter()
                                        .zip(data[(start * NODE_SIZE)..(end * NODE_SIZE)].par_chunks_mut(NODE_SIZE))
                                        .map(| (key, data_node_bytes) | {
                                            const auto data_node =
                                                MerkleTreeType::hash_type::digest_type::try_from_bytes(data_node_bytes);
                                            const auto encoded_node =
                                                encode::<typename MerkleTreeType::hash_type::digest_type>(key,
                                                                                                          data_node);
                                            data_node_bytes.copy_from_slice(AsRef::<[u8]>::as_ref(&encoded_node));

                                            encoded_node
                                        });

                                node_index += chunked_nodes_count;
                                BOOST_LOG_TRIVIAL(trace)
                                    << std::format("node index %d/%d/%d", node_index, chunked_nodes_count, nodes_count);

                                std::vector<_> encoded = encoded_data.into_par_iter().map(| x | x.into()).collect();

                                const auto is_final = node_index == nodes_count;
                                builder_tx.send((encoded, is_final));
                            }
                        }
                    }

                    static auto generate_tree_r_last_spawn_1(StoreConfig &tree_r_last_config, ???){

                        auto tree_builder = TreeBuilder::<MerkleTreeType::base_arity>(
                            Some(BatcherType::GPU), nodes_count, max_gpu_tree_batch_size,
                            tree_r_last_config.rows_to_discard);

                        std::size_t i = 0;
                        auto config = &configs[i];

                        // Loop until all trees for all configs have been built.
                        while (i < configs.size()) {

                            const auto(encoded, is_final) = builder_rx.recv();

                            // Just add non-final leaf batches.
                            if (!is_final) {
                                tree_builder.add_leaves(&encoded);
                                continue;
                            };

                            // If we get here, this is a final leaf batch: build a sub-tree.
                            BOOST_LOG_TRIVIAL(info)
                                << std::format("building base tree_r_last with GPU %d/%d", i + 1, tree_count);
                            const auto tree_data = std::get<1>(tree_builder.add_final_leaves(&encoded));

                            const auto tree_data_len = tree_data.len();
                            const auto cache_size = get_merkle_tree_cache_size(
                                get_merkle_tree_leafs(config.size, MerkleTreeType::base_arity),
                                MerkleTreeType::base_arity, config.rows_to_discard);

                            BOOST_ASSERT(tree_data_len == cache_size);

                            const std::vector<_> flat_tree_data =
                                tree_data.into_par_iter().flat_map(| el | fr_into_bytes(&el)).collect();

                            // Persist the data to the store based on the current config.
                            const boost::filesystem::path tree_r_last_path =
                                StoreConfig::data_path(&config.path, &config.id);

                            BOOST_LOG_TRIVIAL(trace)
                                << std::format("persisting tree r of len %d with {} rows to discard at path %s",
                                               tree_data_len,
                                               config.rows_to_discard,
                                               tree_r_last_path.string());

                            boost::filesystem::ofstream f(tree_r_last_path);

                            f << flat_tree_data;

                            // Move on to the next config.
                            i += 1;
                            if (i == configs.size()) {
                                break;
                            }
                            config = &configs[i];
                        }
                    }

                    template<typename TreeArity = PoseidonArity>
                    LCTree<tree_hash_type, typename tree_type::Arity, typename tree_type::SubTreeArity,
                           typename tree_type::TopTreeArity>
                        generate_tree_r_last(Data &data, std::size_t nodes_count, std::size_t tree_count,
                                             const StoreConfig &tree_r_last_config,
                                             const boost::filesystem::path &replica_path,
                                             const LabelsCache<Tree> &labels) {

                        std::vector<StoreConfig> configs;
                        ReplicaConfig replica_config;
                        std::tie(configs, replica_config) =
                            split_config_and_replica(tree_r_last_config.clone(), replica_path, nodes_count, tree_count);

                        data.ensure_data();
                        const DiskStore<typename MerkleTreeType::hash_type::digest_type> last_layer_labels =
                            labels.labels_for_last_layer();

                        if (settings ::SETTINGS.lock().use_gpu_tree_builder) {

                            BOOST_LOG_TRIVIAL(info) << "generating tree r last using the GPU";

                            std::uint max_gpu_tree_batch_size = settings::SETTINGS.lock().max_gpu_tree_batch_size;

                            auto builder_tx, builder_rx;
                            // This channel will receive batches of leaf nodes and add them to the TreeBuilder.
                            std::tie(builder_tx, builder_rx) = mpsc::sync_channel::<(Vec<Fr>, bool)>(0);
                            const auto config_count = configs.len();    // Don't move config into closure below.

                            auto ? ? ? = generate_tree_r_last_spawn_0(last_layer_labels, ? ? ?);

                            auto ? ? ? = generate_tree_r_last_spawn_1(tree_r_last_config, ? ? ?);
                        } else {
                            BOOST_LOG_TRIVIAL(info) << "generating tree r last using the CPU";

                            const auto size = Store::len(last_layer_labels);

                            auto start = 0;
                            auto end = size / tree_count;

                            for (std::size_t i = 0, configs::iterator config_it = configs.begin();
                                 config_it != configs.end(); ++i, ++config_it) {

                                const auto encoded_data =
                                    last_layer_labels.read_range(start..end)
                                        .into_par_iter()
                                        .zip(data[(start * NODE_SIZE)..(end * NODE_SIZE)].par_chunks_mut(NODE_SIZE))
                                        .map(| (key, data_node_bytes) | {
                                            const auto data_node =
                                                MerkleTreeType::hash_type::digest_type::try_from_bytes(data_node_bytes);

                                            const auto encoded_node =
                                                encode::<typename MerkleTreeType::hash_type::digest_type>(key,
                                                                                                          data_node);
                                            data_node_bytes.copy_from_slice(AsRef::<[u8]>::as_ref(&encoded_node));

                                            encoded_node
                                        });

                                BOOST_LOG_TRIVIAL(info)
                                    << std::format("building base tree_r_last with CPU %d/%d", i + 1, tree_count);
                                LCTree<typename MerkleTreeType::hash_type, MerkleTreeType::base_arity, 0,
                                       0>::from_par_iter_with_config(encoded_data, (*config_it).clone());

                                start = end;
                                end += size / tree_count;
                            }
                        };

                        return create_lc_tree<LCTree<typename MerkleTreeType::hash_type, MerkleTreeType::base_arity,
                                                     MerkleTreeType::sub_tree_arity, MerkleTreeType::top_tree_arity>>(
                            tree_r_last_config.size, &configs, &replica_config);
                    }

                    TransformedLayers<tree_type, hash_type> transform_and_replicate_layers(
                        const StackedBucketGraph<tree_hash_type> &graph, const LayerChallenges &layer_challenges,
                        const typename hash_type::digest_type &replica_id, const Data &data,
                        const BinaryMerkleTree<G> &data_tree, const StoreConfig &config,
                        const boost::filesystem::path &replica_path) {
                        // Generate key layers.
                        const Labels<tree_type> labels =
                            std::get<1>(generate_labels(graph, layer_challenges, replica_id, config.clone()));

                        return transform_and_replicate_layers_inner(graph, layer_challenges, data, data_tree, config,
                                                                    replica_path, labels);
                    }

                    TransformedLayers<tree_type, hash_type> transform_and_replicate_layers_inner(
                        const StackedBucketGraph<tree_hash_type> &graph, const LayerChallenges &layer_challenges,
                        const typename hash_type::digest_type &replica_id, const Data &data,
                        const BinaryMerkleTree<G> &data_tree, const StoreConfig &config,
                        const boost::filesystem::path &replica_path, const Labels<tree_type> &label_configs) {

                        BOOST_LOG_TRIVIAL(trace) << "transform_and_replicate_layers";

                        std::size_t nodes_count = graph.size();

                        assert(data.len() == nodes_count * NODE_SIZE);
                        BOOST_LOG_TRIVIAL(trace) << std::format("nodes count %d, data len {}", nodes_count, data.len());

                        std::size_t tree_count = get_base_tree_count::<Tree>();
                        std::size_t nodes_count = graph.size() / tree_count;

                        // Ensure that the node count will work for binary and oct arities.
                        bool binary_arity_valid = is_merkle_tree_size_valid(nodes_count, BINARY_ARITY);
                        bool other_arity_valid = is_merkle_tree_size_valid(nodes_count, MerkleTreeType::base_arity);

                        BOOST_LOG_TRIVIAL(trace) << std::format("is_merkle_tree_size_valid(%d, BINARY_ARITY) = {}",
                                                                nodes_count, binary_arity_valid);
                        BOOST_LOG_TRIVIAL(trace) << std::format("is_merkle_tree_size_valid(%d, {}) = {}", nodes_count,
                                                                MerkleTreeType::base_arity, other_arity_valid);

                        assert(binary_arity_valid);
                        assert(other_arity_valid);

                        std::size_t layers = layer_challenges.layers();
                        assert(layers > 0);

                        // Generate all store configs that we need based on the
                        // cache_path in the specified config.
                        StoreConfig tree_d_config = StoreConfig::from_config(
                            config, cache_key::CommDTree.to_string(), get_merkle_tree_len(nodes_count, BINARY_ARITY));
                        tree_d_config.rows_to_discard = default_rows_to_discard(nodes_count, BINARY_ARITY);

                        StoreConfig tree_r_last_config =
                            StoreConfig::from_config(config, cache_key::CommRLastTree.to_string(),
                                                     get_merkle_tree_len(nodes_count, MerkleTreeType::base_arity));

                        // A default 'rows_to_discard' value will be chosen for tree_r_last, unless the user overrides
                        // this value via the environment setting (FIL_PROOFS_ROWS_TO_DISCARD).  If this value is
                        // specified, no checking is done on it and it may result in a broken configuration.  Use with
                        // caution.
                        tree_r_last_config.rows_to_discard =
                            default_rows_to_discard(nodes_count, MerkleTreeType::base_arity);

                        BOOST_LOG_TRIVIAL(trace)
                            << std::format("tree_r_last using rows_to_discard={}", tree_r_last_config.rows_to_discard);

                        StoreConfig tree_c_config = StoreConfig::from_config(
                            &config, cache_key::CommCTree.to_string(),
                            Some(get_merkle_tree_len(nodes_count, MerkleTreeType::base_arity)), );
                        tree_c_config.rows_to_discard =
                            default_rows_to_discard(nodes_count, MerkleTreeType::base_arity);

                        LabelsCache<tree_type> labels(&label_configs);
                        const auto configs = split_config(tree_c_config.clone(), tree_count);

                        typename tree_hash_type::digest_type tree_c_root;
                        if (layers == 2) {
                            const auto tree_c = generate_tree_c::<U2, MerkleTreeType::base_arity>(
                                layers, nodes_count, tree_count, configs, &labels);
                            tree_c_root = tree_c.root();
                        } else if (layers == 8) {
                            const auto tree_c = generate_tree_c::<U8, MerkleTreeType::base_arity>(
                                layers, nodes_count, tree_count, configs, &labels);
                            tree_c_root = tree_c.root();
                        } else if (layers == 11) {
                            const auto tree_c = generate_tree_c::<U11, MerkleTreeType::base_arity>(
                                layers, nodes_count, tree_count, configs, &labels);
                            tree_c_root = tree_c.root();
                        } else {
                            throw "Unsupported column arity";
                        }

                        BOOST_LOG_TRIVIAL(info) << "tree_c done";

                        // Build the MerkleTree over the original data (if needed).
                        BinaryMerkleTree<Hash> tree_d;
                        if (data_tree.empty()) {
                            BOOST_LOG_TRIVIAL(trace) << "building merkle tree for the original data";
                            data.ensure_data();
                            build_binary_tree::<G>(data, tree_d_config.clone());
                        } else {
                            BOOST_LOG_TRIVIAL(trace) << "using existing original data merkle tree";
                            BOOST_ASSERT(t.len() == 2 * (data.len() / NODE_SIZE) - 1);
                            tree_d = t;
                        }    // namespace stacked

                        tree_d_config.size = Some(tree_d.len());
                        BOOST_ASSERT(tree_d_config.size == tree_d.size());
                        auto tree_d_root = tree_d.root();
                        drop(tree_d);

                        // Encode original data into the last layer.
                        BOOST_LOG_TRIVIAL(info) << "building tree_r_last";
                        auto tree_r_last = generate_tree_r_last::<MerkleTreeType::base_arity>(
                            data, nodes_count, tree_count, tree_r_last_config.clone(), replica_path.clone(), &labels);

                        BOOST_LOG_TRIVIAL(info) << "tree_r_last done";

                        const auto tree_r_last_root = tree_r_last.root();
                        drop(tree_r_last);

                        data.drop_data();

                        // comm_r = H(comm_c || comm_r_last)
                        typename MerkleTreeType::hash_type::digest_type comm_r =
                            <typename MerkleTreeType::hash_type>::Function::hash2(&tree_c_root, &tree_r_last_root);

                        return std::make_tuple(
                            Tau<typename MerkleTreeType::hash_type::digest_type, typename Hash::digest_type>(
                                {.comm_d = tree_d_root, .comm_r}),
                            PersistentAux<typename MerkleTreeType::hash_type::digest_type>(
                                {.comm_c = tree_c_root, .comm_r_last = tree_r_last_root}),
                            TemporaryAux<MerkleTreeType, Hash>(
                                {.labels = label_configs, .tree_d_config, .tree_r_last_config, .tree_c_config}));
                    }

                    /// Phase1 of replication.
                    Labels<tree_type> replicate_phase1(const PublicParams<tree_type> &pp,
                                                       const typename tree_hash_type::digest_type &replica_id,
                                                       const StoreConfig &config) {
                        BOOST_LOG_TRIVIAL(info) << "replicate_phase1";

                        return std::get<1>(generate_labels(&pp.graph, &pp.layer_challenges, replica_id, config));
                    }

                    std::tuple << Self as PoRep <'a, typename MerkleTreeType::hash_type, G>>::Tau,  <
                        Self as PoRep <'a, typename MerkleTreeType::hash_type, G> >::ProverAux >  replicate_phase2(
                            const PublicParams<tree_type> &pp, const Labels<tree_type> &labels, const Data &data,
                            const BinaryMerkleTree<hash_type> &data_tree, const StoreConfig &config,
                            const boost::filesystem::path &replica_path) {
                        BOOST_LOG_TRIVIAL(info) << "replicate_phase2";

                        return transform_and_replicate_layers_inner(&pp.graph, &pp.layer_challenges, data,
                                                                    Some(data_tree), config, replica_path, labels);
                    }

                    tree_type &_a;
                    hash_type &_b;
                };    // StackedDrg
            }         // namespace vanilla
        }             // namespace stacked
    }                 // namespace filecoin
}    // namespace nil

#endif

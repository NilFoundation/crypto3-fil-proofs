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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_PROOF_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_PROOF_HPP

#include <boost/filesystem/path.hpp>

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/column.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/params.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/porep.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/challenges.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/create_label.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/encoding_proof.hpp>
#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/labelling_proof.hpp>

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

                    std::vector<std::vector<Proof<tree_type, hash_type>>> prove_layers(
                        const StackedBucketGraph<tree_hash_type> &graph,
                        const PublicInputs<typename tree_hash_type::digest_type, typename hash_type::digest_type>
                            &pub_inputs,
                        const PersistentAux<typename tree_hash_type::digest_type> &p_aux,
                        const TemporaryAuxCache<tree_type, hash_type> &t_aux,
                        const LayerChallenges &layer_challenges,
                        std::size_t layers,
                        std::size_t _total_layers,
                        std::size_t partition_count) {

                        assert(layers > 0);
                        assert(t_aux.labels.size() == layers);

                        std::size_t graph_size = graph.size();

                        // Sanity checks on restored trees.
                        assert(pub_inputs.tau.is_some());
                        assert(pub_inputs.tau.as_ref().comm_d == t_aux.tree_d.root());

                        auto get_drg_parents_columns = [&](std::size_t x) -> std::vector<Column<tree_hash_type>> {
                            std::size_t base_degree = graph.base_graph().degree();

                            std::vector<Column<tree_hash_type>> columns(base_degree);

                            std::vector<std::uint64_t> parents(0, base_degree);
                            graph.base_parents(x, parents);

                            for (std::uint64_t parent : parents) {
                                columns.push_back(t_aux.column(*parent));
                            }

                            assert(columns.size() == base_degree);

                            return columns;
                        };

                        auto get_exp_parents_columns = [&](std::size_t x) -> std::vector<Column<tree_hash_type>> {
                            auto mut parents = vec ![0; graph.expansion_degree()];
                            graph.expanded_parents(x, &mut parents) ? ;

                            return parents.iter().map(| parent | t_aux.column(*parent)).collect();
                        };

                    (0..partition_count)
                        .map(|k| {
                            trace !("proving partition {}/{}", k + 1, partition_count);

                            // Derive the set of challenges we are proving over.
                            auto challenges = pub_inputs.challenges(layer_challenges, graph_size, Some(k));

                            // Stacked commitment specifics
                        challenges
                        .into_par_iter()
                        .enumerate()
                        .map(|(challenge_index, challenge)| {
                                trace !(" challenge {} ({})", challenge, challenge_index);
                                assert !(challenge < graph.size(), "Invalid challenge");
                                assert !(challenge > 0, "Invalid challenge");

                                // Initial data layer openings (c_X in Comm_D)
                                auto comm_d_proof = t_aux.tree_d.gen_proof(challenge) ? ;
                                assert !(comm_d_proof.validate(challenge));

                                // Stacked replica column openings
                                auto rcp = {
                                    auto(c_x, drg_parents,
                                        exp_parents) = {assert_eq !(p_aux.comm_c, t_aux.tree_c.root());
                                auto tree_c = &t_aux.tree_c;

                                // All labels in C_X
                                trace !("  c_x");
                                auto c_x = t_aux.column(std::uint_32t(challenge)) ?.into_proof(tree_c) ? ;

                                // All labels in the DRG parents.
                                trace !("  drg_parents");
                                auto drg_parents =
                                    get_drg_parents_columns(challenge) ?.into_iter()
                                                                            .map(| column | column.into_proof(tree_c))
                                                                            .collect::<Result<_>>() ?
                                    ;

                                // Labels for the expander parents
                                trace !("  exp_parents");
                                auto exp_parents =
                                    get_exp_parents_columns(challenge) ?.into_iter()
                                                                            .map(| column | column.into_proof(tree_c))
                                                                            .collect::<Result<_>>() ?
                                    ;

                                (c_x, drg_parents, exp_parents)
                                };

                                ReplicaColumnProof {
                                c_x, drg_parents, exp_parents,
                                }
                            };

                            // Final replica layer openings
                            trace!("final replica layer openings");
                            auto comm_r_last_proof = t_aux.tree_r_last.gen_cached_proof(
                                challenge,
                                Some(t_aux.tree_r_last_config_rows_to_discard),
                            )?;

                            debug_assert!(comm_r_last_proof.validate(challenge));

                            // Labeling Proofs Layer 1..l
                            auto mut labeling_proofs = Vec::with_capacity(layers);
                            auto mut encoding_proof = None;

                            for (int layer = 1; layer != layers; layer++) {
                            trace !("  encoding proof layer {}", layer);
                            std::vector<typename tree_hash_type::digest_type> parents_data;
                            if (layer == 1) {
                                auto mut parents = vec ![0; graph.base_graph().degree()];
                                graph.base_parents(challenge, &mut parents) ? ;

                                parents_data = parents.into_iter()
                                                   .map(| parent | t_aux.domain_node_at_layer(layer, parent))
                                                   .collect::<Result<_>>();
                            } else {
                                auto mut parents = vec ![0; graph.degree()];
                                graph.parents(challenge, &mut parents) ? ;
                                auto base_parents_count = graph.base_graph().degree();

                                parents_data = parents.into_iter()
                                                   .enumerate()
                                                   .map(| (i, parent) |
                                                        {
                                                            if (i < base_parents_count) {
                                                                // parents data for base parents is from the current
                                                                // layer
                                                                t_aux.domain_node_at_layer(layer, parent)
                                                            } else {
                                                                // parents data for exp parents is from the previous
                                                                // layer
                                                                t_aux.domain_node_at_layer(layer - 1, parent)
                                                            }
                                                        })
                                                   .collect::<Result<_>>();
                            };

                            // repeat parents
                            auto mut parents_data_full = vec ![Default::default(); TOTAL_PARENTS];
                            for (chunk : parents_data_full.chunks_mut(parents_data.size())) {
                                chunk.copy_from_slice(&parents_data[..chunk.size()]);
                            }

                            auto proof = LabelingProof::<typename MerkleTreeType::hash_type>::new (std::uint_32t(layer), 
                                std::uint_64t(challenge), parents_data_full.clone());

                            auto labeled_node = rcp.c_x.get_node_at_layer(layer) ? ;
                            assert !(proof.verify(&pub_inputs.replica_id, &labeled_node),
                                     format !("Invalid encoding proof generated at layer {}", layer));
                            trace !("Valid encoding proof generated at layer {}", layer);

                            labeling_proofs.push(proof);

                            if (layer == layers) {
                                encoding_proof =
                                    Some(EncodingProof::new (std::uint_32t(layer), std::uint_64t(challenge), parents_data_full, ));
                            }
                            }

                            Ok(Proof {
                                comm_d_proofs: comm_d_proof,
                                replica_column_proofs: rcp,
                                comm_r_last_proof,
                                labeling_proofs,
                                encoding_proof: encoding_proof.expect("invalid tapering"),
                            })
                    })
                        .collect()
                    })
                    .collect();
            }    // namespace vanilla

            void extract_and_invert_transform_layers(const StackedBucketGraph<tree_hash_type> &graph,
                                                     const LayerChallenges &layer_challenges,
                                                     const typename tree_hash_type::digest_type &replica_id,
                                                     const std::vector<std::uint8_t> &data, const StoreConfig &config) {
                trace !("extract_and_invert_transform_layers");

                auto layers = layer_challenges.layers();
                assert(layers > 0);

                // generate labels
                auto(labels, _) = generate_labels(graph, layer_challenges, replica_id, config) ? ;

                auto last_layer_labels = labels.labels_for_last_layer() ? ;
                auto size = merkletree::store::Store::len(last_layer_labels);

                for ((key, encoded_node_bytes)
                    : last_layer_labels.read_range(0..size) ?.into_iter().zip(data.chunks_mut(NODE_SIZE))) {
                    auto encoded_node = <typename MerkleTreeType::hash_type>::Domain::try_from_bytes(encoded_node_bytes) ? ;
                    auto data_node = decode:: << typename MerkleTreeType::hash_type> ::Domain > (key, encoded_node);

                    // store result in the data
                    encoded_node_bytes.copy_from_slice(AsRef::<[u8]>::as_ref(&data_node));
                }
            }

            std::tuple<LabelsCache<tree_type>, Labels<tree_type>>
                generate_labels(const StackedBucketGraph<tree_hash_type> &graph,
                                const LayerChallenges &layer_challenges,
                                const typename tree_hash_type::digest_type &replica_id, const StoreConfig &config) {
                info !("generate labels");

                auto layers = layer_challenges.layers();
                // For now, we require it due to changes in encodings structure.
                auto mut labels : Vec<DiskStore << typename MerkleTreeType::hash_type>::Domain >> = Vec::with_capacity(layers);
                auto mut label_configs : Vec<StoreConfig> = Vec::with_capacity(layers);

                auto layer_size = graph.size() * NODE_SIZE;
                // NOTE: this means we currently keep 2x sector size around, to improve speed.
                auto mut labels_buffer = vec ![0u8; 2 * layer_size];

                auto use_cache = settings::SETTINGS.lock().maximize_caching;
                auto mut cache = if use_cache {
                            Some(graph.parent_cache()?)
                }
                else {None};

                    for
                        layer in 1.. = layers {
                            info !("generating layer: {}", layer);
                            if auto
                                Some(ref mut cache) = cache {
                                    cache.reset() ? ;
                                }

                            if layer
                                == 1 {
                                    auto layer_labels = &mut labels_buffer[..layer_size];
                            for
                                node in 0..graph.size() {
                                    create_label(graph, cache.as_mut(), replica_id, layer_labels, layer, node) ? ;
                                }
                                }
                            else {
                                auto(layer_labels, exp_labels) = labels_buffer.split_at_mut(layer_size);
                            for
                                node in 0..graph.size() {
                                    create_label_exp(graph, cache.as_mut(), replica_id, exp_labels, layer_labels, layer,
                                                     node, ) ?
                                        ;
                                }
                            }

                            info !("  setting exp parents");
                            labels_buffer.copy_within(..layer_size, layer_size);

                            // Write the result to disk to avoid keeping it in memory all the time.
                            auto layer_config =
                                StoreConfig::from_config(&config, cache_key::label_layer(layer), Some(graph.size()));

                            info !("  storing labels on disk");
                            // Construct and persist the layer data.
                            DiskStore<typename tree_hash_type::digest_type> layer_store =
                                DiskStore::new_from_slice_with_config(graph.size(), MerkleTreeType::base_arity,
                                                                      &labels_buffer[..layer_size],
                                                                      layer_config.clone());
                            info !("  generated layer {} store with id {}", layer, layer_config.id);

                            // Track the layer specific store and StoreConfig for later retrieval.
                            labels.push(layer_store);
                            label_configs.push(layer_config);
                        }

                    assert_eq !(labels.len(), layers, "Invalid amount of layers encoded expected");

                    Ok((LabelsCache::<Tree> {labels}, Labels::<Tree> {
                        labels : label_configs,
                        _h : PhantomData,
                    }, ))
            }

            template<typename TreeHash>
            BinaryMerkleTree<TreeHash> build_binary_tree(const std::vector<std::uint8_t> &tree_data,
                                                         const StoreConfig &config) {
                trace !("building tree (size: {})", tree_data.len());

                std::size_t leafs = tree_data.size() / NODE_SIZE;
                assert(tree_data.size() % NODE_SIZE == 0);

                MerkleTree<TreeHash> tree =
                    MerkleTree::from_par_iter_with_config((0..leafs)
                                                              .into_par_iter()
                                                              // TODO: proper error handling instead of `unwrap()`
                                                              .map(| i | get_node::<K>(tree_data, i)),
                                                          config);
                return tree;
            }

            template<typename ColumnArity = PoseidonArity, typename TreeArity = PoseidonArity>
            DiskTree<tree_hash_type, typename tree_type::Arity, typename tree_type::SubTreeArity,
                     typename tree_type::TopTreeArity>
                generate_tree_c(std::size_t layers, std::size_t nodes_count, std::size_t tree_count,
                                const std::vector<StoreConfig> &configs, const LabelsCache<tree_type> &labels) {
                if (settings ::SETTINGS.lock().use_gpu_column_builder) {
                    Self::generate_tree_c_gpu::<ColumnArity, TreeArity>(layers, nodes_count, tree_count, configs,
                                                                        labels, )
                } else {
                    Self::generate_tree_c_cpu::<ColumnArity, TreeArity>(layers, nodes_count, tree_count, configs,
                                                                        labels, )
                }
            }

            template<typename ColumnArity = PoseidonArity, typename TreeArity = PoseidonArity>
            DiskTree<tree_hash_type, typename tree_type::Arity, typename tree_type::SubTreeArity,
                     typename tree_type::TopTreeArity>
                generate_tree_c_gpu(std::size_t layers, std::size_t nodes_count, std::size_t tree_count,
                                    const std::vector<StoreConfig> &configs, const LabelsCache<tree_type> &labels) {
                info !("generating tree c using the GPU");
                // Build the tree for CommC
                measure_op(
                    GenerateTreeC, || {
                        info !("Building column hashes");

                        // NOTE: The max number of columns we recommend sending to the GPU at once is
                        // 400000 for columns and 700000 for trees (conservative soft-limits discussed).
                        //
                        // 'column_write_batch_size' is how many nodes to chunk the base layer of data
                        // into when persisting to disk.
                        //
                        // Override these values with care using environment variables:
                        // FIL_PROOFS_MAX_GPU_COLUMN_BATCH_SIZE, FIL_PROOFS_MAX_GPU_TREE_BATCH_SIZE, and
                        // FIL_PROOFS_COLUMN_WRITE_BATCH_SIZE respectively.
                        auto max_gpu_column_batch_size =
                            settings::SETTINGS.lock().max_gpu_column_batch_size;
                        auto max_gpu_tree_batch_size =
                            settings::SETTINGS.lock().max_gpu_tree_batch_size;
                        auto column_write_batch_size =
                            settings::SETTINGS.lock().column_write_batch_size;

                        // This channel will receive batches of columns and add them to the ColumnTreeBuilder.
                        auto(builder_tx, builder_rx) = mpsc::sync_channel(0);
                        mpsc::sync_channel::<(Vec<GenericArray<Fr, ColumnArity>>, bool)>(
                            max_gpu_column_batch_size * ColumnArity::to_usize() * 32, );

                        auto config_count = configs.len();    // Don't move config into closure below.
                        rayon::scope(| s | {
                            s.spawn(move | _ | {
                                for (int i = 0; i < config_count; ++i) {
                                    auto mut node_index = 0;
                                    auto builder_tx = builder_tx.clone();
                                    while (node_index != nodes_count) {
                                        auto chunked_nodes_count =
                                            std::cmp::min(nodes_count - node_index, max_gpu_column_batch_size);
                                        trace !("processing config {}/{} with column nodes {}", i + 1, tree_count,
                                                chunked_nodes_count, );
                                        auto mut columns
                                            : Vec<GenericArray<Fr, ColumnArity>> =
                                                  vec ![GenericArray::<Fr, ColumnArity>::generate(| _i
                                                                                                  : usize | Fr::zero());
                                                      chunked_nodes_count];

                                        // Allocate layer data array and insert a placeholder for each layer.
                                        auto mut layer_data : Vec<Vec<Fr>> =
                                                                 vec ![Vec::with_capacity(chunked_nodes_count); layers];

                                        rayon::scope(| s | {
                                            // capture a shadowed version of layer_data.
                                            auto layer_data : &mut Vec<_> = &mut layer_data;

                                            // gather all layer data in parallel.
                                            s.spawn(move | _ | {
                                                for ((layer_index, layer_elements) :
                                                     layer_data.iter_mut().enumerate()) {
                                                    auto store = labels.labels_for_layer(layer_index + 1);
                                                    auto start = (i * nodes_count) + node_index;
                                                    auto end = start + chunked_nodes_count;
                                                    auto elements : Vec << typename MerkleTreeType::hash_type> ::Domain >
                                                        = store.read_range(std::ops::Range {start, end})
                                                              .expect("failed to read store range");
                                                    layer_elements.extend(elements.into_iter().map(Into::into));
                                                }
                                            });
                                        });

                                        // Copy out all layer data arranged into columns.
                                        for (int layer_index = 0; layer_index < layer; layer_index++) {
                                            for (int index = 0; index < chunked_nodes_count) {
                                                columns[index][layer_index] = layer_data[layer_index][index];
                                            }
                                        }

                                        drop(layer_data);

                                        node_index += chunked_nodes_count;
                                        trace !("node index {}/{}/{}", node_index, chunked_nodes_count, nodes_count, );

                                        auto is_final = node_index == nodes_count;
                                        builder_tx.send((columns, is_final)).expect("failed to send columns");
                                    }
                                }
                            });
                            auto configs = &configs;
                            s.spawn(move | _ | {
                                auto mut column_tree_builder = ColumnTreeBuilder::<ColumnArity, TreeArity, >::new (
                                                                  Some(BatcherType::GPU), nodes_count,
                                                                  max_gpu_column_batch_size, max_gpu_tree_batch_size, )
                                                                  .expect("failed to create ColumnTreeBuilder");

                                auto mut i = 0;
                                auto mut config = &configs[i];

                                // Loop until all trees for all configs have been built.
                                while (i < configs.size()) {
                                    auto(columns, is_final) :
                                        (Vec<GenericArray<Fr, ColumnArity>>, bool) =
                                            builder_rx.recv().expect("failed to recv columns");

                                    // Just add non-final column batches.
                                    if (!is_final) {
                                        column_tree_builder.add_columns(&columns).expect("failed to add columns");
                                        continue;
                                    };

                                    // If we get here, this is a final column: build a sub-tree.
                                    auto(base_data, tree_data) = column_tree_builder.add_final_columns(&columns).expect(
                                        "failed to add final columns");
                                    trace !("base data len {}, tree data len {}", base_data.len(), tree_data.len());
                                    auto tree_len = base_data.len() + tree_data.len();
                                    info !("persisting base tree_c {}/{} of length {}", i + 1, tree_count, tree_len, );
                                    assert_eq !(base_data.len(), nodes_count);
                                    assert_eq !(tree_len, config.size);

                                    // Persist the base and tree data to disk based using the current store config.
                                    auto tree_c_store =
                                        DiskStore:: << typename MerkleTreeType::hash_type> ::Domain >
                                        ::new_with_config(tree_len, MerkleTreeType::base_arity, config.clone(), )
                                            .expect("failed to create DiskStore for base tree data");

                                    auto store = Arc::new (RwLock::new (tree_c_store));
                                    auto batch_size = std::cmp::min(base_data.len(), column_write_batch_size);
                                    auto flatten_and_write_store = | data : &Vec<Fr>,
                                        offset | {data.into_par_iter()
                                                      .chunks(column_write_batch_size)
                                                      .enumerate()
                                                      .try_for_each(| (index, fr_elements) | {
                                                          auto mut buf = Vec::with_capacity(batch_size * NODE_SIZE);

                                                          for (fr : fr_elements) {
                                                              buf.extend(fr_into_bytes(&fr));
                                                          }
                                                          store.write()
                                                              .expect("failed to access store for write")
                                                              .copy_from_slice(&buf[..], offset + (batch_size * index))
                                                      })};

                                    trace !("flattening tree_c base data of {} nodes using batch size {}",
                                            base_data.len(),
                                            batch_size);
                                    flatten_and_write_store(&base_data, 0).expect("failed to flatten and write store");
                                    trace !("done flattening tree_c base data");

                                    auto base_offset = base_data.len();
                                    trace !(
                                        "flattening tree_c tree data of {} nodes using batch size {} and base "
                                        "offset "
                                        "{}",
                                        tree_data.len(), batch_size, base_offset);
                                    flatten_and_write_store(&tree_data, base_offset)
                                        .expect("failed to flatten and write store");
                                    trace !("done flattening tree_c tree data");

                                    trace !("writing tree_c store data");
                                    store.write().expect("failed to access store for sync").sync();
                                    trace !("done writing tree_c store data");

                                    // Move on to the next config.
                                    i += 1;
                                    if (i == configs.size()) {
                                        break;
                                    }
                                    config = &configs[i];
                                }
                            });
                        });

                        create_disk_tree::<
                            DiskTree<typename MerkleTreeType::hash_type, MerkleTreeType::base_arity, MerkleTreeType::sub_tree_arity, MerkleTreeType::top_tree_arity>, >(
                            configs[0].size, &configs)
                    })
            }    // namespace stacked

            template<typename ColumnArity = PoseidonArity, typename TreeArity = PoseidonArity>
            DiskTree<tree_hash_type, typename tree_type::Arity, typename tree_type::SubTreeArity,
                     typename tree_type::TopTreeArity>
                generate_tree_c_cpu(std::size_t layers, std::size_t nodes_count, std::size_t tree_count,
                                    const std::vector<StoreConfig> &configs, const LabelsCache<tree_type> &labels) {
                info !("generating tree c using the CPU");
                measure_op(
                    GenerateTreeC, || {
                        info !("Building column hashes");

                        auto mut trees = Vec::with_capacity(tree_count);
                        for ((i, config) : configs.iter().enumerate()) {
                            auto mut hashes : Vec << typename MerkleTreeType::hash_type > ::Domain >
                                = vec ![<typename MerkleTreeType::hash_type>::Domain::default(); nodes_count];

                            rayon::scope(| s | {
                                auto n = num_cpus::get();

                                // only split if we have at least two elements per thread
                                std::size_t num_chunks = n > nodes_count * 2 ? 1 : n;

                                // chunk into n chunks
                                std::size_t chunk_size =
                                    std::ceil(static_cast<double>(nodes_count) / static_cast<double>(num_chunks));

                                // calculate all n chunks in parallel
                                for ((chunk, hashes_chunk) : hashes.chunks_mut(chunk_size).enumerate()) {
                                    auto labels = &labels;

                                    s.spawn(move | _ | {
                                        for ((j, hash) : hashes_chunk.iter_mut().enumerate()) {
                                            auto data : Vec<_> =
                                                           (1.. = layers)
                                                               .map(| layer |
                                                                    {
                                                                        auto store = labels.labels_for_layer(layer);
                                                                        auto el
                                                                            : <typename MerkleTreeType::hash_type>::Domain =
                                                                                  store
                                                                                      .read_at((i * nodes_count) + j +
                                                                                               chunk * chunk_size)
                                                                                      ;
                                                                        el.into()
                                                                    })
                                                               .collect();

                                            *hash = hash_single_column(&data).into();
                                        }
                                    });
                                }
                            });

                            info !("building base tree_c {}/{}", i + 1, tree_count);
                            trees.push(DiskTree<typename MerkleTreeType::hash_type, MerkleTreeType::base_arity, 0, 0>::
                                           from_par_iter_with_config(hashes.into_par_iter(), config.clone()));
                        }

                        assert(tree_count == trees.len());
                        create_disk_tree::<
                            DiskTree<typename MerkleTreeType::hash_type, MerkleTreeType::base_arity, MerkleTreeType::sub_tree_arity, MerkleTreeType::top_tree_arity>, >(
                            configs[0].size, &configs)
                    })
            }

            template<typename TreeArity = PoseidonArity>
            LCTree<tree_hash_type, typename tree_type::Arity, typename tree_type::SubTreeArity,
                   typename tree_type::TopTreeArity>
                generate_tree_r_last(Data &data, std::size_t nodes_count, std::size_t tree_count,
                                     const StoreConfig &tree_r_last_config, const boost::filesystem::path &replica_path,
                                     const LabelsCache<Tree> &labels) {
                auto(configs, replica_config) =
                    split_config_and_replica(tree_r_last_config.clone(), replica_path, nodes_count, tree_count, ) ?
                    ;

                data.ensure_data() ? ;
                auto last_layer_labels = labels.labels_for_last_layer() ? ;

                if (settings ::SETTINGS.lock().use_gpu_tree_builder) {
                    info !("generating tree r last using the GPU");
                    std::uint max_gpu_tree_batch_size = settings::SETTINGS.lock().max_gpu_tree_batch_size;

                    // This channel will receive batches of leaf nodes and add them to the TreeBuilder.
                    auto(builder_tx, builder_rx) = mpsc::sync_channel::<(Vec<Fr>, bool)>(0);
                    auto config_count = configs.len();    // Don't move config into closure below.
                    auto configs = &configs;
                    rayon::scope(| s | {
                        s.spawn(move | _ | {
                            for (int i = 0; i < config_count; i++) {
                                auto mut node_index = 0;
                                while (node_index != nodes_count) {
                                    auto chunked_nodes_count =
                                        std::cmp::min(nodes_count - node_index, max_gpu_tree_batch_size);
                                    auto start = (i * nodes_count) + node_index;
                                    auto end = start + chunked_nodes_count;
                                    trace !("processing config {}/{} with leaf nodes {} [{}, {}, {}-{}]", i + 1,
                                            tree_count, chunked_nodes_count, node_index, nodes_count, start, end, );

                                    auto encoded_data =
                                        last_layer_labels.read_range(start..end)
                                            .expect("failed to read layer range")
                                            .into_par_iter()
                                            .zip(data.as_mut()[(start * NODE_SIZE)..(end * NODE_SIZE)].par_chunks_mut(
                                                     NODE_SIZE), )
                                            .map(| (key, data_node_bytes) | {
                                                auto data_node =
                                                    <typename MerkleTreeType::hash_type>::Domain::try_from_bytes(data_node_bytes, )
                                                        .expect("try_from_bytes failed");
                                                auto encoded_node =
                                                    encode:: << typename MerkleTreeType::hash_type> ::Domain > (key, data_node);
                                                data_node_bytes.copy_from_slice(AsRef::<[u8]>::as_ref(&encoded_node));

                                                encoded_node
                                            });

                                    node_index += chunked_nodes_count;
                                    trace !("node index {}/{}/{}", node_index, chunked_nodes_count, nodes_count, );

                                    auto encoded : Vec<_> = encoded_data.into_par_iter().map(| x | x.into()).collect();

                                    auto is_final = node_index == nodes_count;
                                    builder_tx.send((encoded, is_final)).expect("failed to send encoded");
                                }
                            }
                        });

                        {
                            auto tree_r_last_config = &tree_r_last_config;
                            s.spawn(move | _ | {
                                auto mut tree_builder = TreeBuilder::<MerkleTreeType::base_arity>::new (
                                                           Some(BatcherType::GPU), nodes_count, max_gpu_tree_batch_size,
                                                           tree_r_last_config.rows_to_discard, )
                                                           .expect("failed to create TreeBuilder");

                                auto mut i = 0;
                                auto mut config = &configs[i];

                                // Loop until all trees for all configs have been built.
                                while (i < configs.size()) {
                                    auto(encoded, is_final) = builder_rx.recv().expect("failed to recv encoded data");

                                    // Just add non-final leaf batches.
                                    if (!is_final) {
                                        tree_builder.add_leaves(&encoded).expect("failed to add leaves");
                                        continue;
                                    };

                                    // If we get here, this is a final leaf batch: build a sub-tree.
                                    info !("building base tree_r_last with GPU {}/{}", i + 1, tree_count);
                                    auto(_, tree_data) =
                                        tree_builder.add_final_leaves(&encoded).expect("failed to add final leaves");
                                    auto tree_data_len = tree_data.len();
                                    auto cache_size =
                                        get_merkle_tree_cache_size(
                                            get_merkle_tree_leafs(config.size, MerkleTreeType::base_arity, )
                                                .expect("failed to get merkle tree leaves"),
                                            MerkleTreeType::base_arity, config.rows_to_discard, )
                                            .expect("failed to get merkle tree cache size");
                                    assert_eq !(tree_data_len, cache_size);

                                    auto flat_tree_data
                                        : Vec<_> =
                                              tree_data.into_par_iter().flat_map(| el | fr_into_bytes(&el)).collect();

                                    // Persist the data to the store based on the current config.
                                    auto tree_r_last_path = StoreConfig::data_path(&config.path, &config.id);
                                    trace !("persisting tree r of len {} with {} rows to discard at path {:?}",
                                            tree_data_len,
                                            config.rows_to_discard,
                                            tree_r_last_path);
                                    auto mut f = OpenOptions::new ()
                                                    .create(true)
                                                    .write(true)
                                                    .open(&tree_r_last_path)
                                                    .expect("failed to open file for tree_r_last");
                                    f.write_all(&flat_tree_data).expect("failed to wrote tree_r_last data");

                                    // Move on to the next config.
                                    i += 1;
                                    if (i == configs.size()) {
                                        break;
                                    }
                                    config = &configs[i];
                                }
                            });
                        }
                    });
                } else {
                    info !("generating tree r last using the CPU");
                    auto size = Store::len(last_layer_labels);

                    auto mut start = 0;
                    auto mut end = size / tree_count;

                    for ((i, config) : configs.iter().enumerate()) {
                        auto encoded_data = last_layer_labels.read_range(start..end) ?
                            .into_par_iter()
                            .zip(data.as_mut()[(start * NODE_SIZE)..(end * NODE_SIZE)].par_chunks_mut(NODE_SIZE), )
                            .map(| (key, data_node_bytes) | {
                                auto data_node = <typename MerkleTreeType::hash_type>::Domain::try_from_bytes(data_node_bytes)
                                                    .expect("try from bytes failed");
                                auto encoded_node = encode:: << typename MerkleTreeType::hash_type> ::Domain > (key, data_node);
                                data_node_bytes.copy_from_slice(AsRef::<[u8]>::as_ref(&encoded_node));

                                encoded_node
                            });

                        info !("building base tree_r_last with CPU {}/{}", i + 1, tree_count);
                        LCTree<typename MerkleTreeType::hash_type, MerkleTreeType::base_arity, 0, 0>::from_par_iter_with_config(encoded_data, config.clone());

                        start = end;
                        end += size / tree_count;
                    }
                };

                return create_lc_tree<LCTree<typename MerkleTreeType::hash_type, MerkleTreeType::base_arity, MerkleTreeType::sub_tree_arity, MerkleTreeType::top_tree_arity>>(
                    tree_r_last_config.size, &configs, &replica_config);
            }

            TransformedLayers<tree_type, hash_type>
                transform_and_replicate_layers(const StackedBucketGraph<tree_hash_type> &graph,
                                               const LayerChallenges &layer_challenges,
                                               const typename hash_type::digest_type &replica_id, const Data &data,
                                               const BinaryMerkleTree<G> &data_tree, const StoreConfig &config,
                                               const boost::filesystem::path &replica_path) {
                // Generate key layers.
                auto(_, labels) =
                    measure_op(EncodeWindowTimeAll,
                               || {Self::generate_labels(graph, layer_challenges, replica_id, config.clone())}) ?
                    ;

                return transform_and_replicate_layers_inner(graph, layer_challenges, data, data_tree, config,
                                                            replica_path, labels);
            }

            TransformedLayers<tree_type, hash_type> transform_and_replicate_layers_inner(
                const StackedBucketGraph<tree_hash_type> &graph, const LayerChallenges &layer_challenges,
                const typename hash_type::digest_type &replica_id, const Data &data,
                const BinaryMerkleTree<G> &data_tree, const StoreConfig &config,
                const boost::filesystem::path &replica_path, const Labels<tree_type> &label_configs) {
                trace !("transform_and_replicate_layers");
                std::size_t nodes_count = graph.size();

                assert(data.len() == nodes_count * NODE_SIZE);
                trace !("nodes count {}, data len {}", nodes_count, data.len());

                std::size_t tree_count = get_base_tree_count::<Tree>();
                std::size_t nodes_count = graph.size() / tree_count;

                // Ensure that the node count will work for binary and oct arities.
                bool binary_arity_valid = is_merkle_tree_size_valid(nodes_count, BINARY_ARITY);
                bool other_arity_valid = is_merkle_tree_size_valid(nodes_count, MerkleTreeType::base_arity);
                trace !("is_merkle_tree_size_valid({}, BINARY_ARITY) = {}", nodes_count, binary_arity_valid);
                trace !("is_merkle_tree_size_valid({}, {}) = {}", nodes_count, MerkleTreeType::base_arity,
                        other_arity_valid);
                assert(binary_arity_valid);
                assert(other_arity_valid);

                std::size_t layers = layer_challenges.layers();
                assert(layers > 0);

                // Generate all store configs that we need based on the
                // cache_path in the specified config.
                StoreConfig tree_d_config = StoreConfig::from_config(config, cache_key::CommDTree.to_string(),
                                                                     get_merkle_tree_len(nodes_count, BINARY_ARITY));
                tree_d_config.rows_to_discard = default_rows_to_discard(nodes_count, BINARY_ARITY);

                StoreConfig tree_r_last_config =
                    StoreConfig::from_config(config,
                                             cache_key::CommRLastTree.to_string(),
                                             get_merkle_tree_len(nodes_count, MerkleTreeType::base_arity));

                // A default 'rows_to_discard' value will be chosen for tree_r_last, unless the user overrides this
                // value via the environment setting (FIL_PROOFS_ROWS_TO_DISCARD).  If this value is specified, no
                // checking is done on it and it may result in a broken configuration.  Use with caution.
                tree_r_last_config.rows_to_discard = default_rows_to_discard(nodes_count, MerkleTreeType::base_arity);
                trace !("tree_r_last using rows_to_discard={}", tree_r_last_config.rows_to_discard);

                StoreConfig mut tree_c_config = StoreConfig::from_config(
                        &config,
                        cache_key::CommCTree.to_string(),
                        Some(get_merkle_tree_len(nodes_count, MerkleTreeType::base_arity)?),
                    );
                tree_c_config.rows_to_discard = default_rows_to_discard(nodes_count, MerkleTreeType::base_arity);

                LabelsCache<tree_type> labels(&label_configs);
                auto configs = split_config(tree_c_config.clone(), tree_count) ? ;

                typename tree_hash_type::digest_type tree_c_root;
                if (layers == 2) {
                    auto tree_c =
                        Self::generate_tree_c::<U2, MerkleTreeType::base_arity>(layers, nodes_count, tree_count, configs, &labels, ) ?
                        ;
                    tree_c_root = tree_c.root();
                } else if (layers == 8) {
                    auto tree_c =
                        Self::generate_tree_c::<U8, MerkleTreeType::base_arity>(layers, nodes_count, tree_count, configs, &labels, ) ?
                        ;
                    tree_c_root = tree_c.root();
                } else if (layers == 11) {
                    auto tree_c =
                        Self::generate_tree_c::<U11, MerkleTreeType::base_arity>(layers, nodes_count, tree_count, configs, &labels, ) ?
                        ;
                    tree_c_root = tree_c.root();
                } else {
                    throw "Unsupported column arity";
                }

                info !("tree_c done");

                // Build the MerkleTree over the original data (if needed).
                BinaryMerkleTree<Hash> tree_d;
                if (data_tree.empty()) {
                    trace !("building merkle tree for the original data");
                    data.ensure_data() ? ;
                    measure_op(CommD, || {Self::build_binary_tree::<G>(data.as_ref(), tree_d_config.clone())});
                } else {
                    trace !("using existing original data merkle tree");
                    assert_eq !(t.len(), 2 * (data.len() / NODE_SIZE) - 1);
                    tree_d = t;

                }    // namespace stacked
                tree_d_config.size = Some(tree_d.len());
                assert_eq !(tree_d_config.size, tree_d.size());
                auto tree_d_root = tree_d.root();
                drop(tree_d);

                // Encode original data into the last layer.
                info !("building tree_r_last");
                auto tree_r_last = measure_op(GenerateTreeRLast,
                                             || {Self::generate_tree_r_last::<MerkleTreeType::base_arity>(
                                                    &mut data, nodes_count, tree_count, tree_r_last_config.clone(),
                                                    replica_path.clone(), &labels, )}) ?
                    ;
                info !("tree_r_last done");

                auto tree_r_last_root = tree_r_last.root();
                drop(tree_r_last);

                data.drop_data();

                // comm_r = H(comm_c || comm_r_last)
                auto comm_r : <typename MerkleTreeType::hash_type>::Domain =
                                 <typename MerkleTreeType::hash_type>::Function::hash2(&tree_c_root, &tree_r_last_root);

                Ok((Tau {
                    comm_d : tree_d_root,
                    comm_r,
                },
                    PersistentAux {
                        comm_c : tree_c_root,
                        comm_r_last : tree_r_last_root,
                    },
                    TemporaryAux {
                        labels : label_configs,
                        tree_d_config,
                        tree_r_last_config,
                        tree_c_config,
                        _g : PhantomData,
                    }, ))
            }    // namespace stacked

            /// Phase1 of replication.
            Labels<tree_type> replicate_phase1(const PublicParams<tree_type> &pp,
                                               const typename tree_hash_type::digest_type &replica_id,
                                               const StoreConfig &config) {
                info !("replicate_phase1");

                auto(_, labels) =
                    measure_op(EncodeWindowTimeAll,
                               || {Self::generate_labels(&pp.graph, &pp.layer_challenges, replica_id, config)}) ?
                    ;

                return labels;
            }

            std::tuple << Self as PoRep<'a, typename MerkleTreeType::hash_type, G>>::Tau, < Self as PoRep <' a, typename MerkleTreeType::hash_type, G> >
                ::ProverAux > replicate_phase2(const PublicParams<tree_type> &pp, const Labels<tree_type> &labels,
                                               const Data &data, const BinaryMerkleTree<hash_type> &data_tree,
                                               const StoreConfig &config, const boost::filesystem::path &replica_path) {
                info !("replicate_phase2");

                return transform_and_replicate_layers_inner(&pp.graph, &pp.layer_challenges, data, Some(data_tree),
                                                            config, replica_path, labels);
            }

            tree_type &_a;
            hash_type &_b;
        };    // namespace stacked
    }         // namespace filecoin
}    // namespace nil
}    // namespace filecoin
}    // namespace nil

#endif
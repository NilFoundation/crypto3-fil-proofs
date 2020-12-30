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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_MERKLE_BUILDERS_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_MERKLE_BUILDERS_HPP

#include <vector>

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>

#include <nil/filecoin/storage/proofs/core/sector.hpp>

namespace nil {
    namespace filecoin {
        template<typename MerkleTreeType>
        inline std::size_t get_base_tree_size(sector_size_type sector_size) {
            std::uint64_t base_tree_leaves =
                sector_size / MerkleTreeType::hash_type::digest_bits / get_base_tree_count<MerkleTreeType>();

            return get_merkle_tree_len(base_tree_leaves, MerkleTreeType::base_arity);
        }

        template<typename MerkleTreeType>
        inline std::size_t get_base_tree_leafs(std::size_t base_tree_size) {
            return get_merkle_tree_leafs(base_tree_size, MerkleTreeType::base_arity);
        }

        // Create a DiskTree from the provided config(s), each representing a 'base' layer tree with
        // 'base_tree_len' elements.
        template<typename MerkleTreeType>
        DiskTree<typename MerkleTreeType::hash_type, MerkleTreeType::base_arity, MerkleTreeType::sub_tree_arity,
                 MerkleTreeType::top_tree_arity>
            create_disk_tree(std::size_t base_tree_len, const std::vector<StoreConfig> &configs) {
            std::size_t base_tree_leafs = get_merkle_tree_leafs(base_tree_len, MerkleTreeType::base_arity);

            if (MerkleTreeType::top_tree_arity > 0) {
                assert(("Invalid top arity specified without sub arity", MerkleTreeType::sub_tree_arity > 0));

                return DiskTree::from_sub_tree_store_configs(base_tree_leafs, configs);
            } else if (MerkleTreeType::sub_tree_arity > 0) {
                assert(("Cannot create sub-tree with a single tree config", !configs.empty()));

                return DiskTree::from_store_configs(base_tree_leafs, configs);
            } else {
                assert(("Invalid tree-shape specified", configs.size() == 1));
                DiskStore store = DiskStore::new_from_disk(base_tree_len, MerkleTreeType::base_arity, configs[0]);

                return DiskTree::from_data_store(store, base_tree_leafs);
            }
        }

        // Create an LCTree from the provided config(s) and replica(s), each representing a 'base' layer tree with
        // 'base_tree_len' elements.
        template<typename MerkleTreeType>
        LCTree<typename MerkleTreeType::hash_type, MerkleTreeType::base_arity, MerkleTreeType::sub_tree_arity,
               MerkleTreeType::top_tree_arity>
            create_lc_tree(std::size_t base_tree_len, const std::vector<StoreConfig> &configs,
                           const ReplicaConfig &replica_config) {
            std::size_t base_tree_leafs = get_merkle_tree_leafs(base_tree_len, MerkleTreeType::base_arity);

            if (MerkleTreeType::top_tree_arity > 0) {
                assert(("Invalid top arity specified without sub arity", MerkleTreeType::sub_tree_arity > 0));

                return LCTree::from_sub_tree_store_configs_and_replica(base_tree_leafs, configs, replica_config);
            } else if (MerkleTreeType::sub_tree_arity > 0) {
                assert(("Cannot create sub-tree with a single tree config", !configs.empty()));

                return LCTree::from_store_configs_and_replica(base_tree_leafs, configs, replica_config);
            } else {
                assert(("Invalid tree-shape specified", configs.size() == 1));
                LCStore store =
                    LCStore::new_from_disk_with_reader(base_tree_len, MerkleTreeType::base_arity, configs[0],
                                                       ExternalReader::new_from_path(replica_config.path), );

                return LCTree::from_data_store(store, base_tree_leafs);
            }
        }

        // Given base tree configs and optionally a replica_config, returns
        // either a disktree or an lctree, specified by Tree.
        template<typename MerkleTreeType>
        MerkleTreeType create_tree(std::size_t base_tree_len, const std::vector<StoreConfig> &configs,
                                   boost::optional<ReplicaConfig> replica_config) {

            std::size_t base_tree_leafs = get_base_tree_leafs<MerkleTreeType>(base_tree_len);
            std::vector<MerkleTreeType> trees(configs.size());
            for (int i = 0; i < configs.size(); i++) {
                typename MerkleTreeType::Store store = typename MerkleTreeType::Store::new_with_config(
                    base_tree_len, MerkleTreeType::base_arity, configs[i]);
                if let
                    Some(lc_store) = Any::downcast_mut::<merkletree::store::LevelCacheStore
                                                         << typename MerkleTreeType::hash_type>::Domain,
                    std::fs::File >, > (&mut store) {
                        assert(("Cannot create LCTree without replica paths", replica_config));
                        lc_store.set_external_reader(ExternalReader::new_from_config(&replica_config, i));
                    }

                if (configs.size() == 1) {
                        return MerkleTreeType::from_data_store(store, base_tree_leafs);
                    }
                else {
                    trees.push_back(
                        MerkleTreeType<typename MerkleTreeType::hash_type, MerkleTreeType::Store, MerkleTreeType::arity, 0,
                                       0>::from_data_store(store, base_tree_leafs));
                }
            }

            assert(("Cannot have a sub/top tree without more than 1 config",
                    MerkleTreeType::top_tree_arity > 0 || MerkleTreeType::sub_tree_arity > 0));
            if (MerkleTreeType::top_tree_arity > 0) {
                assert(("Invalid top arity specified without sub arity", MerkleTreeType::sub_tree_arity > 0));

                return MerkleTreeType<
                    typename MerkleTreeType::hash_type, MerkleTreeType::Store, MerkleTreeType::base_arity, MerkleTreeType::sub_tree_arity, MerkleTreeType::top_tree_arity>::
                    from_sub_trees_as_trees(trees);
            } else {
                assert(("Cannot create sub-tree with a single tree config", !configs.empty()));

                return MerkleTreeType::from_trees(trees);
            }
        }

        template<typename MerkleTreeType>
        MerkleTreeType create_base_merkle_tree(boost::optional<StoreConfig> config, std::size_t size,
                                               const std::vector<std::uint8_t> &data) {
            assert(data.size == NODE_SIZE * size);

            assert(("Invalid merkle tree size given the arity",
                    is_merkle_tree_size_valid(size, MerkleTreeType::base_arity)));

            auto f = [&](std::size_t i) {
                // TODO Replace `expect()` with `context()` (problem is the parallel iterator)
                std::vector<std::uint8_t> d = data_at_node(data, i);
                // TODO/FIXME: This can panic. FOR NOW, let's leave this since we're experimenting with
                // optimization paths. However, we need to ensure that bad input will not lead to a panic
                // that isn't caught by the FPS API.
                // Unfortunately, it's not clear how to perform this error-handling in the parallel
                // iterator case.
                return typename MerkleTreeType::hash_type::digest_type(d);
            };

            if (config) {
                merkle::MerkleTree << typename MerkleTreeType::hash_type > ::Domain,
                    <typename MerkleTreeType::hash_type>::Function, MerkleTreeType::Store, MerkleTreeType::base_arity,
                    MerkleTreeType::sub_tree_arity, MerkleTreeType::top_tree_arity,
                    > ::from_par_iter_with_config((0..size).into_par_iter().map(f), x);
            } else {
                merkle::MerkleTree:: << typename MerkleTreeType::hash_type > ::Domain,
                    <typename MerkleTreeType::hash_type>::Function, MerkleTreeType::Store, MerkleTreeType::base_arity,
                    MerkleTreeType::sub_tree_arity, MerkleTreeType::top_tree_arity,
                    > ::from_par_iter((0..size).into_par_iter().map(f))
            }

            return MerkleTreeType::from_merkle(tree);
        }

        /// Construct a new level cache merkle tree, given the specified
        /// config.
        ///
        /// Note that while we don't need to pass both the data AND the
        /// replica path (since the replica file will contain the same data),
        /// we pass both since we have access from all callers and this avoids
        /// reading that data from the replica_config here.
        template<typename Hash, std::size_t BaseTreeArity>
        LCMerkleTree create_base_lcmerkle_tree(const StoreConfig &config,
                                               std::size_t size,
                                               const std::vector<std::uint8_t> &data,
                                               const ReplicaConfig &replica_config) {
            assert(("Invalid merkle tree size given the arity", is_merkle_tree_size_valid(size, BaseTreeArity)));
            assert(("Invalid data length for merkle tree", data.size() == Hash::digest_bits / CHAR_BIT));

            auto f = [&](std::size_t i) {
                let d = data_at_node(&data, i);
                return Hash::digest_type(d);
            };

            LCMerkleTree<Hash, BaseTreeArity> lc_tree =
                LCMerkleTree<Hash, BaseTreeArity>::try_from_iter_with_config((0..size).map(f), config);

            lc_tree.set_external_reader_path(&replica_config.path);

            return lc_tree;
        }

        // Given a StoreConfig, generate additional ones with appended numbers
        // to uniquely identify them and return the results.  If count is 1,
        // the original config is not modified.
        std::vector<StoreConfig> split_config(const StoreConfig &config, std::size_t count) {
            if (count == 1) {
                return {config};
            }

            std::vector<StoreConfig> configs(count);
            for (int i = 0; i < count; i++) {
                configs.push_back(StoreConfig::from_config(&config, format !("{}-{}", config.id, i), None));
                configs[i].rows_to_discard = config.rows_to_discard;
            }

            return configs;
        }

        // Given a StoreConfig, generate additional ones with appended numbers
        // to uniquely identify them and return the results.  If count is 1,
        // the original config is not modified.
        //
        // Useful for testing, where there the config may be None.
        std::vector<boost::optional<StoreConfig>> split_config_wrapped(boost::optional<StoreConfig> config,
                                                                       std::size_t count) {
            if (count == 1) {
                return {config};
            }

            if (config) {
                std::vector<boost::optional<StoreConfig>> configs(count);
                for (int i = 0; i < count; i++) {
                    configs.push_back(Some(StoreConfig::from_config(&c, format !("{}-{}", c.id, i), None, )));
                }
                return configs;
            } else {
                return {};
            }
        }

        // Given a StoreConfig, replica path and tree_width (leaf nodes),
        // append numbers to each StoreConfig to uniquely identify them and
        // return the results along with a ReplicaConfig using calculated
        // offsets into the single replica path specified for later use with
        // external readers.  If count is 1, the original config is not
        // modified.
        std::tuple<std::vector<StoreConfig>, ReplicaConfig>
            split_config_and_replica(StoreConfig config, const boost::filesystem::path &replica_path,
                                     std::size_t sub_tree_width,    // nodes, not bytes
                                     std::size_t count) {
            if (count == 1) {
                return std::make_tuple({config}, {replica_path, {0}});
            }

            std::vector<StoreConfig> configs(count);
            std::vector<std::size_t> replica_offsets(count);

            for (int i = 0; i < count; i++) {
                configs.push_back(StoreConfig::from_config(&config, format !("{}-{}", config.id, i), None));
                configs[i].rows_to_discard = config.rows_to_discard;

                replica_offsets.push_back(i * sub_tree_width * NODE_SIZE);
            }

            return std::make_tuple(configs, {replica_path, replica_offsets});
        }

        template<typename MerkleTreeType>
        std::size_t get_base_tree_count() {
            if (MerkleTreeType ::top_tree_arity == 0 && MerkleTreeType::sub_tree_arity == 0) {
                return 1;
            }

            if (MerkleTreeType ::top_tree_arity > 0) {
                assert(MerkleTreeType::sub_tree_arity != 0);

                return MerkleTreeType::top_tree_arity * MerkleTreeType::sub_tree_arity;
            } else {
                return MerkleTreeType::sub_tree_arity;
            }
        }

        template<typename MerkleTreeType>
        std::size_t get_base_tree_leafs(std::size_t base_tree_size) {
            return get_merkle_tree_leafs(base_tree_size, MerkleTreeType::base_arity);
        }

        template<typename MerkleTreeType, typename UniformRandomGenerator>
        std::tuple<std::vector<std::uint8_t>, MerkleTreeType>
            generate_base_tree(UniformRandomGenerator &rng, std::size_t nodes,
                               boost::optional<const boost::filesystem::path &> temp_path) {
            let elements =
                (0..nodes).map(| _ | <typename MerkleTreeType::hash_type>::Domain::random(rng)).collect::<Vec<_>>();

            std::vector<std::uint8_t> data;
            for (el : elements) {
                data.extend_from_slice(el);
            }

            if (temp_path) {
                std::uint64_t id = rng.gen();
                boost::filesystem::path replica_path = temp_path.join(format !("replica-path-{}", id));
                StoreConfig config(*temp_path, format !("test-lc-tree-{}", id),
                                   default_rows_to_discard(nodes, MerkleTreeType::base_arity));

                let mut tree =
                    MerkleTreeWrapper::try_from_iter_with_config(elements.iter().map(| v | (Ok(*v))), config).unwrap();

                // Write out the replica data.
                let mut f = std::fs::File::create(&replica_path).unwrap();
                f.write_all(&data).unwrap();

                {
                    // Beware: evil dynamic downcasting RUST MAGIC down below.
                    use std::any::Any;

                    if let
                        Some(lc_tree) =
                            Any::downcast_mut::<merkle::MerkleTree << typename MerkleTreeType::hash_type>::Domain,
                        <typename MerkleTreeType::hash_type>::Function,
                        merkletree::store::LevelCacheStore << typename MerkleTreeType::hash_type> ::Domain,
                        std::fs::File, >, MerkleTreeType::base_arity, MerkleTreeType::sub_tree_arity,
                        MerkleTreeType::top_tree_arity, >, > (&mut tree.inner) {
                            lc_tree.set_external_reader_path(&replica_path).unwrap();
                        }
                }

                (data, tree)
            } else {
                (data, MerkleTreeWrapper::try_from_iter(elements.iter().map(| v | Ok(*v))).unwrap())
            }
        }

        template<typename MerkleTreeType, typename UniformRandomGenerator>
        std::tuple<std::vector<std::uint8_t>, MerkleTreeType>
            generate_sub_tree(UniformRandomGenerator &rng,
                              std::size_t nodes,
                              boost::optional<const boost::filesystem::path &>
                                  temp_path) {
            std::size_t base_tree_count = MerkleTreeType::sub_tree_arity;
            std::size_t base_tree_size = nodes / base_tree_count;
            std::vector<MerkleTreeType> trees(base_tree_count);
            std::vector<std::uint8_t> data;

            for (int i = 0; i < base_tree_count) {
                let(inner_data, tree) =
                    generate_base_tree<UniformRandomGenerator, MerkleTreeType>(rng, base_tree_size, temp_path);
                trees.push_back(tree);
                data.extend(inner_data);
            }

            (data, MerkleTreeWrapper::from_trees(trees))
        }

        /// Only used for testing, but can't cfg-test it as that stops exports.
        template<typename MerkleTreeType, typename UniformRandomGenerator>
        std::tuple<std::vector<std::uint8_t>, MerkleTreeType>
            generate_tree(UniformRandomGenerator &rng, std::size_t nodes,
                          boost::optional<const boost::filesystem::path &> temp_path) {
            std::size_t sub_tree_arity = MerkleTreeType::sub_tree_arity;
            std::size_t top_tree_arity = MerkleTreeType::top_tree_arity;

            if (top_tree_arity > 0) {
                assert(("malformed tree with TopTreeArity > 0 and SubTreeARity == 0", sub_tree_arity != 0));

                std::vector<MerkleTreeType> sub_trees(top_tree_arity);
                std::vector<std::uint8_t> data;
                for (int i = 0; i < top_tree_arity; i++) {
                    let(inner_data, tree) = generate_sub_tree<
                        UniformRandomGenerator,
                        MerkleTreeWrapper<typename MerkleTreeType::hash_type, MerkleTreeType::Store, MerkleTreeType::base_arity,
                                          MerkleTreeType::sub_tree_arity, typenum::U0>>(rng, nodes / top_tree_arity,
                                                                                        temp_path.clone());

                    sub_trees.push(tree);
                    data.extend(inner_data);
                }
                (data, MerkleTreeWrapper::from_sub_trees(sub_trees).unwrap())
            } else if (sub_tree_arity > 0) {
                generate_sub_tree<UniformRandomGenerator, MerkleTreeType>(rng, nodes, temp_path)
            } else {
                generate_base_tree<UniformRandomGenerator, MerkleTreeType>(rng, nodes, temp_path)
            }
        }
    }    // namespace filecoin
}    // namespace nil

#endif
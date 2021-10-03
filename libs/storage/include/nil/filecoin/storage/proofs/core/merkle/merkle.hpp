//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantfrom_store_configs_and_replicaial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef FILECOIN_MERKLE_HPP
#define FILECOIN_MERKLE_HPP

#include <nil/filecoin/storage/proofs/core/merkle/storage/utilities.hpp>

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>
#include <nil/filecoin/storage/proofs/core/merkle/storage/vec.hpp>

namespace nil {
    namespace filecoin {
        namespace merkletree {
            const size_t SMALL_TREE_BUILD = 1024;

            // Number of nodes to process in parallel during the `build` stage.
            const size_t BUILD_CHUNK_NODES = 1024 * 4;
            // Number of batched nodes processed and stored together when
            // populating from the data leaves.
            const size_t BUILD_DATA_BLOCK_SIZE = 64 * BUILD_CHUNK_NODES;
            
            // Merkle Tree.
            //
            // All leafs and nodes are stored in a linear array (vec).
            //
            // A merkle tree is a tree in which every non-leaf node is the hash of its
            // child nodes. A diagram depicting how it works://
            // ```text
            //         root = h1234 = h(h12 + h34)
            //        /                           \
            //  h12 = h(h1 + h2)            h34 = h(h3 + h4)
            //   /            \              /            \
            // h1 = h(tx1)  h2 = h(tx2)    h3 = h(tx3)  h4 = h(tx4)
            // ```
            //
            // In memory layout:
            //
            // ```text
            //     [h1 h2 h3 h4 h12 h34 root]
            // ```
            //
            // Merkle root is always the last element in the array.
            //
            // The number of inputs must always be a power of two.
            //
            // This tree structure can consist of at most 3 layers of trees (of
            // arity U, N and R, from bottom to top).
            //
            // This structure ties together multiple Merkle Trees and allows
            // supported properties of the Merkle Trees across it.  The
            // significance of this class is that it allows an arbitrary number
            // of sub-trees to be constructed and proven against.
            //
            // To show an example, this structure can be used to create a single
            // tree composed of 3 sub-trees, each that have branching factors /
            // arity of 4.  Graphically, this may look like this:
            //
            // ```text
            //                O
            //       ________/|\_________
            //      /         |          \
            //     O          O           O
            //  / / \ \    / / \ \     / / \ \
            // O O  O  O  O O  O  O   O O  O  O
            //
            //
            // At most, one more layer (top layer) can be constructed to group a
            // number of the above sub-tree structures (not pictured).
            //
            // BaseTreeArity is the arity of the base layer trees [bottom].
            // SubTreeArity is the arity of the sub-tree layer of trees [middle].
            // TopTreeArity is the arity of the top layer of trees [top].
            //
            // With N and R defaulting to 0, the tree performs as a single base
            // layer merkle tree without layers (i.e. a conventional merkle
            // tree).
            template <typename Hash, typename Store, size_t BaseTreeArity = 2, size_t SubTreeArity = 0, size_t TopTreeArity = 0>
            struct MerkleTree {
                std::vector<Store> data;
                typedef Hash hash_type;

                typedef typename hash_type::digest_type element;
                constexpr static const std::size_t digest_size = Hash::digest_size;

                size_t leafs;
                size_t len;
                // Note: The former 'upstream' merkle_light project uses 'height'
                // (with regards to the tree property) incorrectly, so we've
                // renamed it since it's actually a 'row_count'.  For example, a
                // tree with 2 leaf nodes and a single root node has a height of
                // 1, but a row_count of 2.
                //
                // Internally, this code considers only the row_count.
                size_t row_count;
                // Cache with the `root` of the tree built from `data`. This allows to
                // not access the `Store` (e.g., access to disks in `DiskStore`).
                element root;

//                using container_blob_type = nil::marshalling::types::array_list<nil::marshalling::field_type<nil::marshalling::option::big_endian>, uint8_t>;
//                using container_hash_type = nil::marshalling::types::array_list<nil::marshalling::field_type<nil::marshalling::option::big_endian>, element>;
//
//                std::vector<uint8_t> blob_data;
//                std::vector<element> hash_data;
//
//                container_hash_type v_hash = container_hash_type(blob_data);
//                container_blob_type v_blob =


                template<std::size_t Arity = 2>
                element hash_children_to_one(std::array<element, Arity> &children) {

                    constexpr static const std::size_t arity = Arity;
                    constexpr static const std::size_t digest_size = Hash::digest_size;

                    crypto3::static_digest<Hash::digest_bits * arity> new_input;

                    for (std::size_t i = 0; i < arity; ++i) {
                        assert(children[i].size() == digest_size);
                        std::copy(children[i].begin(), children[i].end(), new_input.begin() + i * digest_size);
                    }

                    return crypto3::hash<Hash>(new_input);
                }

                template<std::size_t Arity = 2>
                element build_small_tree(size_t leafs, size_t row_count) {
                    BOOST_ASSERT_MSG(leafs % 2 == 0, "Leafs must be a power of two");

                    size_t level = 0;
                    size_t width = leafs;
                    size_t level_node_index = 0;
                    size_t branches = Arity;
                    size_t shift = (size_t)std::log(branches);

                    size_t read_start;
                    size_t write_start;
                    while (width > 1) {
                        // Same indexing logic as `build`.
                        if (level == 0) {
                            read_start = 0;
                            write_start = data.len();
                        } else {
                            read_start = level_node_index;
                            write_start = level_node_index + width;
                        }

                        uint8_t buf[big_size];
                        std::pair<size_t, size_t> r = std::make_pair(read_start * digest_size, (read_start + width) * read_start + width);
                        data.read(r, buf);
                        Hash(buf);
                        root = buf[last];
                        buf = buf.serialize();
                        layer = buf;
                    };
                    data.write(std::make_pair(layer.begin(), layer.end()), (write_start + i) * digest_size);
                    level_node_index += width;
                    level += 1;
                    width >>= shift;    // width /= branches;
                    BOOST_ASSERT_MSG(row_count == level + 1, "Invalid tree row_count");
                    // The root isn't part of the previous loop so `row_count` is
                    // missing one level.

                    return root;
                };

                template<std::size_t Arity = 2>
                void process_layer(size_t width, size_t level, size_t read_start, size_t write_start) {
                    size_t branches = Arity;

                    // Allocate `width` indexes during operation (which is a negligible memory bloat
                    // compared to the 32-bytes size of the nodes stored in the `Store`s) and hash each
                    // pair of nodes to write them to the next level in concurrent threads.
                    // Process `BUILD_CHUNK_NODES` nodes in each thread at a time to reduce contention,
                    // optimized for big sector sizes (small ones will just have one thread doing all
                    // the work).
                    BOOST_ASSERT_MSG(BUILD_CHUNK_NODES % branches == 0, "Invalid chunk size");
                    for (size_t chunk_index = read_start; chunk_index < read_start + width; chunk_index += BUILD_CHUNK_NODES) {
                        size_t chunk_size = std::min(BUILD_CHUNK_NODES, read_start + width - chunk_index);
                        uint8_t buf[BUILD_CHUNK_NODES];
                        data.read(chunk_index, chunk_index + chunk_size, buf);
                        // We write the hashed nodes to the next level in the
                        // position that would be "in the middle" of the
                        // previous pair (dividing by branches).
                        size_t write_delta = (chunk_index - read_start) / branches;
                        size_t nodes_size = (buf.len() / branches) * digest_size;
                        hashes::hash(buf);
                        root = buf[last];
                        buf = buf.serialize();
                        // Check that we correctly pre-allocated the space.
                        BOOST_ASSERT_MSG(buf.len() == chunk_size / branches * digest_size,"Invalid hashed node length");
                        data.write(buf, write_start + write_delta)
                    }
                };

                // Default merkle-tree build, based on store type.
                template<std::size_t Arity = 2>
                element build(size_t leafs, size_t row_count, utilities::StoreConfig config) {
                    size_t branches = Arity;
                    BOOST_ASSERT_MSG(data.len() == leafs, "Inconsistent data");
                    BOOST_ASSERT_MSG(leafs % 2 == 0, "Leafs must be a power of two");

                    if (leafs <= SMALL_TREE_BUILD) {
                        return build_small_tree<Arity>(leafs, row_count);
                    }

                    size_t shift = (size_t)std::log(branches);

                    // Process one `level` at a time of `width` nodes. Each level has half the nodes
                    // as the previous one; the first level, completely stored in `data`, has `leafs`
                    // nodes. We guarantee an even number of nodes per `level`, duplicating the last
                    // node if necessary.
                    size_t level = 0;
                    size_t width = leafs;
                    size_t level_node_index = 0;
                    while (width > 1) {
                        // Start reading at the beginning of the current level, and writing the next
                        // level immediate after.  `level_node_index` keeps track of the current read
                        // starts, and width is updated accordingly at each level so that we know where
                        // to start writing.
                        size_t read_start;
                        size_t write_start;
                        if (level == 0) {
                            read_start = 0;
                            write_start = data.len();
                        } else {
                            read_start = level_node_index;
                            write_start = level_node_index + width;
                        }
                        process_layer<Arity>(width, level, read_start, write_start);

                        level_node_index += width;
                        level += 1;
                        width >>= shift;    // width /= branches;
                    }

                    BOOST_ASSERT_MSG(row_count == level + 1, "Invalid tree row_count");
                    // The root isn't part of the previous loop so `row_count` is
                    // missing one level.

                    // Return the root
                    return root;
                };
            
                /// Creates new merkle tree from an already allocated 'Store'
                /// (used with 'Store::new_from_disk').  The specified 'size' is
                /// the number of base data leafs in the MT.
                MerkleTree(Store data, size_t leafs) {
                    BOOST_ASSERT_MSG(SubTreeArity == 0, "Data stores must not have sub-tree layers");
                    BOOST_ASSERT_MSG(TopTreeArity == 0, "Data stores must not have a top layer");
            
                    size_t branches = BaseTreeArity;
                    BOOST_ASSERT_MSG(utilities::next_pow2(leafs) == leafs, "leafs MUST be a power of 2");
                    BOOST_ASSERT_MSG(utilities::next_pow2(branches) == branches, "branches MUST be a power of 2");
            
                    size_t tree_len = utilities::get_merkle_tree_len(leafs, branches);
                    BOOST_ASSERT_MSG(tree_len == data.len(), "Inconsistent tree data");
            
                    BOOST_ASSERT_MSG(utilities::is_merkle_tree_size_valid(leafs, branches), "MerkleTree size is invalid given the arity");

                    this->data = data;
                    this->leafs = leafs;
                    this->len = tree_len;
                    this->row_count = utilities::get_merkle_tree_row_count(leafs, branches);
                    this->root = data.read(data.len() - 1);
                }
                // Represent a fully constructed merkle tree from a provided slice.
                MerkleTree(uint8_t *data, size_t leafs) {
                    BOOST_ASSERT_MSG(SubTreeArity == 0,  "Data slice must not have sub-tree layers");
                    BOOST_ASSERT_MSG(TopTreeArity == 0, "Data slice must not have a top layer");
            
                    size_t branches = BaseTreeArity;
                    size_t row_count = utilities::get_merkle_tree_row_count(leafs, branches);
                    size_t tree_len = utilities::get_merkle_tree_len(leafs, branches)?;
                    BOOST_ASSERT_MSG(tree_len == data.len() / digest_size, "Inconsistent tree data");
            
                    BOOST_ASSERT_MSG(utilities::is_merkle_tree_size_valid(leafs, branches), "MerkleTree size is invalid given the arity");

                    let store = S::new_from_slice(tree_len, &data).context("failed to create data store")?;
                    this->data.push_back(store);
                    this->leafs = leafs;
                    this->len = tree_len;
                    this->row_count = row_count;
                    this->root = store.read(data.len() - 1);
                }
            
                // Represent a fully constructed merkle tree from a provided slice.
                MerkleTree(uint8_t * data, size_t leafs, StoreConfig config) {
                    BOOST_ASSERT_MSG(SubTreeArity == 0, "Data slice must not have sub-tree layers");
                    BOOST_ASSERT_MSG(TopTreeArity == 0, "Data slice must not have a top layer");
            
                    size_t branches = BaseTreeArity;
                    size_t row_count = utilities::get_merkle_tree_row_count(leafs, branches);
                    size_t tree_len = utilities::get_merkle_tree_len(leafs, branches)?;
                    BOOST_ASSERT_MSG(tree_len == data.len() / digest_size, "Inconsistent tree data");
            
                    BOOST_ASSERT_MSG(utilities::is_merkle_tree_size_valid(leafs, branches),  "MerkleTree size is invalid given the arity");
            
                    let store = S::new_from_slice_with_config(tree_len, branches, &data, config).context("failed to create data store")?;
                    this->data.push_back(store);
                    this->leafs = leafs;
                    this->len = tree_len;
                    this->row_count = row_count;
                    this->root = store.read(data.len() - 1);
                }
            
                // Creates new compound merkle tree from a vector of merkle
                // trees.  The ordering of the trees is significant, as trees are
                // leaf indexed / addressable in the same sequence that they are
                // provided here.
                MerkleTree(std::vector<MerkleTree<Hash, Store, BaseTreeArity>> trees) {
                    BOOST_ASSERT_MSG(SubTreeArity > 0,  "Cannot use from_trees if not constructing a structure with sub-trees");
                    BOOST_ASSERT_MSG(trees.iter().all(|ref mt| mt.row_count() == trees[0].row_count()), "All passed in trees must have the same row_count");
                    BOOST_ASSERT_MSG(trees.iter().all(|ref mt| mt.len() == trees[0].len()), "All passed in trees must have the same length");
            
                    size_t sub_tree_layer_nodes = SubTreeArity;
                    BOOST_ASSERT_MSG(trees.len() == sub_tree_layer_nodes, "Length of trees MUST equal the number of sub tree layer nodes");

                    // Total number of leafs in the compound tree is the combined leafs total of all subtrees.
                    let leafs = trees.iter().fold(0, |leafs, mt| leafs + mt.leafs());
                    // Total length of the compound tree is the combined length of all subtrees plus the root.
                    let len = trees.iter().fold(0, |len, mt| len + mt.len()) + 1;
                    // Total row_count of the compound tree is the row_count of any of the sub-trees to top-layer plus root.
                    let row_count = trees[0].row_count() + 1;
                    // Calculate the compound root by hashing the top layer roots together.
                    let roots: Vec<E> = trees.iter().map(|x| x.root()).collect();
                    let root = A::default().multi_node(&roots, 1);

                    this->data = Data::SubTree(trees);
                    this->leafs = leafs;
                    this->len = len;
                    this->row_count = row_count;
                    this->root = root;
                }
            
                // Creates new top layer merkle tree from a vector of merkle
                // trees with sub-trees.  The ordering of the trees is
                // significant, as trees are leaf indexed / addressable in the
                // same sequence that they are provided here.
                MerkleTree(std::vector<MerkleTree<Hash, Store, BaseTreeArity, SubTreeArity>> trees) {
                    BOOST_ASSERT_MSG(TopTreeArity > 0, "Cannot use from_sub_trees if not constructing a structure with sub-trees");
                    for (size_t i = 0; i < trees.size(); ++i) {
                        BOOST_ASSERT_MSG(trees[i].row_count() == trees[0].row_count(),"All passed in trees must have the same row_count");
                        BOOST_ASSERT_MSG(trees[i].len() == trees[0].len(), "All passed in trees must have the same length");
                    }

                    size_t top_layer_nodes = TopTreeArity;
                    BOOST_ASSERT_MSG(trees.len() == top_layer_nodes, "Length of trees MUST equal the number of top layer nodes");
            
                    // If we are building a compound tree with no sub-trees,
                    // all properties revert to the single tree properties.
                    let (leafs, len, row_count, root) = {
                        // Total number of leafs in the compound tree is the combined leafs total of all subtrees.
                        let leafs = trees.iter().fold(0, |leafs, mt| leafs + mt.leafs());
                        // Total length of the compound tree is the combined length of all subtrees plus the root.
                        let len = trees.iter().fold(0, |len, mt| len + mt.len()) + 1;
                        // Total row_count of the compound tree is the row_count of any of the sub-trees to top-layer plus root.
                        let row_count = trees[0].row_count() + 1;
                        // Calculate the compound root by hashing the top layer roots together.
                        let roots: Vec<E> = trees.iter().map(|x| x.root()).collect();
                        let root = A::default().multi_node(&roots, 1);
            
                        (leafs, len, row_count, root)
                    };
                    this->data = Data::TopTree(trees);
                    this->leafs = leafs;
                    this->len = len;
                    this->row_count = row_count;
                    this->root = root;
                }
            
                // Creates new top layer merkle tree from a vector of merkle
                // trees by first constructing the appropriate sub-trees.  The
                // ordering of the trees is significant, as trees are leaf
                // indexed / addressable in the same sequence that they are
                // provided here.
                MerkleTree(std::vector<MerkleTree<E, A, S, BaseTreeArity>> trees) {
                    BOOST_ASSERT_MSG(TopTreeArity > 0, "Cannot use from_sub_trees if not constructing a structure with sub-trees");
                    BOOST_ASSERT_MSG(trees.iter().all(|ref mt| mt.row_count() == trees[0].row_count()),"All passed in trees must have the same row_count");
                    BOOST_ASSERT_MSG(trees.iter().all(|ref mt| mt.len() == trees[0].len()), "All passed in trees must have the same length");
            
                    size_t sub_tree_count = TopTreeArity;
                    size_t top_layer_nodes = sub_tree_count * SubTreeArity;
                    BOOST_ASSERT_MSG(trees.len() == top_layer_nodes,"Length of trees MUST equal the number of top layer nodes");
            
                    // Group the trees appropriately into sub-tree ready vectors.
                    let mut grouped_trees = Vec::with_capacity(sub_tree_count);
                    for _ in (0..sub_tree_count).step_by(trees.len() / sub_tree_count) {
                        grouped_trees.push(trees.split_off(trees.len() / sub_tree_count));
                    }
                    grouped_trees.insert(0, trees);
            
                    let mut sub_trees: Vec<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity>> =
                        Vec::with_capacity(sub_tree_count);
                    for group in grouped_trees {
                        sub_trees.push(MerkleTree::from_trees(group)?);
                    }
            
                    let (leafs, len, row_count, root) = {
                        // Total number of leafs in the compound tree is the combined leafs total of all subtrees.
                        let leafs = sub_trees.iter().fold(0, |leafs, mt| leafs + mt.leafs());
                        // Total length of the compound tree is the combined length of all subtrees plus the root.
                        let len = sub_trees.iter().fold(0, |len, mt| len + mt.len()) + 1;
                        // Total row_count of the compound tree is the row_count of any of the sub-trees to top-layer plus root.
                        let row_count = sub_trees[0].row_count() + 1;
                        // Calculate the compound root by hashing the top layer roots together.
                        let roots: Vec<E> = sub_trees.iter().map(|x| x.root()).collect();
                        let root = A::default().multi_node(&roots, 1);
            
                        (leafs, len, row_count, root)
                    };
                    this->data = Data::TopTree(sub_trees);
                    this->leafs = leafs;
                    this->len = len;
                    this->row_count = row_count;
                    this->root = root;
                }
            
                // Create a compound merkle tree given already constructed merkle
                // trees contained as a slices. The ordering of the trees is
                // significant, as trees are leaf indexed / addressable in the
                // same sequence that they are provided here.
                pub fn from_slices(
                    tree_data: &[&[u8]],
                    leafs: usize,
                ) -> Result<MerkleTree<E, A, S, BaseTreeArity, SubTreeArity>> {
                    let mut trees = Vec::with_capacity(tree_data.len());
                    for data in tree_data {
                        trees.push(MerkleTree::<E, A, S, BaseTreeArity>::from_tree_slice(
                            data, leafs,
                        )?);
                    }
            
                    MerkleTree::from_trees(trees)
                }
            
                // Create a compound merkle tree given already constructed merkle
                // trees contained as a slices, along with configs for
                // persistence.  The ordering of the trees is significant, as
                // trees are leaf indexed / addressable in the same sequence that
                // they are provided here.
                MerkleTree(tree_data: &[&[u8]], size_t leafs: usize, configs: &[StoreConfig]) {
                    let mut trees = Vec::with_capacity(tree_data.len());
                    for i in 0..tree_data.len() {
                        trees.push(
                            MerkleTree::<E, A, S, BaseTreeArity>::from_tree_slice_with_config(
                                tree_data[i],
                                leafs,
                                configs[i].clone(),
                            )?,
                        );
                    }
                    MerkleTree::from_trees(trees)
                }
            
                // Given a set of Stores (i.e. backing to MTs), instantiate each
                // tree and return a compound merkle tree with them.  The
                // ordering of the stores is significant, as trees are leaf
                // indexed / addressable in the same sequence that they are
                // provided here.
                MerkleTree(size_t leafs, std::vector<S> stores) {
                    let mut trees = Vec::with_capacity(stores.len());
                    for store in stores {
                        trees.push(MerkleTree::<E, A, S, BaseTreeArity>::from_data_store(
                            store, leafs,
                        )?);
                    }
                    MerkleTree::from_trees(trees)
                }
            
                // Given a set of StoreConfig's (i.e on-disk references to disk
                // stores), instantiate each tree and return a compound merkle
                // tree with them.  The ordering of the trees is significant, as
                // trees are leaf indexed / addressable in the same sequence that
                // they are provided here.
                MerkleTree(size_t leafs, configs: &[StoreConfig]) {
                    let branches = BaseTreeArity::to_usize();
                    let mut trees = Vec::with_capacity(configs.len());
                    for config in configs {
                        let data = S::new_with_config(
                            get_merkle_tree_len(leafs, branches)?,
                            branches,
                            config.clone(),
                        )
                        .context("failed to create data store")?;
                        trees.push(MerkleTree::<E, A, S, BaseTreeArity>::from_data_store(
                            data, leafs,
                        )?);
                    }
                    MerkleTree::from_trees(trees)
                }
            
                // Given a set of StoreConfig's (i.e on-disk references to dis
                // stores), instantiate each sub tree and return a compound
                // merkle tree with them.  The ordering of the trees is
                // significant, as trees are leaf indexed / addressable in the
                // same sequence that they are provided here.
            //    pub fn from_sub_tree_store_configs(
            //        leafs: usize,
            //        configs: &[StoreConfig],
            //    ) -> Result<<E, A, S, BaseTreeArity, SubTreeArity, TopTreeArity>> {
            //        let tree_count = TopTreeArity;
            //
            //        let mut start = 0;
            //        let mut end = configs.len() / tree_count;
            //
            //        let mut trees = Vec::with_capacity(tree_count);
            //        for _ in 0..tree_count {
            //            trees.push(
            //                MerkleTree::<E, A, S, BaseTreeArity, SubTreeArity>::from_store_configs(
            //                    leafs,
            //                    &configs[start..end],
            //                )?,
            //            );
            //            start = end;
            //            end += configs.len() / tree_count;
            //        }
            //
            //        Self::from_sub_trees(trees)
            //    }
            
                fn build_partial_tree(std::vector<E> data, size_t leafs, size_t row_count)
                    mut data: VecStore<E>,
                    leafs: usize,
                    row_count: usize,
                ) -> Result<MerkleTree<E, A, VecStore<E>, BaseTreeArity>> {
                    let root = VecStore::build::<A, BaseTreeArity>(&mut data, leafs, row_count, None)?;
                    let branches = BaseTreeArity::to_usize();
            
                    let tree_len = get_merkle_tree_len(leafs, branches)?;
                    BOOST_ASSERT_MSG(tree_len == Store::len(&data), "Inconsistent tree data");
            
                    BOOST_ASSERT_MSG(
                        is_merkle_tree_size_valid(leafs, branches),
                        "MerkleTree size is invalid given the arity"
                    );
            
                    Ok(MerkleTree {
                        data: Data::BaseTree(data),
                        leafs,
                        len: tree_len,
                        row_count,
                        root
                    })
                }
            
                // Generate merkle sub tree inclusion proof for leaf `i` for
                // either the top layer or the sub-tree layer, specified by the
                // top_layer flag
                fn gen_sub_tree_proof(size_t i, bool top_layer, size_t arity) -> Result<Proof<E, BaseTreeArity>> {
                    BOOST_ASSERT_MSG(arity != 0, "Invalid sub-tree arity");
            
                    // Locate the sub-tree the leaf is contained in.
                    let tree_index = i / (this->leafs / arity);
            
                    // Generate the sub tree proof at this tree level.
                    let sub_tree_proof = if top_layer {
                        BOOST_ASSERT_MSG(this->data.sub_trees().is_some(), "sub trees required");
                        let sub_trees = this->data.sub_trees().unwrap();
                        BOOST_ASSERT_MSG(arity == sub_trees.len(), "Top layer tree shape mis-match");
            
                        let tree = &sub_trees[tree_index];
                        let leaf_index = i % tree.leafs();
            
                        tree.gen_proof(leaf_index)
                    } else {
                        BOOST_ASSERT_MSG(this->data.base_trees().is_some(), "base trees required");
                        let base_trees = this->data.base_trees().unwrap();
                        BOOST_ASSERT_MSG(arity == base_trees.len(), "Sub tree layer shape mis-match");
            
                        let tree = &base_trees[tree_index];
                        let leaf_index = i % tree.leafs();
            
                        tree.gen_proof(leaf_index)
                    }?;
            
                    // Construct the top layer proof.  'lemma' length is
                    // top_layer_nodes - 1 + root == top_layer_nodes
                    let mut path: Vec<usize> = Vec::with_capacity(1); // path - 1
                    let mut lemma: Vec<E> = Vec::with_capacity(arity);
                    for i in 0..arity {
                        if i != tree_index {
                            lemma.push(if top_layer {
                                BOOST_ASSERT_MSG(this->data.sub_trees().is_some(), "sub trees required");
                                let sub_trees = this->data.sub_trees().unwrap();
            
                                sub_trees[i].root()
                            } else {
                                BOOST_ASSERT_MSG(this->data.base_trees().is_some(), "base trees required");
                                let base_trees = this->data.base_trees().unwrap();
            
                                base_trees[i].root()
                            });
                        }
                    }
            
                    lemma.push(this->root());
                    path.push(tree_index);
            
                    Proof::new::<TopTreeArity, SubTreeArity>(Some(Box::new(sub_tree_proof)), lemma, path)
                }
            
                // Generate merkle tree inclusion proof for leaf `i`
                #[inline]
                pub fn gen_proof(size_t i) -> Result<Proof<E, BaseTreeArity>> {
                    match &this->data {
                        Data::TopTree(_) => this->gen_sub_tree_proof(i, true, TopTreeArity),
                        Data::SubTree(_) => this->gen_sub_tree_proof(i, false, SubTreeArity),
                        Data::BaseTree(_) => {
                            BOOST_ASSERT_MSG(
                                i < this->leafs,
                                "{} is out of bounds (max: {})",
                                i,
                                this->leafs
                            ); // i in [0 .. this->leafs)
            
                            let mut base = 0;
                            let mut j = i;
            
                            // level 1 width
                            let mut width = this->leafs;
                            let branches = BaseTreeArity::to_usize();
                            BOOST_ASSERT_MSG(width == next_pow2(width), "Must be a power of 2 tree");
                            BOOST_ASSERT_MSG(
                                branches == next_pow2(branches),
                                "branches must be a power of 2"
                            );
                            let shift = log2_pow2(branches);
            
                            let mut lemma: Vec<E> =
                                Vec::with_capacity(get_merkle_proof_lemma_len(this->row_count, branches));
                            let mut path: Vec<usize> = Vec::with_capacity(this->row_count - 1); // path - 1
            
                            // item is first
                            BOOST_ASSERT_MSG(SubTreeArity == 0,"Data slice must not have sub-tree layers");
                            BOOST_ASSERT_MSG(TopTreeArity == 0,"Data slice must not have a top layer");
            
                            lemma.push(this->read_at(j)?);
                            while base + 1 < this->len() {
                                let hash_index = (j / branches) * branches;
                                for k in hash_index..hash_index + branches {
                                    if k != j {
                                        lemma.push(this->read_at(base + k)?)
                                    }
                                }
            
                                path.push(j % branches); // path_index
            
                                base += width;
                                width >>= shift; // width /= branches;
                                j >>= shift; // j /= branches;
                            }
            
                            // root is final
                            lemma.push(this->root());
            
                            // Sanity check: if the `MerkleTree` lost its integrity and `data` doesn't match the
                            // expected values for `leafs` and `row_count` this can get ugly.
                            BOOST_ASSERT_MSG(lemma.len() == get_merkle_proof_lemma_len(this->row_count, branches),"Invalid proof lemma length");
                            BOOST_ASSERT_MSG(path.len() == this->row_count - 1,"Invalid proof path length");
            
                            Proof::new::<U0, U0>(None, lemma, path)
                        }
                    }
                }
            
                // Generate merkle sub-tree inclusion proof for leaf `i` using
                // partial trees built from cached data if needed at that layer.
                fn gen_cached_top_tree_proof<Arity: Unsigned>(size_t i, size_t rows_to_discard) -> Result<Proof<E, BaseTreeArity>> {
                    BOOST_ASSERT_MSG(Arity::to_usize() != 0, "Invalid top-tree arity");
                    BOOST_ASSERT_MSG(i < this->leafs,"{} is out of bounds (max: {})",i,this->leafs); // i in [0 .. this->leafs)
            
                    // Locate the sub-tree the leaf is contained in.
                    BOOST_ASSERT_MSG(this->data.sub_trees().is_some(), "sub trees required");
                    let trees = &this->data.sub_trees().unwrap();
                    let tree_index = i / (this->leafs / Arity::to_usize());
                    let tree = &trees[tree_index];
                    let tree_leafs = tree.leafs();
            
                    // Get the leaf index within the sub-tree.
                    let leaf_index = i % tree_leafs;
            
                    // Generate the proof that will validate to the provided
                    // sub-tree root (note the branching factor of B).
                    let sub_tree_proof = tree.gen_cached_proof(leaf_index, rows_to_discard)?;
            
                    // Construct the top layer proof.  'lemma' length is
                    // top_layer_nodes - 1 + root == top_layer_nodes
                    let mut path: Vec<usize> = Vec::with_capacity(1); // path - 1
                    let mut lemma: Vec<E> = Vec::with_capacity(Arity::to_usize());
                    for i in 0..Arity::to_usize() {
                        if i != tree_index {
                            lemma.push(trees[i].root())
                        }
                    }
            
                    lemma.push(this->root());
                    path.push(tree_index);
            
                    // Generate the final compound tree proof which is composed of
                    // a sub-tree proof of branching factor B and a top-level
                    // proof with a branching factor of SubTreeArity.
                    Proof::new::<TopTreeArity, SubTreeArity>(Some(Box::new(sub_tree_proof)), lemma, path)
                }
            
                // Generate merkle sub-tree inclusion proof for leaf `i` using
                // partial trees built from cached data if needed at that layer.
                fn gen_cached_sub_tree_proof<Arity: Unsigned>(size_t i, size_t rows_to_discard) -> Result<Proof<E, BaseTreeArity>> {
                    BOOST_ASSERT_MSG(Arity::to_usize() != 0, "Invalid sub-tree arity");
                    BOOST_ASSERT_MSG(i < this->leafs,"{} is out of bounds (max: {})",i,this->leafs); // i in [0 .. this->leafs)
            
                    // Locate the sub-tree the leaf is contained in.
                    BOOST_ASSERT_MSG(this->data.base_trees().is_some(), "base trees required");
                    let trees = &this->data.base_trees().unwrap();
                    let tree_index = i / (this->leafs / Arity::to_usize());
                    let tree = &trees[tree_index];
                    let tree_leafs = tree.leafs();
            
                    // Get the leaf index within the sub-tree.
                    let leaf_index = i % tree_leafs;
            
                    // Generate the proof that will validate to the provided
                    // sub-tree root (note the branching factor of B).
                    let sub_tree_proof = tree.gen_cached_proof(leaf_index, rows_to_discard)?;
            
                    // Construct the top layer proof.  'lemma' length is
                    // top_layer_nodes - 1 + root == top_layer_nodes
                    let mut path: Vec<usize> = Vec::with_capacity(1); // path - 1
                    let mut lemma: Vec<E> = Vec::with_capacity(Arity::to_usize());
                    for i in 0..Arity::to_usize() {
                        if i != tree_index {
                            lemma.push(trees[i].root())
                        }
                    }
            
                    lemma.push(this->root());
                    path.push(tree_index);
            
                    // Generate the final compound tree proof which is composed of
                    // a sub-tree proof of branching factor B and a top-level
                    // proof with a branching factor of SubTreeArity.
                    Proof::new::<TopTreeArity, SubTreeArity>(Some(Box::new(sub_tree_proof)), lemma, path)
                }
            
                // Generate merkle tree inclusion proof for leaf `i` by first
                // building a partial tree (returned) along with the proof.
                // 'rows_to_discard' is an option that will be used if set (even
                // if it may cause an error), otherwise a reasonable default is
                // chosen.
                //
                // Return value is a Result tuple of the proof and the partial
                // tree that was constructed.
                pub fn gen_cached_proof(size_t i, size_t rows_to_discard) -> Result<Proof<E, BaseTreeArity>> {
                    match &this->data {
                        Data::TopTree(_) => this->gen_cached_top_tree_proof::<TopTreeArity>(i, rows_to_discard),
                        Data::SubTree(_) => this->gen_cached_sub_tree_proof::<SubTreeArity>(i, rows_to_discard),
                        Data::BaseTree(_) => {
                            BOOST_ASSERT_MSG(i < this->leafs,"{} is out of bounds (max: {})",i,this->leafs); // i in [0 .. this->leafs]
            
                            // For partial tree building, the data layer width must be a
                            // power of 2.
                            BOOST_ASSERT_MSG(this->leafs == next_pow2(this->leafs),"The size of the data layer must be a power of 2");
            
                            let branches = BaseTreeArity::to_usize();
                            let total_size = get_merkle_tree_len(this->leafs, branches)?;
                            // If rows to discard is specified and we *know* it's a value that will cause an error
                            // (i.e. there are not enough rows to discard, we use a sane default instead).  This
                            // primarily affects tests because it only affects 'small' trees, entirely outside the
                            // scope of any 'production' tree width.
                            let rows_to_discard = if let Some(rows) = rows_to_discard {
                                std::cmp::min(
                                    rows,
                                    StoreConfig::default_rows_to_discard(this->leafs, branches),
                                )
                            } else {
                                StoreConfig::default_rows_to_discard(this->leafs, branches)
                            };
                            let cache_size = get_merkle_tree_cache_size(this->leafs, branches, rows_to_discard)?;
                            BOOST_ASSERT_MSG(cache_size < total_size,"Generate a partial proof with all data available?");
            
                            let cached_leafs = get_merkle_tree_leafs(cache_size, branches)?;
                            BOOST_ASSERT_MSG(cached_leafs == next_pow2(cached_leafs),"The size of the cached leafs must be a power of 2");
            
                            let cache_row_count = get_merkle_tree_row_count(cached_leafs, branches);
                            let partial_row_count = this->row_count - cache_row_count + 1;
            
                            // Calculate the subset of the base layer data width that we
                            // need in order to build the partial tree required to build
                            // the proof (termed 'segment_width'), given the data
                            // configuration specified by 'rows_to_discard'.
                            let segment_width = this->leafs / cached_leafs;
                            let segment_start = (i / segment_width) * segment_width;
                            let segment_end = segment_start + segment_width;
            
                            // Copy the proper segment of the base data into memory and
                            // initialize a VecStore to back a new, smaller MT.
                            let mut data_copy = vec![0; segment_width * E::byte_len()];
                            BOOST_ASSERT_MSG(this->data.store().is_some(), "store data required");
            
                            this->data.store().unwrap().read_range_into(
                                segment_start,
                                segment_end,
                                &mut data_copy,
                            )?;
                            let partial_store = VecStore::new_from_slice(segment_width, &data_copy)?;
                            BOOST_ASSERT_MSG(Store::len(&partial_store) == segment_width,"Inconsistent store length");
            
                            // Before building the tree, resize the store where the tree
                            // will be built to allow space for the newly constructed layers.
                            data_copy.resize(
                                get_merkle_tree_len(segment_width, branches)? * E::byte_len(),
                                0,
                            );
            
                            // Build the optimally small tree.
                            let partial_tree: MerkleTree<E, A, VecStore<E>, BaseTreeArity> =
                                Self::build_partial_tree(partial_store, segment_width, partial_row_count)?;
                            BOOST_ASSERT_MSG(partial_row_count == partial_tree.row_count(),"Inconsistent partial tree row_count");
            
                            // Generate entire proof with access to the base data, the
                            // cached data, and the partial tree.
                            let proof = this->gen_proof_with_partial_tree(i, rows_to_discard, &partial_tree)?;
                            
                            Ok(proof)
                        }
                    }
                }
            
                // Generate merkle tree inclusion proof for leaf `i` given a
                // partial tree for lookups where data is otherwise unavailable.
                fn gen_proof_with_partial_tree(size_t i, size_t rows_to_discard,
                    partial_tree: &MerkleTree<E, A, VecStore<E>, BaseTreeArity>,
                ) -> Result<Proof<E, BaseTreeArity>> {
                    BOOST_ASSERT_MSG(i < this->leafs,"{} is out of bounds (max: {})",i,this->leafs); // i in [0 .. this->leafs)
            
                    // For partial tree building, the data layer width must be a
                    // power of 2.
                    let mut width = this->leafs;
                    let branches = BaseTreeArity::to_usize();
                    BOOST_ASSERT_MSG(width == next_pow2(width), "Must be a power of 2 tree");
                    BOOST_ASSERT_MSG(branches == next_pow2(branches),"branches must be a power of 2");
            
                    let data_width = width;
                    let total_size = get_merkle_tree_len(data_width, branches)?;
                    let cache_size = get_merkle_tree_cache_size(this->leafs, branches, rows_to_discard)?;
                    let cache_index_start = total_size - cache_size;
                    let cached_leafs = get_merkle_tree_leafs(cache_size, branches)?;
                    BOOST_ASSERT_MSG(cached_leafs == next_pow2(cached_leafs),"Cached leafs size must be a power of 2");
            
                    // Calculate the subset of the data layer width that we need
                    // in order to build the partial tree required to build the
                    // proof (termed 'segment_width').
                    let mut segment_width = width / cached_leafs;
                    let segment_start = (i / segment_width) * segment_width;
            
                    // shift is the amount that we need to decrease the width by
                    // the number of branches at each level up the main merkle
                    // tree.
                    let shift = log2_pow2(branches);
            
                    // segment_shift is the amount that we need to offset the
                    // partial tree offsets to keep them within the space of the
                    // partial tree as we move up it.
                    //
                    // segment_shift is conceptually (segment_start >>
                    // (current_row_count * shift)), which tracks an offset in the
                    // main merkle tree that we apply to the partial tree.
                    let mut segment_shift = segment_start;
            
                    // 'j' is used to track the challenged nodes required for the
                    // proof up the tree.
                    let mut j = i;
            
                    // 'base' is used to track the data index of the layer that
                    // we're currently processing in the main merkle tree that's
                    // represented by the store.
                    let mut base = 0;
            
                    // 'partial_base' is used to track the data index of the layer
                    // that we're currently processing in the partial tree.
                    let mut partial_base = 0;
            
                    let mut lemma: Vec<E> =
                        Vec::with_capacity(get_merkle_proof_lemma_len(this->row_count, branches));
                    let mut path: Vec<usize> = Vec::with_capacity(this->row_count - 1); // path - 1
            
                    BOOST_ASSERT_MSG(SubTreeArity == 0,"Data slice must not have sub-tree layers");
                    BOOST_ASSERT_MSG(TopTreeArity == 0,"Data slice must not have a top layer");
            
                    lemma.push(this->read_at(j)?);
                    while base + 1 < this->len() {
                        let hash_index = (j / branches) * branches;
                        for k in hash_index..hash_index + branches {
                            if k != j {
                                let read_index = base + k;
                                lemma.push(
                                    if read_index < data_width || read_index >= cache_index_start {
                                        this->read_at(base + k)?
                                    } else {
                                        let read_index = partial_base + k - segment_shift;
                                        partial_tree.read_at(read_index)?
                                    },
                                );
                            }
                        }
            
                        path.push(j % branches); // path_index
            
                        base += width;
                        width >>= shift; // width /= branches
            
                        partial_base += segment_width;
                        segment_width >>= shift; // segment_width /= branches
            
                        segment_shift >>= shift; // segment_shift /= branches
            
                        j >>= shift; // j /= branches;
                    }
            
                    // root is final
                    lemma.push(this->root());
            
                    // Sanity check: if the `MerkleTree` lost its integrity and `data` doesn't match the
                    // expected values for `leafs` and `row_count` this can get ugly.
                    BOOST_ASSERT_MSG(lemma.len() == get_merkle_proof_lemma_len(this->row_count, branches),"Invalid proof lemma length");
                    BOOST_ASSERT_MSG(path.len() == this->row_count - 1,"Invalid proof path length");
            
                    Proof::new::<U0, U0>(None, lemma, path)
                }
            
                // Returns merkle root
                E root() {
                    return this->root;
                }
            
                // Returns number of elements in the tree.
                size_t len() {
                    match &this->data {
                        Data::TopTree(_) => this->len,
                        Data::SubTree(_) => this->len,
                        Data::BaseTree(store) => store.len(),
                    }
                }
            
                // Truncates the data for later access via LevelCacheStore
                // interface.
                bool compact(StoreConfig config, uint32_t store_version) {
                    let branches = BaseTreeArity::to_usize();
                    BOOST_ASSERT_MSG(this->data.store_mut().is_some(), "store data required");
            
                    this->data.store_mut().unwrap().compact(branches, config, store_version)
                }
            
                void reinit() {
                    BOOST_ASSERT_MSG(this->data.store_mut().is_some(), "store data required");
                    this->data.store_mut().unwrap().reinit()
                }
            
                // Removes the backing store for this merkle tree.
                void delete(StoreConfig config) {
                    S::delete(config)
                }
            
                // Returns `true` if the store contains no elements.
                    bool is_empty() {
                    match &this->data {
                        Data::TopTree(_) => true,
                        Data::SubTree(_) => true,
                        Data::BaseTree(store) => store.is_empty(),
                    }
                }
            
                // Returns row_count of the tree
                size_t row_count() {
                    return this->row_count;
                }
            
                // Returns original number of elements the tree was built upon.
                size_t leafs() {
                    return this->leafs;
                }
            
                // Returns data reference
                pub fn data(&self) -> Option<&S> {
                    match &this->data {
                        Data::TopTree(_) => None,
                        Data::SubTree(_) => None,
                        Data::BaseTree(store) => Some(store),
                    }
                }
            
                // Returns merkle leaf at index i
                E read_at(size_t i) {
                    match &this->data {
                        Data::TopTree(sub_trees) => {
                            // Locate the top-layer tree the sub-tree leaf is contained in.
                            BOOST_ASSERT_MSG(TopTreeArity == sub_trees.len(),"Top layer tree shape mis-match");
                            let tree_index = i / (this->leafs / TopTreeArity);
                            let tree = &sub_trees[tree_index];
                            let tree_leafs = tree.leafs();
            
                            // Get the leaf index within the sub-tree.
                            let leaf_index = i % tree_leafs;
            
                            tree.read_at(leaf_index)
                        }
                        Data::SubTree(base_trees) => {
                            // Locate the sub-tree layer tree the base leaf is contained in.
                            BOOST_ASSERT_MSG(SubTreeArity == base_trees.len(),"Sub-tree shape mis-match");
                            let tree_index = i / (this->leafs / SubTreeArity);
                            let tree = &base_trees[tree_index];
                            let tree_leafs = tree.leafs();
            
                            // Get the leaf index within the sub-tree.
                            let leaf_index = i % tree_leafs;
            
                            tree.read_at(leaf_index)
                        }
                        Data::BaseTree(data) => {
                            // Read from the base layer tree data.
                            data.read_at(i)
                        }
                    }
                }
            
                std::vector<E> read_range(size_t start, size_t end) {
                    BOOST_ASSERT_MSG(start < end, "start must be less than end");
                    BOOST_ASSERT_MSG(this->data.store().is_some(), "store data required");
                    this->data.store().unwrap().read_range(start..end)
                }
            
                void read_range_into(size_t start, size_t end, uint8_t *buf) {
                    BOOST_ASSERT_MSG(start < end, "start must be less than end");
                    BOOST_ASSERT_MSG(this->data.store().is_some(), "store data required");
                    this->data.store().unwrap().read_range_into(start, end, buf)
                }
            
                // Reads into a pre-allocated slice (for optimization purposes).
                void read_into(size_t pos, uint8_t *buf) {
                    BOOST_ASSERT_MSG(this->data.store().is_some(), "store data required");
                    this->data.store().unwrap().read_into(pos, buf)
                }
            
                // Build the tree given a slice of all leafs, in bytes form.
                pub fn from_byte_slice_with_config(leafs: &[u8], config: StoreConfig) -> Result<Self> {
                    BOOST_ASSERT_MSG(leafs.len() % E::byte_len() == 0,"{} ist not a multiple of {}",leafs.len(),E::byte_len());
            
                    let leafs_count = leafs.len() / E::byte_len();
                    let branches = BaseTreeArity::to_usize();
                    BOOST_ASSERT_MSG(leafs_count > 1, "not enough leaves");
                    BOOST_ASSERT_MSG(next_pow2(leafs_count) == leafs_count,"size MUST be a power of 2");
                    BOOST_ASSERT_MSG(next_pow2(branches) == branches,"branches MUST be a power of 2");
            
                    let size = get_merkle_tree_len(leafs_count, branches)?;
                    let row_count = get_merkle_tree_row_count(leafs_count, branches);
            
                    let mut data = S::new_from_slice_with_config(size, branches, leafs, config.clone())
                        .context("failed to create data store")?;
                    let root = S::build::<A, BaseTreeArity>(&mut data, leafs_count, row_count, Some(config))?;
                    this->data = Data::BaseTree(data);
                    this->leafs = leafs_count;
                    this->len = size;
                    this->row_count = row_count;
                }
            
                // Build the tree given a slice of all leafs, in bytes form.
                pub fn from_byte_slice(leafs: &[u8]) -> Result<Self> {
                    BOOST_ASSERT_MSG(leafs.len() % E::byte_len() == 0,"{} is not a multiple of {}",leafs.len(),E::byte_len());
            
                    let leafs_count = leafs.len() / E::byte_len();
                    let branches = BaseTreeArity::to_usize();
                    BOOST_ASSERT_MSG(leafs_count > 1, "not enough leaves");
                    BOOST_ASSERT_MSG(next_pow2(leafs_count) == leafs_count,"size MUST be a power of 2");
                    BOOST_ASSERT_MSG(next_pow2(branches) == branches,"branches MUST be a power of 2");
            
                    let size = get_merkle_tree_len(leafs_count, branches)?;
                    let row_count = get_merkle_tree_row_count(leafs_count, branches);
            
                    let mut data = S::new_from_slice(size, leafs).context("failed to create data store")?;
            
                    let root = S::build::<A, BaseTreeArity>(&mut data, leafs_count, row_count, None)?;
            
                    Ok(MerkleTree {
                        data: Data::BaseTree(data),
                        leafs: leafs_count,
                        len: size,
                        row_count,
                        root
                    })
                }

                // Attempts to create a new merkle tree using hashable objects yielded by
                // the provided iterator. This method returns the first error yielded by
                // the iterator, if the iterator yielded an error.
                // try_from_iter
                MerkleTree(std::pair<uint8_t *, uint8_t *> data) {
                    size_t leafs = (data.second - data.first) / digest_size;
                    size_t branches = BaseTreeArity;
                    BOOST_ASSERT_MSG(leafs > 1, "not enough leaves");
                    BOOST_ASSERT_MSG(next_pow2(leafs) == leafs, "size MUST be a power of 2");
                    BOOST_ASSERT_MSG(next_pow2(branches) == branches,"branches MUST be a power of 2");

                    size_t size = get_merkle_tree_len(leafs, branches);
                    size_t row_count = get_merkle_tree_row_count(leafs, branches);

                    self->root = self->build<BaseTreeArity>(data, leafs, row_count, None);
                    self->data = Data::BaseTree(data);
                    self->leafs = leafs;
                    self->len = size;
                    self->row_count = row_count;
                }
            }
            
            pub trait FromIndexedParallelIterator<E, BaseTreeArity>: Sized
            where
                E: Send,
            {
                fn from_par_iter<I>(par_iter: I) -> Result<Self>
                where
                    BaseTreeArity: Unsigned,
                    I: IntoParallelIterator<Item = E>,
                    I::Iter: IndexedParallelIterator;
            
                fn from_par_iter_with_config<I>(par_iter: I, config: StoreConfig) -> Result<Self>
                where
                    I: IntoParallelIterator<Item = E>,
                    I::Iter: IndexedParallelIterator,
                    BaseTreeArity: Unsigned;
            }
            
            impl<
                    E: Element,
                    A: Algorithm<E>,
                    S: Store<E>,
                    BaseTreeArity: Unsigned,
                    SubTreeArity: Unsigned,
                    TopTreeArity: Unsigned,
                > FromIndexedParallelIterator<E, BaseTreeArity>
                for MerkleTree<E, A, S, BaseTreeArity, SubTreeArity, TopTreeArity>
            {
                // Creates new merkle tree from an iterator over hashable objects.
                fn from_par_iter<I>(into: I) -> Result<Self>
                where
                    I: IntoParallelIterator<Item = E>,
                    I::Iter: IndexedParallelIterator,
                {
                    let iter = into.into_par_iter();
            
                    let leafs = iter.opt_len().expect("must be sized");
                    let branches = BaseTreeArity::to_usize();
                    BOOST_ASSERT_MSG(leafs > 1, "not enough leaves");
                    BOOST_ASSERT_MSG(next_pow2(leafs) == leafs, "size MUST be a power of 2");
                    BOOST_ASSERT_MSG(next_pow2(branches) == branches,"branches MUST be a power of 2");
            
                    let size = get_merkle_tree_len(leafs, branches)?;
                    let row_count = get_merkle_tree_row_count(leafs, branches);
            
                    let mut data = S::new(size).expect("failed to create data store");
            
                    populate_data_par::<E, A, S, BaseTreeArity, _>(&mut data, iter)?;
                    let root = S::build::<A, BaseTreeArity>(&mut data, leafs, row_count, None)?;
            
                    Ok(MerkleTree {
                        data: Data::BaseTree(data),
                        leafs,
                        len: size,
                        row_count,
                        root
                    })
                }
            
                // Creates new merkle tree from an iterator over hashable objects.
                fn from_par_iter_with_config<I>(into: I, config: StoreConfig) -> Result<Self>
                where
                    BaseTreeArity: Unsigned,
                    I: IntoParallelIterator<Item = E>,
                    I::Iter: IndexedParallelIterator,
                {
                    let iter = into.into_par_iter();
            
                    let leafs = iter.opt_len().expect("must be sized");
                    let branches = BaseTreeArity::to_usize();
                    BOOST_ASSERT_MSG(leafs > 1, "not enough leaves");
                    BOOST_ASSERT_MSG(next_pow2(leafs) == leafs, "size MUST be a power of 2");
                    BOOST_ASSERT_MSG(next_pow2(branches) == branches,"branches MUST be a power of 2");
            
                    let size = get_merkle_tree_len(leafs, branches)?;
                    let row_count = get_merkle_tree_row_count(leafs, branches);
            
                    let mut data = S::new_with_config(size, branches, config.clone())
                        .context("failed to create data store")?;
            
                    // If the data store was loaded from disk, we know we have
                    // access to the full merkle tree.
                    if data.loaded_from_disk() {
                        let root = data.last().context("failed to read root")?;
            
                        return Ok(MerkleTree {
                            data: Data::BaseTree(data),
                            leafs,
                            len: size,
                            row_count,
                            root
                        });
                    }
            
                    populate_data_par::<E, A, S, BaseTreeArity, _>(&mut data, iter)?;
                    let root = S::build::<A, BaseTreeArity>(&mut data, leafs, row_count, Some(config))?;
            
                    Ok(MerkleTree {
                        data: Data::BaseTree(data),
                        leafs,
                        len: size,
                        row_count,
                        root
                    })
                }
            }


            
                // Attempts to create a new merkle tree using hashable objects yielded by
                // the provided iterator and store config. This method returns the first
                // error yielded by the iterator, if the iterator yielded an error.
                pub fn try_from_iter_with_config<I: IntoIterator<Item = Result<E>>>(
                    into: I,
                    config: StoreConfig,
                ) -> Result<Self> {
                    let iter = into.into_iter();
            
                    let (_, n) = iter.size_hint();
                    let leafs = n.ok_or_else(|| anyhow!("could not get size hint from iterator"))?;
                    let branches = BaseTreeArity::to_usize();
                    BOOST_ASSERT_MSG(leafs > 1, "not enough leaves");
                    BOOST_ASSERT_MSG(next_pow2(leafs) == leafs, "size MUST be a power of 2");
                    BOOST_ASSERT_MSG(
                        next_pow2(branches) == branches,
                        "branches MUST be a power of 2"
                    );
            
                    let size = get_merkle_tree_len(leafs, branches)?;
                    let row_count = get_merkle_tree_row_count(leafs, branches);
            
                    let mut data = S::new_with_config(size, branches, config.clone())
                        .context("failed to create data store")?;
            
                    // If the data store was loaded from disk, we know we have
                    // access to the full merkle tree.
                    if data.loaded_from_disk() {
                        let root = data.last().context("failed to read root")?;
            
                        return Ok(MerkleTree {
                            data: Data::BaseTree(data),
                            leafs,
                            len: size,
                            row_count,
                            root
                        });
                    }
            
                    populate_data::<E, A, S, BaseTreeArity, I>(&mut data, iter)
                        .expect("failed to populate data");
                    let root = S::build::<A, BaseTreeArity>(&mut data, leafs, row_count, Some(config))?;
            
                    Ok(MerkleTree {
                        data: Data::BaseTree(data),
                        leafs,
                        len: size,
                        row_count,
                        root
                    })
                }
            }
            }
            
            impl Element for [u8; 32] {
                fn byte_len() -> usize {
                    32
                }
            
                fn from_slice(bytes: &[u8]) -> Self {
                    if bytes.len() != 32 {
                        panic!("invalid length {}, expected 32", bytes.len());
                    }
                    *array_ref!(bytes, 0, 32)
                }
            
                fn copy_to_slice(&self, bytes: &mut [u8]) {
                    bytes.copy_from_slice(self);
                }
            }
            
            pub fn populate_data<
                E: Element,
                A: Algorithm<E>,
                S: Store<E>,
                BaseTreeArity: Unsigned,
                I: IntoIterator<Item = Result<E>>,
            >(S data,
                iter: <I as std::iter::IntoIterator>::IntoIter,
            ) -> Result<()> {
                if !data.is_empty() {
                    return;
                }
            
                let mut buf = Vec::with_capacity(BUILD_DATA_BLOCK_SIZE * E::byte_len());
            
                let mut a = A::default();
                for item in iter {
                    // short circuit the tree-populating routine if the iterator yields an
                    // error
                    let item = item?;
            
                    a.reset();
                    buf.extend(a.leaf(item).as_ref());
                    if buf.len() >= BUILD_DATA_BLOCK_SIZE * E::byte_len() {
                        let data_len = data.len();
                        // FIXME: Integrate into `len()` call into `copy_from_slice`
                        // once we update to `stable` 1.36.
                        data.copy_from_slice(&buf, data_len)?;
                        buf.clear();
                    }
                }
                let data_len = data.len();
                data.copy_from_slice(&buf, data_len)?;
                data.sync()?;
            }
            
            void populate_data_par<E, A, S, BaseTreeArity, I>(data: &mut S, iter: I)
            where
                E: Element,
                A: Algorithm<E>,
                S: Store<E>,
                BaseTreeArity: Unsigned,
                I: ParallelIterator<Item = E> + IndexedParallelIterator,
            {
                if !data.is_empty() {
                    return Ok(());
                }
            
                let store = Arc::new(RwLock::new(data));
            
                iter.chunks(BUILD_DATA_BLOCK_SIZE)
                    .enumerate()
                    .try_for_each(|(index, chunk)| {
                        let mut a = A::default();
                        let mut buf = Vec::with_capacity(BUILD_DATA_BLOCK_SIZE * E::byte_len());
            
                        for item in chunk {
                            a.reset();
                            buf.extend(a.leaf(item).as_ref());
                        }
                        store
                            .write()
                            .unwrap()
                            .copy_from_slice(&buf[..], BUILD_DATA_BLOCK_SIZE * index)
                    })?;
            
                store.write().unwrap().sync()?;
            }
        }    // namespace merkletree
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_DISK_HPP
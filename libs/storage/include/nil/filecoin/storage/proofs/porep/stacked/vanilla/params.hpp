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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_PARAMS_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_PARAMS_HPP

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/challenges.hpp>

namespace nil {
    namespace filecoin {
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
                return format !("layered_drgporep::PublicParams{{ graph: {}, challenges: {:?}, tree: {} }}",
                                self.graph.identifier(),
                                self.layer_challenges,
                                Tree::display());
            }

            std::uint64_t sector_size() {
                return graph.sector_size();
            }

            StackedBucketGraph<hash_type> graph;
            LayerChallenges layer_challenges;
            tree_type &_t;
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

        template<typename MerkleTreeType>
        struct Labels {
            std::vector<StoreConfig> labels;
            Tree &_h;
        };

        template<typename MerkleTreeType, typename Hash>
        struct TemporaryAux {
            Labels<MerkleTreeType> labels;
            StoreConfig tree_d_config;
            StoreConfig tree_r_last_config;
            StoreConfig tree_c_config;
            Hash &_g;
        };

        template<typename T, typename S>
        struct PublicInputs {
            std::vector<std::size_t> challenges(const LayerChallenges &layer_challenges, std::size_t leaves,
                                                std::size_t partition_k) {
                let k = partition_k.unwrap_or(0);

                return layer_challenges.derive::<T>(leaves, &self.replica_id, &self.seed, k);
            }

            T replica_id;

            std::array<std::uint8_t, 32> seed;

            Tau<T, S> tau;

            /// Partition index
            std::size_t k;
        };

        template<typename MerkleTreeType, typename Hash>
        struct PrivateInputs {
            PersistentAux<typename MerkleTreeType::hash_type::domain_type> p_aux;
            TemporaryAuxCache<MerkleTreeType, Hash> t_aux;
        };

        template<typename MerkleTreeType, typename Hash>
        struct Proof {
            MerkleProof<G, typenum::U2> comm_d_proofs;
            MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity> comm_r_last_proof;
            ReplicaColumnProof<MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>
                replica_column_proofs;
        };

impl<Tree: MerkleTreeTrait, G: Hasher> Clone for Proof<Tree, G> {
    fn clone(&self)->Self {
        Self {
        comm_d_proofs:
            self.comm_d_proofs.clone(), comm_r_last_proof : self.comm_r_last_proof.clone(),
                replica_column_proofs : self.replica_column_proofs.clone(),
                labeling_proofs : self.labeling_proofs.clone(), encoding_proof : self.encoding_proof.clone(),
        }
    }
}

impl<Tree : MerkleTreeTrait, G : Hasher> Proof<Tree, G> {
    pub fn comm_r_last(&self)
        -><Tree::Hasher as Hasher>::Domain {self.comm_r_last_proof.root()}

    pub fn
        comm_c(&self)
        -><Tree::Hasher as Hasher>::Domain {self.replica_column_proofs.c_x.root()}

    /// Verify the full proof.
    pub fn
        verify(&self, pub_params
               : &PublicParams<Tree>, pub_inputs
               : &PublicInputs << Tree::Hasher as Hasher > ::Domain, <G as Hasher>::Domain >, challenge
               : usize, graph
               : &StackedBucketGraph<Tree::Hasher>, )
        ->bool {
        let replica_id = &pub_inputs.replica_id;

        check !(challenge < graph.size());
        check !(pub_inputs.tau.is_some());

        // Verify initial data layer
        trace !("verify initial data layer");

        check !(self.comm_d_proofs.proves_challenge(challenge));

        if let
            Some(ref tau) = pub_inputs.tau {
                check_eq !(&self.comm_d_proofs.root(), &tau.comm_d);
            }
        else {
            return false;
        }

        // Verify replica column openings
        trace !("verify replica column openings");
        let mut parents = vec ![0; graph.degree()];
        graph.parents(challenge, &mut parents).unwrap();    // FIXME: error handling
        check !(self.replica_column_proofs.verify(challenge, &parents));

        check !(self.verify_final_replica_layer(challenge));

        check !(self.verify_labels(replica_id, &pub_params.layer_challenges));

        trace !("verify encoding");

        check !(
            self.encoding_proof.verify::<G>(replica_id, &self.comm_r_last_proof.leaf(), &self.comm_d_proofs.leaf()));

        true
    }

    /// Verify all labels.
    fn verify_labels(&self, replica_id
                     : &<Tree::Hasher as Hasher>::Domain, layer_challenges
                     : &LayerChallenges, )
        ->bool {
        // Verify Labels Layer 1..layers
for
    layer in 1.. = layer_challenges.layers() {
        trace !("verify labeling (layer: {})", layer, );

        check !(self.labeling_proofs.get(layer - 1).is_some());
        let labeling_proof = &self.labeling_proofs.get(layer - 1).unwrap();
        let labeled_node = self.replica_column_proofs.c_x.get_node_at_layer(layer).unwrap();    // FIXME: error handling
        check !(labeling_proof.verify(replica_id, labeled_node));
    }

true
    }

    /// Verify final replica layer openings
    fn verify_final_replica_layer(&self, challenge : usize)->bool {
        trace !("verify final replica layer openings");
        check !(self.comm_r_last_proof.proves_challenge(challenge));

        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaColumnProof<Proof: MerkleProofTrait> {
#[serde(bound(
    serialize = "ColumnProof<Proof>: Serialize",
    deserialize = "ColumnProof<Proof>: Deserialize<'de>"
))]
pub c_x: ColumnProof<Proof>,
#[serde(bound(
    serialize = "ColumnProof<Proof>: Serialize",
    deserialize = "ColumnProof<Proof>: Deserialize<'de>"
))]
pub drg_parents: Vec<ColumnProof<Proof>>,
#[serde(bound(
    serialize = "ColumnProof<Proof>: Serialize",
    deserialize = "ColumnProof<Proof>: Deserialize<'de>"
))]
pub exp_parents: Vec<ColumnProof<Proof>>,
}

impl<Proof: MerkleProofTrait> ReplicaColumnProof<Proof> {
    pub fn verify(&self, challenge : usize, parents : &[u32])->bool {
        let expected_comm_c = self.c_x.root();

        trace !("  verify c_x");
        check !(self.c_x.verify(challenge as u32, &expected_comm_c));

        trace !("  verify drg_parents");
        for (proof, parent)
            in self.drg_parents.iter().zip(parents.iter()) {
                check !(proof.verify(*parent, &expected_comm_c));
            }

        trace !("  verify exp_parents");
        for (proof, parent)
            in self.exp_parents.iter().zip(parents.iter().skip(self.drg_parents.len())) {
                check !(proof.verify(*parent, &expected_comm_c));
            }

        true
    }
}

pub type TransformedLayers<Tree, G> =
    (Tau<<<Tree as MerkleTreeTrait>::Hasher as Hasher>::Domain, <G as Hasher>::Domain>,
     PersistentAux<<<Tree as MerkleTreeTrait>::Hasher as Hasher>::Domain>, TemporaryAux<Tree, G>, );

/// Tau for a single parition.
#[derive(Debug, Clone, PartialEq, Eq)]
        pub struct Tau<D : Domain, E : Domain> {
            pub comm_d : E, pub comm_r : D,
        }

impl<Tree: MerkleTreeTrait, G: Hasher> Clone for TemporaryAux<Tree, G> {
            fn clone(&self)->Self {
                Self {
                labels:
                    self.labels.clone(), tree_d_config : self.tree_d_config.clone(),
                        tree_r_last_config : self.tree_r_last_config.clone(),
                        tree_c_config : self.tree_c_config.clone(), _g : Default::default(),
                }
            }
        }

        impl<Tree : MerkleTreeTrait, G : Hasher>
            TemporaryAux<Tree, G> {
            pub fn set_cache_path<P : AsRef<Path>>(&mut self, cache_path : P) {
                let cp = cache_path.as_ref().to_path_buf();
for
    label in self.labels.labels.iter_mut() {
        label.path = cp.clone();
    }
self.tree_d_config.path = cp.clone();
self.tree_r_last_config.path = cp.clone();
self.tree_c_config.path = cp;
            }

pub fn labels_for_layer(
    &self,
    layer: usize,
) -> Result<DiskStore<<Tree::Hasher as Hasher>::Domain>> {
self.labels.labels_for_layer(layer)
}

pub fn domain_node_at_layer(
    &self,
    layer: usize,
node_index: u32,
) -> Result<<Tree::Hasher as Hasher>::Domain> {
Ok(self.labels_for_layer(layer)?.read_at(node_index as usize)?)
}

pub fn column(&self, column_index: u32) -> Result<Column<Tree::Hasher>> {
self.labels.column(column_index)
}

// 'clear_temp' will discard all persisted merkle and layer data
// that is no longer required.
pub fn clear_temp(t_aux: TemporaryAux<Tree, G>) -> Result<()> {
    let cached = | config : &StoreConfig | {Path::new (&StoreConfig::data_path(&config.path, &config.id)).exists()};

    let delete_tree_c_store = | config : &StoreConfig, tree_c_size : usize |->Result<()> {
        let tree_c_store = DiskStore:: << Tree::Hasher as Hasher > ::Domain >
                           ::new_from_disk(tree_c_size, Tree::Arity::to_usize(), &config, ).context("tree_c") ?
            ;
        // Note: from_data_store requires the base tree leaf count
let tree_c = DiskTree::<
             Tree::Hasher,
    Tree::Arity,
    Tree::SubTreeArity,
    Tree::TopTreeArity,
>::from_data_store(
    tree_c_store,
    get_merkle_tree_leafs(tree_c_size, Tree::Arity::to_usize())?,
)
.context("tree_c")?;
tree_c.delete(config.clone()).context("tree_c") ? ;

Ok(())
    };

    if cached (&t_aux.tree_d_config) {
        let tree_d_size = t_aux.tree_d_config.size.context("tree_d config has no size") ? ;
        let tree_d_store
            : DiskStore<G::Domain> =
                  DiskStore::new_from_disk(tree_d_size, BINARY_ARITY, &t_aux.tree_d_config).context("tree_d") ?
            ;
        // Note: from_data_store requires the base tree leaf count
let tree_d = BinaryMerkleTree::<G>::from_data_store(
    tree_d_store,
    get_merkle_tree_leafs(tree_d_size, BINARY_ARITY)?,
)
    .context("tree_d")?;

tree_d.delete(t_aux.tree_d_config).context("tree_d") ? ;
trace !("tree d deleted");
    }

    let tree_count = get_base_tree_count::<Tree>();
    let tree_c_size = t_aux.tree_c_config.size.context("tree_c config has no size") ? ;
    let configs = split_config(t_aux.tree_c_config.clone(), tree_count) ? ;

    if cached (&t_aux.tree_c_config) {
        delete_tree_c_store(&t_aux.tree_c_config, tree_c_size) ? ;
    } else if cached (&configs[0]) {
    for
        config in &configs {
            // Trees with sub-trees cannot be instantiated and deleted via the existing tree interface since
            // knowledge of how the base trees are split exists outside of merkle light.  For now, we manually
            // remove each on disk tree file since we know where they are here.
            let tree_c_path = StoreConfig::data_path(&config.path, &config.id);
            remove_file(&tree_c_path).with_context(|| format !("Failed to delete {:?}", &tree_c_path)) ?
        }
    }
    trace !("tree c deleted");

for
    i in 0..t_aux.labels.labels.len() {
        let cur_config = t_aux.labels.labels[i].clone();
        if cached (&cur_config) {
            DiskStore:: << Tree::Hasher as Hasher > ::Domain >
                ::delete (cur_config).with_context(|| format !("labels {}", i)) ?
                ;
            trace !("layer {} deleted", i);
        }
    }

Ok(())
}
        }

#[derive(Debug)]
        pub struct TemporaryAuxCache<Tree : MerkleTreeTrait, G : Hasher> {
            /// The encoded nodes for 1..layers.
            pub labels : LabelsCache<Tree>,
            pub tree_d : BinaryMerkleTree<G>,

            // Notably this is a LevelCacheTree instead of a full merkle.
            pub tree_r_last : LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,

            // Store the 'rows_to_discard' value from the tree_r_last
            // StoreConfig for later use (i.e. proof generation).
            pub tree_r_last_config_rows_to_discard : usize,

            pub tree_c : DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
            pub t_aux : TemporaryAux<Tree, G>,
            pub replica_path : PathBuf,
        }

        impl<Tree : MerkleTreeTrait, G : Hasher>
            TemporaryAuxCache<Tree, G> {
            pub fn new (t_aux : &TemporaryAux<Tree, G>, replica_path : PathBuf)->Result<Self> {
                // tree_d_size stored in the config is the base tree size
                let tree_d_size = t_aux.tree_d_config.size.unwrap();
                let tree_d_leafs = get_merkle_tree_leafs(tree_d_size, BINARY_ARITY) ? ;
                trace !("Instantiating tree d with size {} and leafs {}", tree_d_size, tree_d_leafs, );
                let tree_d_store : DiskStore<G::Domain> =
                                       DiskStore::new_from_disk(tree_d_size, BINARY_ARITY, &t_aux.tree_d_config)
                                           .context("tree_d_store") ?
                    ;
                let tree_d = BinaryMerkleTree::<G>::from_data_store(tree_d_store, tree_d_leafs).context("tree_d") ? ;

                let tree_count = get_base_tree_count::<Tree>();
                let configs = split_config(t_aux.tree_c_config.clone(), tree_count) ? ;

                // tree_c_size stored in the config is the base tree size
                let tree_c_size = t_aux.tree_c_config.size.unwrap();
                trace !("Instantiating tree c [count {}] with size {} and arity {}", tree_count, tree_c_size,
                        Tree::Arity::to_usize(), );
                let tree_c =
                    create_disk_tree::<DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>, >(
                        tree_c_size, &configs) ?
                    ;

                // tree_r_last_size stored in the config is the base tree size
                let tree_r_last_size = t_aux.tree_r_last_config.size.unwrap();
                let tree_r_last_config_rows_to_discard = t_aux.tree_r_last_config.rows_to_discard;
let (configs, replica_config) = split_config_and_replica(
    t_aux.tree_r_last_config.clone(),
    replica_path.clone(),
    get_merkle_tree_leafs(tree_r_last_size, Tree::Arity::to_usize())?,
tree_count,
)?;

trace !("Instantiating tree r last [count {}] with size {} and arity {}, {}, {}", tree_count, tree_r_last_size,
        Tree::Arity::to_usize(), Tree::SubTreeArity::to_usize(), Tree::TopTreeArity::to_usize(), );
let tree_r_last = create_lc_tree::<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>, >(
    tree_r_last_size, &configs, &replica_config) ?
    ;

Ok(TemporaryAuxCache {
    labels : LabelsCache::new (&t_aux.labels).context("labels_cache") ?
    ,
    tree_d,
    tree_r_last,
    tree_r_last_config_rows_to_discard,
    tree_c,
    replica_path,
    t_aux :
    t_aux.clone(),
})
            }

pub fn labels_for_layer(&self, layer: usize) -> &DiskStore<<Tree::Hasher as Hasher>::Domain> {
self.labels.labels_for_layer(layer)
}

pub fn domain_node_at_layer(
    &self,
    layer: usize,
node_index: u32,
) -> Result<<Tree::Hasher as Hasher>::Domain> {
Ok(self.labels_for_layer(layer).read_at(node_index as usize)?)
}

pub fn column(&self, column_index: u32) -> Result<Column<Tree::Hasher>> {
    self.labels.column(column_index)
}
        }

        type VerifyCallback = fn(&StoreConfig, usize, usize)->Result<()>;

impl<Tree: MerkleTreeTrait> Clone for Labels<Tree> {
    fn clone(&self)->Self {
        Self {
        labels:
            self.labels.clone(), _h : Default::default(),
        }
    }
}

impl<Tree : MerkleTreeTrait> Labels<Tree> {
    pub fn new (labels : Vec<StoreConfig>)->Self {
        Labels {
            labels, _h : PhantomData,
        }
    }

    pub fn len(&self)
        ->usize {self.labels.len()}

    pub fn
        is_empty(&self)
        ->bool {self.labels.is_empty()}

    pub fn
        verify_stores(&self, callback
                      : VerifyCallback, cache_dir
                      : &PathBuf)
        ->Result<()> {
        let updated_path_labels = self.labels.clone();
        let required_configs = get_base_tree_count::<Tree>();
for
    mut label in updated_path_labels {
        label.path = cache_dir.to_path_buf();
        callback(&label, BINARY_ARITY, required_configs) ? ;
    }

Ok(())
    }

    pub fn labels_for_layer(&self, layer : usize, )->Result<DiskStore << Tree::Hasher as Hasher>::Domain >> {
        assert !(layer != 0, "Layer cannot be 0");
        assert !(layer <= self.layers(), "Layer {} is not available (only {} layers available)", layer, self.layers());

        let row_index = layer - 1;
        let config = self.labels[row_index].clone();
        assert !(config.size.is_some());

        DiskStore::new_from_disk(config.size.unwrap(), Tree::Arity::to_usize(), &config)
    }

    /// Returns label for the last layer.
    pub fn labels_for_last_layer(&self)->Result<DiskStore << Tree::Hasher as Hasher>::Domain >>
        {self.labels_for_layer(self.labels.len() - 1)}

        /// How many layers are available.
        fn
        layers(&self)
            ->usize {self.labels.len()}

        /// Build the column for the given node.
        pub fn
        column(&self, node
               : u32)
            ->Result<Column<Tree::Hasher>> {
        let rows =
            self.labels.iter()
                .map(| label |
                     {
                         assert !(label.size.is_some());
                         let store = DiskStore::new_from_disk(label.size.unwrap(), Tree::Arity::to_usize(), &label) ? ;
                         store.read_at(node as usize)
                     })
                .collect::<Result<_>>() ?
            ;

        Column::new (node, rows)
    }

    /// Update all configs to the new passed in root cache path.
    pub fn update_root<P : AsRef<Path>>(&mut self, root : P) {
for
    config in &mut self.labels {
        config.path = root.as_ref().into();
    }
    }
}

#[derive(Debug)]
pub struct LabelsCache<Tree : MerkleTreeTrait> {
    pub labels : Vec<DiskStore << Tree::Hasher as Hasher>::Domain >>
    ,
}

impl<Tree : MerkleTreeTrait>
    LabelsCache<Tree> {
    pub fn new (labels : &Labels<Tree>)->Result<Self> {
        let mut disk_store_labels : Vec<DiskStore << Tree::Hasher as Hasher>::Domain >>
            = Vec::with_capacity(labels.len());
for
    i in 0..labels.len() {
disk_store_labels.push(labels.labels_for_layer(i + 1)?);
    }

Ok(LabelsCache {
    labels : disk_store_labels,
})
    }

    pub fn len(&self)
                ->usize {self.labels.len()}

            pub fn is_empty(&self)
                ->bool {self.labels.is_empty()}

            pub fn labels_for_layer(&self, layer
                                    : usize)
                ->&DiskStore
            << Tree::Hasher as Hasher
        > ::Domain > {
        assert !(layer != 0, "Layer cannot be 0");
        assert !(layer <= self.layers(), "Layer {} is not available (only {} layers available)", layer, self.layers());

        let row_index = layer - 1;
        &self.labels[row_index]
    }

    /// Returns the labels on the last layer.
    pub fn labels_for_last_layer(&self)->Result<&DiskStore << Tree::Hasher as Hasher>::Domain >>
        {Ok(&self.labels[self.labels.len() - 1])}

        /// How many layers are available.
        fn layers(&self)
            ->usize {self.labels.len()}

        /// Build the column for the given node.
        pub fn column(&self, node
                      : u32)
            ->Result<Column<Tree::Hasher>> {
        let rows = self.labels.iter().map(| labels | labels.read_at(node as usize)).collect::<Result<_>>() ? ;

        Column::new (node, rows)
    }
}

pub fn get_node<H : Hasher>(data
                            : &[u8], index
                            : usize)
    ->Result<H::Domain> {H::Domain::try_from_bytes(data_at_node(data, index).expect("invalid node math"))}

/// Generate the replica id as expected for Stacked DRG.
pub fn generate_replica_id<H : Hasher, T : AsRef<[u8]>>(prover_id
                                                        : &[u8; 32], sector_id
                                                        : u64, ticket
                                                        : &[u8; 32], comm_d
                                                        : T, porep_seed
                                                        : &[u8; 32], ) -> H::Domain {
    use sha2:: {Digest, Sha256};

    let hash = Sha256::new ()
                   .chain(prover_id)
                   .chain(&sector_id.to_be_bytes()[..])
                   .chain(ticket)
                   .chain(AsRef::<[u8]>::as_ref(&comm_d))
                   .chain(porep_seed)
                   .result();

    bytes_into_fr_repr_safe(hash.as_ref()).into()
}
    }    // namespace filecoin
}    // namespace nil

#endif
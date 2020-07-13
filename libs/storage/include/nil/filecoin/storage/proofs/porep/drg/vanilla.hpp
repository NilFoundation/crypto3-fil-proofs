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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_DRG_VANILLA_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_DRG_VANILLA_HPP

#include <nil/filecoin/storage/proofs/core/parameter_cache.hpp>
#include <nil/filecoin/storage/proofs/core/merkle/proof.hpp>

#include <nil/filecoin/storage/proofs/porep/porep.hpp>
#include <nil/filecoin/storage/proofs/core/utilities.hpp>

namespace nil {
    namespace filecoin {
        namespace porep {
            namespace drg {
                template<typename T>
                struct Tau {
                    T comm_r;
                    T comm_d;
                };

                template<typename Hash, template<typename> class BinaryMerkleTree,
                         template<typename> class BinaryLCMerkleTree>
                struct ProverAux {
                    BinaryMerkleTree<Hash> tree_d;
                    BinaryLCMerkleTree<Hash> tree_r;
                };

                template<typename Domain>
                struct PublicInputs {
                    Domain replica_id;
                    std::vector<std::size_t> challenges;
                    Tau<Domain> tau;
                };

                template<typename Hash, template<typename> class BinaryMerkleTree,
                         template<typename> class BinaryLCMerkleTree>
                struct PrivateInputs {
                    BinaryMerkleTree<Hash> &tree_d;
                    BinaryLCMerkleTree<Hash> &tree_r;
                    std::size_t tree_r_config_rows_to_discard;
                };

                struct DrgParams {
                    // Number of nodes
                    std::size_t nodes;
                    // Base degree of DRG
                    std::size_t degree;
                    std::size_t expansion_degree;
                    std::array<std::uint8_t, 32> porep_id;
                };

                struct SetupParams {
                    DrgParams drg;
                    bool priv;
                    std::size_t challenges_count;
                };

                template<typename Hash, template<typename> class Graph>
                struct PublicParams : public parameter_set_metadata {
                    virtual std::string identifier() const override {
                        return "drgporep::PublicParams{{graph: {}}}" + graph.identifier();
                    }
                    virtual size_t sector_size() const override {
                        return graph.sector_size();
                    }

                    Graph<Hash> graph;
                    bool priv;
                    std::size_t challenges_count;
                };

                template<typename Hash, typename PoseidonArity, template<typename, typename> class MerkleProof>
                struct DataProof {
                    /// proves_challenge returns true if this self.proof corresponds to challenge.
                    /// This is useful for verifying that a supplied proof is actually relevant to a given
                    /// challenge.
                    bool proves_challenge(std::size_t challenge) {
                        return proof.proves_challenge(challenge);
                    }

                    MerkleProof<Hash, PoseidonArity> proof;
                    typename Hash::digest_type data;
                };

                template<typename Hash>
                using ReplicaParents = std::vector<std::tuple<std::uint32_t, DataProof<Hash, typenum::U2>>>;

                template<typename Hash>
                struct Proof {
                    Proof(std::size_t height, std::size_t degree, std::size_t challenges) :
                        replica_nodes({height}, challenges), replica_parents({{{0, height}, degree}, challenges}),
                        nodes({{height}, challenges}) {
                    }

                    Proof(const std::vector<DataProof<Hash, typenum::U2>> &replica_nodes,
                          const std::vector<ReplicaParents<Hash>> &replica_parents,
                          const std::vector<DataProof<Hash, typenum::U2>> &nodes) :
                        replica_nodes(replica_nodes),
                        replica_parents(replica_parents), nodes(nodes), data_root(nodes[0].proof.root()),
                        replica_root(replica_nodes[0].proof.root()) {
                    }

                    typename Hash::digest_type data_root;
                    typename Hash::digest_type replica_root;
                    std::vector<DataProof<Hash, typenum::U2>> replica_nodes;
                    std::vector<ReplicaParents<Hash>> replica_parents;
                    std::vector<DataProof<Hash, typenum::U2>> nodes;
                };

                template<typename Hash, template<typename> class Graph>
                struct DrgPoRep
                    : public PoRep<PublicParams<Hash, Graph>, SetupParams, PublicInputs<typename Hash::digest_type>,
                                   PrivateInputs<Hash, Graph, Graph>, Proof<Hash>, no_requirements, Hash, Hash,
                                   Tau<typename Hash::digest_type>, ProverAux<Hash, Graph, Graph>> {
                    typedef PoRep<PublicParams<Hash, Graph>, SetupParams, PublicInputs<typename Hash::digest_type>,
                                  PrivateInputs<Hash, Graph, Graph>, Proof<Hash>, no_requirements, Hash, Hash,
                                  Tau<typename Hash::digest_type>, ProverAux<Hash, Graph, Graph>>
                        policy_type;

                    typedef typename policy_type::public_params_type public_params_type;
                    typedef typename policy_type::setup_params setup_params_type;
                    typedef typename policy_type::public_inputs public_inputs_type;
                    typedef typename policy_type::private_inputs private_inputs_type;
                    typedef typename policy_type::proof_type proof_type;
                    typedef typename policy_type::requirements_type requirements_type;

                    typedef typename policy_type::tau_type tau_type;
                    typedef typename policy_type::aux_type aux_type;

                    virtual public_params_type setup(const setup_params_type &p) override {
                        return {{p.drg.nodes, p.drg.degree, p.drg.expansion_degree, p.drg.porep_id},
                                p.priv,
                                p.challenges_count};
                    }

                    virtual proof_type prove(const public_params_type &params,
                                             const public_inputs_type &inputs,
                                             const private_inputs_type &pinputs) override {
                        std::size_t len = inputs.challenges.size();
                        assert(len <= params.challenges_count);

                        std::vector<typename Hash::digest_type> replica_nodes(len), replica_parents(len);
                        std::vector<DataProof<Hash, typenum::U2>> data_nodes(len);

                        for (int i = 0; i < len; i++) {
                            std::size_t challenge = inputs.challenges[i] % params.graph.size();
                            assert(("cannot prove the first node", challenge != 0));

                            let tree_d = &priv_inputs.tree_d;
                            let tree_r = &priv_inputs.tree_r;
                            let tree_r_config_rows_to_discard = priv_inputs.tree_r_config_rows_to_discard;

                            let data = tree_r.read_at(challenge) ? ;
                            let tree_proof = tree_r.gen_cached_proof(challenge, Some(tree_r_config_rows_to_discard)) ? ;
                            replica_nodes.emplace_back(tree_proof, data);

                            let mut parents = vec ![0; pub_params.graph.degree()];
                            pub_params.graph.parents(challenge, &mut parents) ? ;
                            let mut replica_parentsi = Vec::with_capacity(parents.len());

                            for (p : parents) {
                                replica_parentsi.push_back((*p, {
                                    let proof =
                                        tree_r.gen_cached_proof(*p as usize, Some(tree_r_config_rows_to_discard));
                                    DataProof {
                                        proof, data : tree_r.read_at(*p as usize)
                                    }
                                }));
                            }

                            replica_parents.push(replica_parentsi);

                            let node_proof = tree_d.gen_proof(challenge);

                            {
                                // TODO: use this again, I can't make lifetimes work though atm and I do not know
                                // why let extracted = Self::extract(
                                //     pub_params,
                                //     &pub_inputs.replica_id.into_bytes(),
                                //     &replica,
                                //     challenge,
                                // )?;

                                    let extracted = decode_domain_block::<H>(
                                        &pub_inputs.replica_id.context("missing replica_id")?,
                                            tree_r,
                                            challenge,
                                            tree_r.read_at(challenge)?,
                                            &parents,
                                    );
                                    data_nodes.emplace_back(extracted, node_proof);
                            }
                        }

                        return {replica_nodes, replica_parents, data_nodes};
                    }

                    virtual bool verify(const public_params_type &pub_params,
                                        const public_inputs_type &pub_inputs,
                                        const proof_type &pr) override {
                        let mut hasher = Sha256::new ();

                        for (int i = 0; i < pub_inputs.challenges.size(); i++) {
                            // This was verify_proof_meta.
                            if (pub_inputs.challenges[i] >= pub_params.graph.size()) {
                                return false;
                            }

                            if (!(proof.nodes[i].proves_challenge(pub_inputs.challenges[i]))) {
                                return false;
                            }

                            if (!(proof.replica_nodes[i].proves_challenge(pub_inputs.challenges[i]))) {
                                return false;
                            }

                            let mut expected_parents = vec ![0; pub_params.graph.degree()];
                            pub_params.graph.parents(pub_inputs.challenges[i], &mut expected_parents);
                            if (proof.replica_parents[i].size() != expected_parents.size()) {
                                println !(
                                    "proof parents were not the same length as in public parameters: "
                                    "{} != {}",
                                    proof.replica_parents[i].size(),
                                    expected_parents.size());
                                return false;
                            }

                            let parents_as_expected = proof.replica_parents[i]
                                                          .iter()
                                                          .zip(&expected_parents)
                                                          .all(| (actual, expected) | actual .0 == *expected);

                            if (!parents_as_expected) {
                                println !("proof parents were not those provided in public parameters");
                                return false;
                            }
                        }

                        let challenge = pub_inputs.challenges[i] % pub_params.graph.size();
                        ensure !(challenge != 0, "cannot prove the first node");

                        if (!proof.replica_nodes[i].proof.validate(challenge)) {
                            return false;
                        }

                        for ((parent_node, p) : proof.replica_parents[i]) {
                            if (!p.proof.validate(*parent_node)) {
                                return false;
                            }
                        }

                        let prover_bytes = pub_inputs.replica_id.context("missing replica_id");
                        hasher.input(AsRef::<[u8]>::as_ref(&prover_bytes));

                        for (p : proof.replica_parents[i].iter()) {
                            hasher.input(AsRef::<[u8]>::as_ref(&p .1.data));
                        }

                        let hash = hasher.result_reset();
                        auto key = bytes_into_fr_repr_safe(hash.as_ref()).into();

                        let unsealed = encode::decode(key, proof.replica_nodes[i].data);

                        if (unsealed != proof.nodes[i].data) {
                            return false;
                        }

                        if (!proof.nodes[i].proof.validate_data(unsealed)) {
                            println !("invalid data for merkle path {:?}", unsealed);
                            return false;
                        }

                        return true;
                    }    // namespace vanilla

                    virtual std::tuple<Tau<Hash::digest_type>, ProverAux<Hash, Graph, Graph>>
                        replicate(const public_params_type &pub_params,
                                  const Hash::digest_type &replica_id,
                                  const Data &data,
                                  const StoreConfig &config,
                                  const boost::filesystem::path &replica_path,
                                  const BinaryMerkleTree<G> &data_tree = BinaryMerkleTree<G>()) override {
                        use storage_proofs_core::cache_key::CacheKey;

                        let tree_d = match data_tree {
                            Some(tree) = > tree, None = > create_base_merkle_tree<BinaryMerkleTree<Hash>>(
                                                              Some(config.clone()), pp.graph.size(), data.as_ref())};

                        let graph = &pp.graph;
                        // encode(&pp.graph, replica_id, data, None)?;
                        // Because a node always follows all of its parents in the data,
                        // the nodes are by definition already topologically sorted.
                        // Therefore, if we simply traverse the data in order, encoding each node in place,
                        // we can always get each parent's encodings with a simple lookup --
                        // since we will already have encoded the parent earlier in the traversal.

                        let mut parents = vec ![0; graph.degree()];
                        for (int node = 0; node < graph.size(); node++) {
                            graph.parents(node, &mut parents);
                            let key = graph.create_key(replica_id, node, &parents, data.as_ref(), None);
                            let start = data_at_node_offset(node);
                            let end = start + NODE_SIZE;

                            let node_data = <H as Hasher>::Domain::try_from_bytes(&data.as_ref()[start..end]);
                            let encoded = H::sloth_encode(key.as_ref(), &node_data);

                            encoded.write_bytes(&mut data.as_mut()[start..end]);
                        }

                        let replica_config = ReplicaConfig {
                            path : replica_path,
                            offsets : vec ![0],
                        };
                        let tree_r_last_config =
                            StoreConfig::from_config(&config, CacheKey::CommRLastTree.to_string(), None);
                        let tree_r = create_base_lcmerkle_tree::<H, <BinaryLCMerkleTree<H> as MerkleTreeTrait>::Arity>(
                            tree_r_last_config, pp.graph.size(), &data.as_ref(), &replica_config);

                        let comm_d = tree_d.root();
                        let comm_r = tree_r.root();

                        return std::make_tuple<tau_type, aux_type>({comm_d, comm_r}, {tree_d, tree_r});
                    }
                    virtual std::vector<uint8_t> extract_all(const public_params_type &pub_params,
                                                             const typename Hash::digest_type &replica_id,
                                                             const std::vector<uint8_t> &replica,
                                                             const StoreConfig &config) override {
                        return decode(pub_params.graph, replica_id, data, None);
                    }
                    virtual std::vector<uint8_t> extract(const public_params_type &pub_params,
                                                         const typename Hash::digest_type &replica_id,
                                                         const std::vector<uint8_t> &replica,
                                                         std::size_t node,
                                                         const StoreConfig &config) override {
                        return decode_block(pub_params.graph, replica_id, data, None, node).into_bytes();
                    }
                };

                template<typename Hash, template<typename> class Graph>
                typename Hash::digest_type
                    decode_block(Graph<Hash> &graph, typename Hash::digest_type &replica_id,
                                 const std::vector<std::uint8_t> &data, std::size_t v,
                                 const std::vector<std::uint8_t> &exp_parents_data = std::vector<std::uint8_t>()) {
                    std::vector<std::uint8_t> parents(graph.degree());
                    graph.parents(v, parents);
                    let key = graph.create_key(replica_id, v, &parents, &data, exp_parents_data) ? ;
                        let node_data = <H as Hasher>::Domain::try_from_bytes(&data_at_node(data, v)?)?;

                        return encode::decode(*key.as_ref(), node_data));
                }

                template<typename Hash, template<typename> class Graph>
                std::vector<std::uint8_t>
                    decode(Graph<Hash> &graph, typename Hash::digest_type &replica_id,
                           const std::vector<std::uint8_t> &data,
                           const std::vector<std::uint8_t> &exp_parents_data = std::vector<std::uint8_t>()) {
                    // TODO: proper error handling
                    let result = (0..graph.size())
                                     .into_par_iter()
                                     .flat_map(| i |
                                               {decode_block<Hash, Graph>(graph, replica_id, data, exp_parents_data, i)
                                                    .unwrap()
                                                    .into_bytes()})
                                     .collect();

                    return result;
                }

                /// Creates the encoding key from a `MerkleTree`.
                /// The algorithm for that is `Blake2s(id | encodedParentNode1 | encodedParentNode1 |
                /// ...)`. It is only public so that it can be used for benchmarking
                template<typename Hash, std::size_t BaseArity, template<typename, typename> class LCMerkleTree,
                         typename IdHash = crypto3::hashes::sha2<256>>
                typename Hash::digest_type create_key_from_tree(const typename Hash::digest_type &id, std::size_t node,
                                                                const std::vector<std::uint32_t> &parents,
                                                                const LCMerkleTree<Hash, Arity> &tree) {

                    using namespace nil::crypto3;

                    accumulator_set<IdHash> acc;
                    hash<IdHash>(id, acc);

                    // The hash is about the parents, hence skip if a node doesn't have any parents
                    if (node != parents[0]) {
                        std::array<std::uint8_t, NODE_SIZE> scratch;
                        scratch.fill(0);

                        for (std::uint32_t &parent : parents) {
                            tree.read_into(*parent, &mut scratch);
                            hasher.input(&scratch);
                        }
                    }

                    let hash = hasher.result();
                    return bytes_into_fr_repr_safe(hash.as_ref()).into();
                }

                template<typename Hash, template<typename> class BinaryLCMerkleTree>
                typename Hash::digest_type decode_domain_block(const typename Hash::digest_type &replica_id,
                                                               const BinaryLCMerkleTree<Hash> &tree, std::size_t node,
                                                               const typename Hash::digest_type &node_data,
                                                               const std::vector<std::uint32_t> &parents) {
                    return encode::decode(create_key_from_tree<Hash>(replica_id, node, parents, tree), node_data);
                }

                template<typename Hash>
                typename Hash::digest_type replica_id(const std::array<std::uint8_t, 32> &prover_id,
                                                      const std::array<std::uint8_t, 32> &sector_id) {
                    using namespace nil::crypto3;

                    accumulator_set<Hash> acc;
                    hash<Hash>(prover_id, acc);
                    hash<Hash>(sector_id, acc);

                    return accumulators::extract::hash<Hash>(acc);
                }
            }    // namespace drg
        }        // namespace porep
    }            // namespace filecoin
}    // namespace nil

#endif
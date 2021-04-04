//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nemo@nil.foundation>
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

#include <format>

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

                template<typename DigestType>
                struct PublicInputs {
                    typedef std::size_t challenge_type;

                    DigestType replica_id;
                    std::vector<challenge_type> challenges;
                    Tau<DigestType> tau;
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
                        return std::format("drgporep::PublicParams{{graph: %d}}", graph.identifier());
                    }

                    Graph<Hash> graph;
                    bool priv;
                    std::size_t challenges_count;
                };

                template<typename Hash, std::size_t PoseidonArity>
                struct DataProof {
                    /// proves_challenge returns true if this self.proof corresponds to challenge.
                    /// This is useful for verifying that a supplied proof is actually relevant to a given
                    /// challenge.
                    bool proves_challenge(std::size_t challenge) {
                        return proof.proves_challenge(challenge);
                    }

                    merkletree::MerkleProof<Hash, PoseidonArity> proof;
                    typename Hash::digest_type data;
                };

                template<typename Hash>
                using ReplicaParents = std::vector<std::tuple<std::uint32_t, DataProof<Hash, 2>>>;

                template<typename Hash>
                struct Proof {
                    Proof(std::size_t height, std::size_t degree, std::size_t challenges) :
                        replica_nodes({height}, challenges), replica_parents({{{0, height}, degree}, challenges}),
                        nodes({{height}, challenges}) {
                    }

                    Proof(const std::vector<DataProof<Hash, 2>> &replica_nodes,
                          const std::vector<ReplicaParents<Hash>> &replica_parents,
                          const std::vector<DataProof<Hash, 2>> &nodes) :
                        replica_nodes(replica_nodes),
                        replica_parents(replica_parents), nodes(nodes), data_root(nodes[0].proof.root()),
                        replica_root(replica_nodes[0].proof.root()) {
                    }

                    typename Hash::digest_type data_root;
                    typename Hash::digest_type replica_root;
                    std::vector<DataProof<Hash, 2>> replica_nodes;
                    std::vector<ReplicaParents<Hash>> replica_parents;
                    std::vector<DataProof<Hash, 2>> nodes;
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
                        std::vector<DataProof<Hash, 2>> data_nodes(len);

                        for (int i = 0; i < len; i++) {
                            std::size_t challenge = inputs.challenges[i] % params.graph.size();
                            BOOST_ASSERT_MSG(challenge != 0, "cannot prove the first node");

                            const auto tree_d = pinputs.tree_d;
                            const auto tree_r = pinputs.tree_r;
                            const auto tree_r_config_rows_to_discard = pinputs.tree_r_config_rows_to_discard;

                            const auto data = tree_r.read_at(challenge);
                            const auto tree_proof =
                                tree_r.gen_cached_proof(challenge, Some(tree_r_config_rows_to_discard));
                            replica_nodes.emplace_back(tree_proof, data);

                            std::vector<auto> parents(params.graph.degree(), 0);
                            params.graph.parents(challenge, parents);
                            std::vector<auto> replica_parentsi;
                            replica_parentsi.reserve(parents.size());

                            for (const auto &parent : parents) {
                                replica_parentsi.push_back((parent, {
                                    const auto proof = tree_r.gen_cached_proof(std::size_t(*parent),
                                                                               Some(tree_r_config_rows_to_discard));
                                    DataProof {
                                        proof, data : tree_r.read_at(std::size_t(*parent))
                                    }
                                }));
                            }

                            replica_parents.push(replica_parentsi);

                            const auto node_proof = generate_proof(tree_d, challenge);

                            const auto extracted =
                                decode_domain_block<Hash>(&pub_inputs.replica_id.context("missing replica_id"), tree_r,
                                                          challenge, tree_r.read_at(challenge), &parents, );
                            data_nodes.emplace_back(extracted, node_proof);
                        }

                        return {replica_nodes, replica_parents, data_nodes};
                    }

                    virtual bool verify(const public_params_type &pub_params,
                                        const public_inputs_type &pub_inputs,
                                        const proof_type &pr) override {
                        auto hasher = Sha256();

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

                            std::vector<auto> expected_parents(pub_params.graph.degree(), 0);
                            pub_params.graph.parents(pub_inputs.challenges[i], expected_parents);
                            if (proof.replica_parents[i].size() != expected_parents.size()) {
                                std::cout << std::format(
                                                 "proof parents were not the same length as in public parameters: "
                                                 "{} != {}",
                                                 proof.replica_parents[i].size(),
                                                 expected_parents.size())
                                          << std::endl;
                                return false;
                            }

                            bool parents_as_expected = false;
                            for (int i = 0; i < proof.replica_parents.size() && i < expected_parents.size(); i++) {
                                parents_as_expected = (std::get<0>(proof.replica_parents[i]) == expected_parents[i]);
                            }

                            if (!parents_as_expected) {
                                std::cout << std::format("proof parents were not those provided in public parameters")
                                          << std::endl;
                                return false;
                            }
                        }

                        const auto challenge = pub_inputs.challenges[i] % pub_params.graph.size();
                        BOOST_ASSERT_MSG(challenge != 0, "cannot prove the first node");

                        if (!proof.replica_nodes[i].proof.validate(challenge)) {
                            return false;
                        }

                        for (const auto &iter : proof.replica_parents[i]) {
                            if (!std::get<1>(iter).proof.validate(std::get<0>(iter)) {
                                return false;
                            }
                        }

                        const auto prover_bytes = pub_inputs.replica_id.context("missing replica_id");
                        hasher.input(prover_bytes);

                        for (const auto &p : proof.replica_parents[i]) {
                            hasher.input(std::get<1>(p).data));
                        }

                        const auto hash = hasher.result_reset();
                        const auto key = bytes_into_fr_repr_safe(hash).into();

                        const auto unsealed = encode::decode(key, proof.replica_nodes[i].data);

                        if (unsealed != proof.nodes[i].data) {
                            return false;
                        }

                        if (!proof.nodes[i].proof.validate_data(unsealed)) {
                            std::cout << std::format("invalid data for merkle path {:?}", unsealed) << std::endl;
                            return false;
                        }

                        return true;
                    }

                    virtual std::tuple<Tau<Hash::digest_type>, ProverAux<Hash, Graph, Graph>>
                        replicate(const public_params_type &pub_params,
                                  const typename Hash::digest_type &replica_id,
                                  const Data &data,
                                  const StoreConfig &config,
                                  const boost::filesystem::path &replica_path,
                                  const BinaryMerkleTree<G> &data_tree = BinaryMerkleTree<G>()) override {
                        using storage_proofs_core::cache_key::CacheKey;

                        auto tree_d;
                        switch (data_tree) {
                            case Some(tree):
                                tree_d = tree;
                                break;
                            case None:
                                tree_d = create_base_merkle_tree<BinaryMerkleTree<Hash>>(Some(config.clone()),
                                                                                         pp.graph.size(), data);
                        };

                        const auto graph = &pp.graph;
                        // encode(&pp.graph, replica_id, data, None)?;
                        // Because a node always follows all of its parents in the data,
                        // the nodes are by definition already topologically sorted.
                        // Therefore, if we simply traverse the data in order, encoding each node in place,
                        // we can always get each parent's encodings with a simple lookup --
                        // since we will already have encoded the parent earlier in the traversal.

                        std::vector<auto> parents(graph.degree(), 0);
                        for (int node = 0; node < graph.size(); node++) {
                            graph.parents(node, parents);
                            auto key = graph.create_key(replica_id, node, &parents, data, None);
                            auto start = data_at_node_offset(node);
                            auto end = start + NODE_SIZE;

                            auto node_data = H::digest_type::try_from_bytes(&data[start..end]);
                            auto encoded = H::sloth_encode(key, &node_data);

                            encoded.write_bytes(data[start..end]);
                        }

                        const auto replica_config = ReplicaConfig {
                            path : replica_path,
                            offsets : vec ![0],
                        };
                        const auto tree_r_last_config =
                            StoreConfig::from_config(&config, cache_key::CommRLastTree.to_string(), None);
                        const auto tree_r =
                            create_base_lcmerkle_tree::<H, <BinaryLCMerkleTree<H> as MerkleTreeTrait>::Arity>(
                                tree_r_last_config, pp.graph.size(), &data, &replica_config);

                        const auto comm_d = tree_d.root();
                        const auto comm_r = tree_r.root();

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
                    const auto key = graph.create_key(replica_id, v, &parents, &data, exp_parents_data);
                    const auto node_data = H::digest_type::try_from_bytes(&data_at_node(data, v));

                    return encode::decode(*key, node_data);
                }

                template<typename Hash, template<typename> class Graph>
                std::vector<std::uint8_t>
                    decode(Graph<Hash> &graph, typename Hash::digest_type &replica_id,
                           const std::vector<std::uint8_t> &data,
                           const std::vector<std::uint8_t> &exp_parents_data = std::vector<std::uint8_t>()) {
                    // TODO: proper error handling
                    std::vector<std::uint8_t> result;
                    for (int i = 0; i < graph.size(); i++) {
                        std::vector<uint8_t> decoded =
                            decode_block<Hash, Graph>(graph, replica_id, data, exp_parents_data, i);
                        result.insert(result.end(), decoded.begin(), decoded.end());
                    }
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

                        for (parents::iterator parent = parents.begin(); parent != parents.end(); ++parent) {
                            tree.read_into(*parent, scratch);
                            hash<Hash>(scratch, acc);
                        }
                    }

                    return accumulators::extract::hash<Hash>(acc);
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

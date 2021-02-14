//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020 Wukong Moscow Algorithm Lab
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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_DRG_COMPOUND_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_DRG_COMPOUND_HPP

#include <nil/filecoin/storage/proofs/core/parameter_cache.hpp>
#include <nil/filecoin/storage/proofs/core/por.hpp>
#include <nil/filecoin/storage/proofs/core/proof/compound_proof.hpp>

#include <nil/filecoin/storage/proofs/porep/drg/vanilla.hpp>
#include <nil/filecoin/storage/proofs/porep/drg/circuit.hpp>

namespace nil {
    namespace filecoin {
        namespace porep {
            namespace drg {
                template<typename Hash, typename Graph, template<typename> class Circuit>
                class drg_porep_compound
                    : public cacheable_parameters<Circuit<algebra::curves::bls12<381>>, parameter_set_metadata>,
                      public compound_proof<porep::drg::DrgPoRep<Hash, Graph>, DrgPoRepCircuit<Hash>> {
                    typedef compound_proof<porep::drg::DrgPoRep<Hash, Graph>, DrgPoRepCircuit<Hash>> policy_type;

                public:
                    typedef Hash hash_type;
                    typedef Graph graph_type;

                    typedef typename policy_type::public_inputs_type public_inputs_type;
                    typedef typename policy_type::public_params_type public_params_type;
                    typedef typename policy_type::private_inputs_type private_inputs_type;
                    typedef typename policy_type::setup_params_type setup_inputs_type;
                    typedef typename policy_type::requirements_type requirements_type;
                    typedef typename policy_type::proof_type proof_type;

                    virtual std::string cache_prefix() const override {
                        return "drg-proof-of-replication-" + typename Hash::name();
                    }

                    std::vector<Fr> generate_public_inputs(const public_inputs_type &pub_in,
                                                           const public_params_type &pub_params,
                                                           std::size_t k = std::size_t()) {
                        const auto replica_id = pub_in.replica_id.context("missing replica id");
                        std::vector<typename public_inputs_type::challenge_type> challenges = pub_in.challenges;

                        BOOST_ASSERT_MSG(pub_in.tau.is_none() == pub_params.priv, "Public input parameter tau must be unset");

                        if (pub_in.tau) {

                        }

                        const auto comm_r, comm_d;

                        switch (pub_in.tau) {
                            case None:
                                comm_r = None;
                                comm_d = None;
                                break;
                            case Some(tau):
                                comm_r = Some(tau.comm_r);
                                comm_d = Some(tau.comm_d);
                                break;
                        };

                        std::size_t leaves = pub_params.graph.size();

                        public_params por_pub_params = {leaves, pub_params.priv};

                        std::vector<Fr> input;
                        input.push_back(replica_id.into());

                        std::vector<typename Hash::digest_type> parents(pub_params.graph.degree());
                        for (challenges::iterator challenge = challenges.begin(); challenge != challenges.end(); ++challenge) {
                            std::vector<std::uint32_t> por_nodes = static_cast<std::uint32_t>(*challenge);
                            pub_params.graph.parents(*challenge, parents);
                            por_nodes.extend_from_slice(&parents);

                            for (por_nodes::iterator node = por_nodes.begin(); node != por_nodes.end(); ++node) {
                                public_inputs por_pub_inputs = {comm_r, *node};
                                const auto por_inputs = PoRCompound<BinaryMerkleTree<hash_type>>::generate_public_inputs(
                                    &por_pub_inputs, &por_pub_params, None);

                                input.extend(por_inputs);
                            }

                            public_inputs por_pub_inputs = {comm_d, *challenge};

                            const auto por_inputs = PoRCompound<BinaryMerkleTree<hash_type>>::generate_public_inputs(
                                por_pub_inputs, por_pub_params, None);
                            input.extend(por_inputs);
                        }
                        return input;
                    }

                    DrgPoRepCircuit<hash_type> circuit(const public_inputs_type &public_inputs,
                                                       const component_private_inputs &component_private_inputs,
                                                       const proof_type &proof, const public_params_type &public_params,
                                                       std::size_t _partition_k = std::size_t) {
                        std::size_t challenges = public_params.challenges_count;
                        std::size_t len = proof.nodes.size();

                        BOOST_ASSERT_MSG(len <= challenges, "too many challenges");
                        BOOST_ASSERT_MSG(proof.replica_parents.size() == len, "Number of replica parents must match");
                        BOOST_ASSERT_MSG(proof.replica_nodes.size() == len, "Number of replica nodes must match");

                        std::vector<_> replica_nodes
                            = proof.replica_nodes.iter().map(| node | Some(node.data.into())).collect();

                        std::vector<_> replica_nodes_paths
                            = proof.replica_nodes.iter().map(| node | node.proof.as_options()).collect();

                        bool is_private = public_params.priv;

                        const auto(data_root, replica_root) = if is_private {
                (
                    component_private_inputs.comm_d.context("is_private")?,
                        component_private_inputs.comm_r.context("is_private")?,
                )
                        }
                        else {(Root::Val(Some(proof.data_root.into())), Root::Val(Some(proof.replica_root.into())), )};

                        const auto replica_id = public_inputs.replica_id;

                        std::vector<_> replica_parents =
                                  proof.replica_parents.iter()
                                      .map(| parents |
                                           {parents.iter().map(| (_, parent) | Some(parent.data.into())).collect()})
                                      .collect();

                        std::vector<std::vector<_>> replica_parents_paths =
                                  proof.replica_parents.iter()
                                      .map(| parents |
                                           {
                                               std::vector<_> p = parents.iter()
                                                                    .map(| (_, parent) | parent.proof.as_options())
                                                                    .collect();
                                               p
                                           })
                                      .collect();

                        std::vector<_> data_nodes = proof.nodes.iter().map(| node | Some(node.data.into())).collect();

                        std::vector<_> data_nodes_paths =
                                                   proof.nodes.iter().map(| node | node.proof.as_options()).collect();

                        BOOST_ASSERT_MSG(public_inputs.tau.is_none() == public_params.priv, "inconsistent private state");

                        return {
                            replica_nodes,
                            replica_nodes_paths,
                            replica_root,
                            replica_parents,
                            replica_parents_paths,
                            data_nodes,
                            data_nodes_paths,
                            data_root,
                            replica_id : replica_id.map(Into::into),
                            public_params.priv
                        };
                    }

                    DrgPoRepCircuit<Hash> blank_circuit(const public_params_type &public_params) {
                        std::size_t depth = public_params.graph.merkle_tree_depth<2>();
                        std::size_t degree = public_params.graph.degree();
                        std::size_t arity = 2;

                        std::size_t challenges_count = public_params.challenges_count;

                        const std::vector<auto> replica_nodes (challenges_count, None);
                        const std::vector<std::vector<std::vector<auto>>> replica_nodes_paths =
                            vec ![vec ![(vec ![None; arity - 1], None); depth - 1]; challenges_count];

                        const auto replica_root = Root::Val(None);
                        const std::vector<std::vector<auto>> replica_parents (challenges_count, std::vector<auto>(degree, None));
                        const std::vector<std::vector<std::vector<std::vector<auto>>>> replica_parents_paths =
                            vec ![vec ![vec ![(vec ![None; arity - 1], None); depth - 1]; degree]; challenges_count];
                        const auto data_nodes = vec ![None; challenges_count];
                        const std::vector<std::vector<std::vector<auto>>> data_nodes_paths =
                            vec ![vec ![(vec ![None; arity - 1], None); depth - 1]; challenges_count];
                        const auto data_root = Root::Val(None);

                        return {
                            replica_nodes,
                            replica_nodes_paths,
                            replica_root,
                            replica_parents,
                            replica_parents_paths,
                            data_nodes,
                            data_nodes_paths,
                            data_root,
                            replica_id : None,
                            public_params.priv
                        };
                    }    // namespace filecoin
                };       // namespace filecoin
            }            // namespace drg
        }                // namespace porep
    }                    // namespace filecoin
}    // namespace nil

#endif

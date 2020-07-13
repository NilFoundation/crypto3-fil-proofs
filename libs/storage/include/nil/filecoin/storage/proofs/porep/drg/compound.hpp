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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_DRG_COMPOUND_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_DRG_COMPOUND_HPP

#include <nil/filecoin/storage/proofs/core/parameter_cache.hpp>
#include <nil/filecoin/storage/proofs/core/proof/compound_proof.hpp>

#include <nil/filecoin/storage/proofs/porep/drg/vanilla.hpp>
#include <nil/filecoin/storage/proofs/porep/drg/circuit.hpp>

namespace nil {
    namespace filecoin {
        namespace porep {
            namespace drg {
                template<typename Hash, typename Graph, template<typename> class Circuit, typename Bls12>
                class drg_porep_compound
                    : public cacheable_parameters<Circuit<Bls12>, parameter_set_metadata>,
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
                        let replica_id = pub_in.replica_id.context("missing replica id") ? ;
                        let challenges = &pub_in.challenges;

                        assert(("Public input parameter tau must be unset", pub_in.tau.is_none() == pub_params.priv));

                        let(comm_r, comm_d) = match pub_in.tau {
                            None = > (None, None),
                            Some(tau) = > (Some(tau.comm_r), Some(tau.comm_d)),
                        };

                        std::size_t leaves = pub_params.graph.size();

                        por::PublicParams por_pub_params {leaves, pub_params.priv};

                        std::vector<Fr> input;
                        input.push_back(replica_id.into());

                        std::vector<typename Hash::digest_type> parents(pub_params.graph.degree());
                        for (challenge : challenges) {
                            let mut por_nodes = vec ![*challenge as u32];
                            pub_params.graph.parents(*challenge, &mut parents) ? ;
                            por_nodes.extend_from_slice(&parents);

                            for (node : por_nodes) {
                                let por_pub_inputs = por::PublicInputs {
                                    commitment : comm_r,
                                    challenge : node as usize,
                                };
                                let por_inputs = PoRCompound::<BinaryMerkleTree<hash_type>>::generate_public_inputs(
                                    &por_pub_inputs, &por_pub_params, None);

                                input.extend(por_inputs);
                            }

                            let por_pub_inputs = por::PublicInputs {
                                commitment : comm_d,
                                challenge : *challenge,
                            };

                            let por_inputs = PoRCompound::<BinaryMerkleTree<hash_type>>::generate_public_inputs(
                                &por_pub_inputs, &por_pub_params, None);
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

                        assert(("too many challenges", len <= challenges));
                        assert(("Number of replica parents must match", proof.replica_parents.size() == len));
                        assert(("Number of replica nodes must match", proof.replica_nodes.size() == len));

                        let replica_nodes
                            : Vec<_> = proof.replica_nodes.iter().map(| node | Some(node.data.into())).collect();

                        let replica_nodes_paths
                            : Vec<_> = proof.replica_nodes.iter().map(| node | node.proof.as_options()).collect();

                        let is_private = public_params.private;

                        let(data_root, replica_root) = if is_private {
                (
                    component_private_inputs.comm_d.context("is_private")?,
                        component_private_inputs.comm_r.context("is_private")?,
                )
                        }
                        else {(Root::Val(Some(proof.data_root.into())), Root::Val(Some(proof.replica_root.into())), )};

                        let replica_id = public_inputs.replica_id;

                        let replica_parents
                            : Vec<_> =
                                  proof.replica_parents.iter()
                                      .map(| parents |
                                           {parents.iter().map(| (_, parent) | Some(parent.data.into())).collect()})
                                      .collect();

                        let replica_parents_paths
                            : Vec<Vec<_>> =
                                  proof.replica_parents.iter()
                                      .map(| parents |
                                           {
                                               let p : Vec<_> = parents.iter()
                                                                    .map(| (_, parent) | parent.proof.as_options())
                                                                    .collect();
                                               p
                                           })
                                      .collect();

                        let data_nodes : Vec<_> = proof.nodes.iter().map(| node | Some(node.data.into())).collect();

                        let data_nodes_paths : Vec<_> =
                                                   proof.nodes.iter().map(| node | node.proof.as_options()).collect();

                        assert(("inconsistent private state", public_inputs.tau.is_none() == public_params.priv));

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
                        std::size_t depth = public_params.graph.merkle_tree_depth::<typenum::U2>();
                        std::size_t degree = public_params.graph.degree();
                        std::size_t arity = 2;

                        let challenges_count = public_params.challenges_count;

                        let replica_nodes = vec ![None; challenges_count];
                        let replica_nodes_paths =
                            vec ![vec ![(vec ![None; arity - 1], None); depth - 1]; challenges_count];

                        let replica_root = Root::Val(None);
                        let replica_parents = vec ![vec ![None; degree]; challenges_count];
                        let replica_parents_paths =
                            vec ![vec ![vec ![(vec ![None; arity - 1], None); depth - 1]; degree]; challenges_count];
                        let data_nodes = vec ![None; challenges_count];
                        let data_nodes_paths =
                            vec ![vec ![(vec ![None; arity - 1], None); depth - 1]; challenges_count];
                        let data_root = Root::Val(None);

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
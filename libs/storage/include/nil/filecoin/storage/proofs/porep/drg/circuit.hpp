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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_DRG_CIRCUIT_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_DRG_CIRCUIT_HPP

#include <nil/crypto3/hash/hash_state.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/zk/components/blueprint_variable.hpp>
#include <nil/crypto3/zk/components/packing.hpp>

#include <nil/filecoin/storage/proofs/core/components/variables.hpp>
#include <nil/filecoin/storage/proofs/core/components/por.hpp>

namespace nil {
    namespace filecoin {
        namespace porep {
            namespace drg {

                /*!
                 * @brief DRG based Proof of Replication.

                 # Fields

                 * `params` - parameters for the curve

                 ----> Private `replica_node` - The replica node being proven.

                 * `replica_node` - The replica node being proven.
                 * `replica_node_path` - The path of the replica node being proven.
                 * `replica_root` - The merkle root of the replica.

                 * `replica_parents` - A list of all parents in the replica, with their value.
                 * `replica_parents_paths` - A list of all parents paths in the replica.

                 ----> Private `data_node` - The data node being proven.

                 * `data_node_path` - The path of the data node being proven.
                 * `data_root` - The merkle root of the data.
                 * `replica_id` - The id of the replica.

                 * @tparam Hash
                 */
                template<typename Hash, typename CurveType = crypto3::algebra::curves::bls12<381>>
                struct DrgPoRepCircuit
                    : public crypto3::zk::components::component<typename CurveType::scalar_field_type> {
                    typedef Hash hash_type;
                    typedef CurveType curve_type;
                    typedef typename curve_type::scalar_field_type fr_type;
                    typedef typename fr_type::value_type fr_value_type;

                    std::vector<fr_value_type> replica_nodes;
                    std::vector<std::vector<std::pair<fr_value_type, std::size_t>>> replica_nodes_paths;
                    root<fr_type> replica_root;
                    std::vector<std::vector<fr_value_type>> replica_parents;
                    std::vector<std::vector<std::vector<std::pair<std::vector<fr_value_type>, std::size_t>>>>
                        replica_parents_paths;
                    std::vector<fr_value_type> data_nodes;
                    std::vector<std::vector<std::pair<std::vector<fr_value_type>, std::size_t>>> data_nodes_paths;
                    root<fr_type> data_root;
                    fr_value_type replica_id;
                    bool priv;

                    crypto3::zk::components::blueprint_variable<fr_type> replica_node_num;

                    DrgPoRepCircuit(crypto3::zk::components::blueprint<fr_type> &bp,
                                    const crypto3::zk::components::blueprint_variable<fr_type> &rroot,
                                    const crypto3::zk::components::blueprint_variable<fr_type> &droot) :
                        replica_root(rroot),
                        data_root(droot), crypto3::zk::components::component<fr_type>(bp) {
                        replica_node_num.allocate(bp);
                    }

                    template<template<typename> class ConstraintSystem>
                    void synthesize(ConstraintSystem<crypto3::algebra::curves::bls12<381>> &cs) {
                        fr_value_type replica_id = replica_id;
                        root<fr_type> replica_root = replica_root;
                        root<fr_type> data_root = data_root;

                        std::size_t nodes = data_nodes.size();

                        assert(replica_nodes.size() == nodes);
                        assert(replica_nodes_paths.size() == nodes);
                        assert(replica_parents.size() == nodes);
                        assert(replica_parents_paths.size() == nodes);
                        assert(data_nodes_paths.size() == nodes);

                        std::size_t replica_node_num = num::AllocatedNumber::alloc(
                            cs.namespace(|| "replica_id_num"),
                            || {replica_id.ok_or_else(|| SynthesisError::AssignmentMissing)});

                        replica_node_num.inputize(cs.namespace(|| "replica_id"));

                        // get the replica_id in bits
                        std::size_t replica_id_bits =
                            reverse_bit_numbering(replica_node_num.to_bits_le(cs.namespace(|| "replica_id_bits")));

                        const auto replica_root_var =
                            Root::Var(replica_root.allocated(cs.namespace(|| "replica_root")));
                        const auto data_root_var = Root::Var(data_root.allocated(cs.namespace(|| "data_root")));

                        for (int i = 0; i < data_nodes.size(); i++) {
                            auto cs = cs.namespace(|| std::format("challenge_{}", i));
                            // ensure that all inputs are well formed
                            std::vector<std::pair<fr_value_type, std::size_t>> replica_node_path =
                                this->replica_nodes_paths[i];
                            std::vector<std::vector<std::pair<std::vector<fr_value_type>, std::size_t>>>
                                replica_parents_paths = this->replica_parents_paths[i];
                            std::vector<std::pair<std::vector<fr_value_type>, std::size_t>> data_node_path =
                                this->data_nodes_paths[i];

                            fr_value_type replica_node = replica_nodes[i];
                            std::vector<fr_value_type> replica_parents = replica_parents[i];
                            fr_value_type data_node = data_nodes[i];

                            assert(replica_parents.size() == replica_parents_paths.size());
                            assert(data_node_path.size() == replica_node_path.size());
                            assert(replica_node.is_some() == data_node.is_some());

                            // Inclusion checks
                            auto cs = cs.namespace(|| "inclusion_checks");
                            PoRCircuit<BinaryMerkleTree<Hash>>::synthesize(
                                cs.namespace(|| "replica_inclusion"), Root::Val(*replica_node),
                                replica_node_path.clone().into(), replica_root_var.clone(), self.priv);

                            // validate each replica_parents merkle proof
                            for (int i = 0; i < replica_parents.size(); i++) {
                                PoRCircuit<BinaryMerkleTree<Hash>>::synthesize(
                                    cs.namespace(|| std::format("parents_inclusion_{}", j)),
                                    Root::Val(replica_parents[j]), replica_parents_paths[j].clone().into(),
                                    replica_root_var.clone(), self.priv);
                            }

                            // validate data node commitment
                            PoRCircuit<BinaryMerkleTree<Hash>>::synthesize(
                                cs.namespace(|| "data_inclusion"), Root::Val(*data_node), data_node_path.clone().into(),
                                data_root_var.clone(), self.priv);

                            // Encoding checks
                            auto cs = cs.namespace(|| "encoding_checks");
                            // get the parents into bits
                            std::vector<std::vector<bool>> parents_bits;

                            for (int i = 0; i < replica_parents.size(); i++) {
                                const auto num = num::AllocatedNumber::alloc(
                                    cs.namespace(|| std::format("parents_{}_num", i)),
                                    || {replica_parents[i]
                                            .map(Into::into)
                                            .ok_or_else(|| SynthesisError::AssignmentMissing)});
                                parents_bits.push_back(reverse_bit_numbering(
                                    num.to_bits_le(cs.namespace(|| std::format("parents_{}_bits", i)))))
                            }

                            // generate the encryption key
                            const auto key = kdf(cs.namespace(|| "kdf"), &replica_id_bits, parents_bits, None, None);

                            const auto replica_node_num = num::AllocatedNumber::alloc(
                                cs.namespace(|| "replica_node"),
                                || {(*replica_node).ok_or_else(|| SynthesisError::AssignmentMissing)});

                            const auto decoded = encode::decode(cs.namespace(|| "decode"), &key, &replica_node_num);

                            // TODO this should not be here, instead, this should be the leaf Fr in the
                            // data_auth_path
                            // TODO also note that we need to change/makesurethat the leaves are the data, instead
                            // of hashes of the data
                            const auto expected = num::AllocatedNumber::alloc(
                                cs.namespace(|| "data node"),
                                || {data_node.ok_or_else(|| SynthesisError::AssignmentMissing)});

                            // ensure the encrypted data and data_node match
                            constraint::equal(cs, || "equality", &expected, &decoded);
                        }
                    }
                };

                /// Key derivation function.
                template<typename ScalarEngine, template<typename> class ConstraintSystem>
                AllocatedNumber<ScalarEngine> kdf(ConstraintSystem<ScalarEngine> &cs, const std::vector<bool> &id,
                                                  const std::vector<std::vector<bool>> &parents,
                                                  std::uint64_t window_index = 0, std::uint64_t node = 0) {
                    // ciphertexts will become a buffer of the layout
                    // id | node | encodedParentNode1 | encodedParentNode1 | ...

                    std::vector<bool> ciphertexts = id;

                    if (window_index) {
                        ciphertexts.extend_from_slice(&window_index.to_bits_be());
                    }

                    if (node) {
                        ciphertexts.extend_from_slice(&node.to_bits_be());
                    }

                    for (const std::vector<bool> &parent : parents) {
                        ciphertexts.extend_from_slice(parent);
                    }

                    const auto alloc_bits = sha256_circuit(cs.namespace(|| "hash"), &ciphertexts[..]);
                    fr_value_type fr;

                    if (alloc_bits[0].get_value().is_some()) {
                        const auto be_bits = alloc_bits.iter()
                                                 .map(| v | v.get_value().ok_or(SynthesisError::AssignmentMissing))
                                                 .collect::<Result<Vec<bool>, SynthesisError>>();

                        const auto le_bits = be_bits.chunks(8)
                                                 .flat_map(| chunk | chunk.iter().rev())
                                                 .copied()
                                                 .take(std::size_t(ScalarEngine::Fr::CAPACITY))
                                                 .collect::<Vec<bool>>();

                        fr = multipack::compute_multipacking<ScalarEngine>(&le_bits)[0];
                    } else {
                        Err(SynthesisError::AssignmentMissing)
                    }

                    return AllocatedNumber<ScalarEngine>::alloc(cs.namespace(|| "result_num"), || fr);
                }
            }    // namespace drg
        }        // namespace porep
    }            // namespace filecoin
}    // namespace nil

#endif

//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>

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
                template<typename TField, typename THash, bool TPrivate>
                class DrgPoRepCircuit: public components::component<TField> {

                    components::blueprint_variable<TField> replica_id_var;
                    components::blueprint_variable<TField> replica_root_var;
                    components::blueprint_variable<TField> data_root_var;

                    std::vector<PoR<TField, BinaryMerkleTree<THash>, TPrivate>> replica_inclusion_por_components;
                    std::vector<std::vector<PoR<TField, BinaryMerkleTree<THash>, TPrivate>>> parents_inclusion_por_components;
                    std::vector<PoR<TField, BinaryMerkleTree<THash>, TPrivate>> data_inclusion_por_components;

                    components::blueprint_variable_vector<TField> replica_id_to_bits;
                    components::reverse_bit_numbering_to_bits_le_packing<TField> replica_id_to_bits_component;

                    std::vector<components::blueprint_variable_vector<TField>> replica_parents_vars;
                    std::vector<std::vector<components::blueprint_variable_vector<TField>>> parents_bits;
                    std::vector<std::vector<components::reverse_bit_numbering_to_bits_le_packing<TField>>> replica_parents_to_bits_component;

                    components::blueprint_variable_vector<TField> kdf_keys;
                    components::blueprint_variable_vector<TField> replica_node_vars;
                    components::blueprint_variable_vector<TField> decoded_vars;
                    components::blueprint_variable_vector<TField> expected_vars;

                    std::size_t nodes_count;
                    std::vector<std::size_t> replica_parents_counts;
                public:

                    DrgPoRepCircuit(components::blueprint<TField> &bp,
                                    const components::blueprint_variable<TField> &rroot,
                                    const components::blueprint_variable<TField> &droot, 
                                    std::size_t nodes_count, 
                                    std::vector<std::size_t> replica_parents_counts) :
                        replica_root(rroot),
                        data_root(droot), components::component<TField>(bp), 
                        nodes_count(nodes_count), replica_parents_counts(replica_parents_counts) {

                        replica_id_var.allocate(bp);
                        replica_root_var.allocate(bp);
                        data_root_var.allocate(bp);

                        replica_id_to_bits.allocate(bp, ???);

                        replica_id_to_bits_component = components::reverse_bit_numbering_to_bits_le_packing<TField>(replica_id_var, 
                            replica_id_to_bits);

                        for (std::size_t i = 0; i < nodes_count; i++){
                            // Inclusion checks
                            replica_inclusion_por_components.emplace_back(???);
                            // validate each replica_parents merkle proof
                            for (std::size_t j = 0; j < replica_parents_counts[i]; j++){
                                parents_inclusion_por_components[i].emplace_back(???);
                            }
                            // validate data node commitment
                            data_inclusion_por_components.emplace_back(???);

                            replica_parents_vars[i].allocate(bp, replica_parents_counts[j]);
                            for (int j = 0; j < replica_parents_counts[j]; j++) {
                                parents_bits[i][j].allocate(bp, ???);
                                replica_parents_to_bits_component[i].emplace_back(replica_parents_vars[i][j], 
                                    parents_bits[i][j]);
                            }
                        }

                        // TODO: KDF component alloc

                        kdf_keys.allocate(bp, nodes_count);
                        replica_node_vars.allocate(bp, nodes_count);
                        decoded_vars.allocate(bp, nodes_count);

                        for (std::size_t i = 0; i < nodes_count; i++){
                            decode_components.emplace_back(kdf_keys[i], replica_node_vars[i], decoded_vars[i]);
                        }

                        expected_vars.allocate(bp, nodes_count);
                    }

                    void generate_r1cs_constraints() {
                        for (std::size_t i = 0; i < nodes_count; i++){

                            // Inclusion checks
                            replica_inclusion_por_components.generate_r1cs_constraints();
                            // validate each replica_parents merkle proof
                            for (std::size_t j = 0; j < replica_parents_counts[i]; j++){
                                parents_inclusion_por_components[i].generate_r1cs_constraints();
                            }

                            // validate data node commitment
                            data_inclusion_por_components.generate_r1cs_constraints();

                            for (std::size_t j = 0; j < replica_parents_counts[j]; j++) {
                                replica_parents_to_bits_component[i].generate_r1cs_constraints();
                            }

                            // TODO: KDF component generate_r1cs_constraints

                            decode_components[i].generate_r1cs_constraints();

                            this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(
                                expected_vars[i], 1, decoded_vars[i]));
                        }
                    }

                    void generate_r1cs_witness(std::vector<typename TField::value_type> replica_nodes,
                                               std::vector<std::vector<std::pair<typename TField::value_type, std::size_t>>> replica_nodes_paths,
                                               typename TField::value_type replica_root,
                                               std::vector<std::vector<typename TField::value_type>> replica_parents,
                                               std::vector<std::vector<std::vector<std::pair<std::vector<typename TField::value_type>, std::size_t>>>>
                                                   replica_parents_paths,
                                               std::vector<typename TField::value_type> data_nodes,
                                               std::vector<std::vector<std::pair<std::vector<typename TField::value_type>, std::size_t>>> data_nodes_paths,
                                               typename TField::value_type data_root,
                                               typename TField::value_type replica_id,
                                               bool priv){

                        assert(replica_nodes.size() == nodes_count);
                        assert(replica_nodes_paths.size() == nodes_count);
                        assert(replica_parents.size() == nodes_count);
                        assert(replica_parents_paths.size() == nodes_count);
                        assert(data_nodes_paths.size() == nodes_count);

                        this->bp.val(replica_id_var) = replica_id;
                        this->bp.val(replica_root_var) = replica_root;
                        this->bp.val(data_root_var) = data_root;

                        replica_id_to_bits_component.generate_r1cs_witness();

                        std::size_t replica_id_bits = this->bp.val(replica_node_to_bits);

                        for (std::size_t i = 0; i < nodes_count; i++){
                            assert(replica_parents[i].size() == replica_parents_paths[i].size());
                            assert(data_node_path[i].size() == replica_node_path[i].size());

                            // Inclusion checks
                            replica_inclusion_por_components.generate_r1cs_witness(replica_nodes[i], 
                                replica_nodes_paths[i], replica_root);
                            // validate each replica_parents merkle proof
                            for (std::size_t j = 0; j < replica_parents_counts[i]; j++){
                                parents_inclusion_por_components[i].generate_r1cs_witness(replica_parents[i], 
                                    replica_parents_paths[i], replica_root);
                            }

                            // validate data node commitment
                            data_inclusion_por_components.generate_r1cs_witness(data_nodes[i], 
                                data_nodes_paths[i], data_root);

                            for (std::size_t j = 0; j < replica_parents_counts[j]; j++) {
                                this->bp.val(replica_parents_vars[i][j]) = replica_parents[i][j];
                                replica_parents_to_bits_component[i].generate_r1cs_witness();
                            }

                            // TODO: KDF component generate_r1cs_witness

                            this->bp.val(replica_node_vars[i]) = replica_nodes[i];

                            decode_components[i].generate_r1cs_witness();

                            this->bp.val(expected_vars[i]) = data_nodes[i];
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
                    typename TField::value_type fr;

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

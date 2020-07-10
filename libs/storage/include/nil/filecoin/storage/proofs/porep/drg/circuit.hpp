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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_DRG_CIRCUIT_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_DRG_CIRCUIT_HPP

#include <nil/filecoin/storage/proofs/core/gadgets/variables.hpp>
#include <nil/filecoin/storage/proofs/core/gadgets/por.hpp>

#include <nil/crypto3/hash/hash_state.hpp>
#include <nil/crypto3/hash/sha2.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename ScalarEngine>
                struct circuit;
            }
        }    // namespace zk
    }        // namespace crypto3
    namespace filecoin {
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
         * @tparam Bls12
         */
        template<typename Hash, template<typename> class ConstraintSystem, typename Bls12, typename Fr>
        struct DrgPoRepCircuit : public crypto3::zk::snark::circuit<Bls12> {
            typedef Hash hash_type;

            std::vector<Fr> replica_nodes;
            std::vector<std::vector<std::pair<Fr, std::size_t>>> replica_nodes_paths;
            root<Bls12> replica_root;
            std::vector<std::vector<Fr>> replica_parents;
            std::vector<std::vector<std::vector<std::pair<std::vector<Fr>, std::size_t>>>> replica_parents_paths;
            std::vector<Fr> data_nodes;
            std::vector<std::vector<std::pair<std::vector<Fr>, std::size_t>>> data_nodes_paths;
            root<Bls12> data_root;
            Fr replica_id;
            bool priv;

            void synthesize(ConstraintSystem<Bls12> &cs) {
                Fr replica_id = replica_id;
                root<Bls12> replica_root = replica_root;
                root<Bls12> data_root = data_root;

                std::size_t nodes = data_nodes.size();

                assert(replica_nodes.size() == nodes);
                assert(replica_nodes_paths.size() == nodes);
                assert(replica_parents.size() == nodes);
                assert(replica_parents_paths.size() == nodes);
                assert(data_nodes_paths.size() == nodes);

                std::size_t replica_node_num =
                    num::AllocatedNum::alloc(cs.namespace(|| "replica_id_num"),
                                             || {replica_id.ok_or_else(|| SynthesisError::AssignmentMissing)}) ?
                    ;

                replica_node_num.inputize(cs.namespace(|| "replica_id")) ? ;

                // get the replica_id in bits
                let replica_id_bits =
                reverse_bit_numbering(replica_node_num.to_bits_le(cs.namespace(|| "replica_id_bits"))?);

                let replica_root_var = Root::Var(replica_root.allocated(cs.namespace(|| "replica_root"))?);
                let data_root_var = Root::Var(data_root.allocated(cs.namespace(|| "data_root"))?);

                for (int i = 0; i < data_nodes.size(); i++) {
                    let mut cs = cs.namespace(|| format !("challenge_{}", i));
                    // ensure that all inputs are well formed
                    let replica_node_path = &self.replica_nodes_paths[i];
                    let replica_parents_paths = &self.replica_parents_paths[i];
                    let data_node_path = &self.data_nodes_paths[i];

                    let replica_node = &self.replica_nodes[i];
                    let replica_parents = &self.replica_parents[i];
                    let data_node = &self.data_nodes[i];

                    assert(replica_parents.size() == replica_parents_paths.size());
                    assert(data_node_path.size() == replica_node_path.size());
                    assert(replica_node.is_some() == data_node.is_some());

                    // Inclusion checks
                    {
                        let mut cs = cs.namespace(|| "inclusion_checks");
                        PoRCircuit<BinaryMerkleTree<Hash>>::synthesize(
                            cs.namespace(|| "replica_inclusion"), Root::Val(*replica_node),
                            replica_node_path.clone().into(), replica_root_var.clone(), self.private, ) ?
                            ;

                        // validate each replica_parents merkle proof
                        for (int i = 0; i < replica_parents.size(); i++) {
                            PoRCircuit<BinaryMerkleTree<Hash>>::synthesize(
                                cs.namespace(|| format !("parents_inclusion_{}", j)), Root::Val(replica_parents[j]),
                                replica_parents_paths[j].clone().into(), replica_root_var.clone(), self.private, ) ?
                                ;
                        }

                        // validate data node commitment
                        PoRCircuit<BinaryMerkleTree<Hash>>::synthesize(
                            cs.namespace(|| "data_inclusion"), Root::Val(*data_node), data_node_path.clone().into(),
                            data_root_var.clone(), self.private, ) ?
                            ;
                    }

                    // Encoding checks
                    {
                        let mut cs = cs.namespace(|| "encoding_checks");
                        // get the parents into bits
                        let parents_bits
                            : Vec<Vec<Boolean>> =
                                  replica_parents.iter()
                                      .enumerate()
                                      .map(| (i, val) |
                                           {
                                               let num = num::AllocatedNum::alloc(
                                                   cs.namespace(|| format !("parents_{}_num", i)),
                                                   || {val.map(Into::into)
                                                           .ok_or_else(|| SynthesisError::AssignmentMissing)}, ) ?
                                                   ;
                        Ok(reverse_bit_numbering(num.to_bits_le(
                        cs.namespace(|| format!("parents_{}_bits", i)),
                        )?))
                                           })
                                      .collect::<Result<Vec<Vec<Boolean>>, SynthesisError>>() ?
                            ;

                        // generate the encryption key
                        let key = kdf(cs.namespace(|| "kdf"), &replica_id_bits, parents_bits, None, None, ) ? ;

                        let replica_node_num = num::AllocatedNum::alloc(
                            cs.namespace(|| "replica_node"),
                            || {(*replica_node).ok_or_else(|| SynthesisError::AssignmentMissing)}) ?
                            ;

                        let decoded = encode::decode(cs.namespace(|| "decode"), &key, &replica_node_num) ? ;

                        // TODO this should not be here, instead, this should be the leaf Fr in the data_auth_path
                        // TODO also note that we need to change/makesurethat the leaves are the data, instead of
                        // hashes of the data
                        let expected =
                            num::AllocatedNum::alloc(cs.namespace(|| "data node"),
                                                     || {data_node.ok_or_else(|| SynthesisError::AssignmentMissing)}) ?
                            ;

                        // ensure the encrypted data and data_node match
                        constraint::equal(&mut cs, || "equality", &expected, &decoded);
                    }
                }
            }
        };

        /// Key derivation function.
        template<typename ScalarEngine, template<typename> class ConstraintSystem, typename InputIdIterator>
        AllocatedNum<ScalarEngine> kdf(ConstraintSystem<ScalarEngine> &cs, InputIdIterator id_first,
                                       InputIdIterator id_last, const std::vector<std::vector<bool>> &parents,
                                       std::uint64_t window_index = 0, std::uint64_t node = 0)

        {
            // ciphertexts will become a buffer of the layout
            // id | node | encodedParentNode1 | encodedParentNode1 | ...

            let mut ciphertexts = id.to_vec();

            if (window_index) {
                ciphertexts.extend_from_slice(&window_index.to_bits_be());
            }

            if (node) {
                ciphertexts.extend_from_slice(&node.to_bits_be());
            }

            for (parent : parents) {
                ciphertexts.extend_from_slice(parent);
            }

            let alloc_bits = sha256_circuit(cs.namespace(|| "hash"), &ciphertexts[..]);
            let fr = if alloc_bits[0].get_value().is_some() {
                let be_bits = alloc_bits.iter()
                                  .map(| v | v.get_value().ok_or(SynthesisError::AssignmentMissing))
                                  .collect::<Result<Vec<bool>, SynthesisError>>() ?
                    ;

                let le_bits = be_bits.chunks(8)
                                  .flat_map(| chunk | chunk.iter().rev())
                                  .copied()
                                  .take(E::Fr::CAPACITY as usize)
                                  .collect::<Vec<bool>>();

                return multipack::compute_multipacking::<E>(&le_bits)[0];
            }
            else {Err(SynthesisError::AssignmentMissing)};

            return num::AllocatedNum::<Engine>::alloc(cs.namespace(|| "result_num"), || fr);
        }
    }    // namespace filecoin
}    // namespace nil

#endif
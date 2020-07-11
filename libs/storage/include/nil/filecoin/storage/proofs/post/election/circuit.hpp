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

#ifndef FILECOIN_STORAGE_PROOFS_POST_ELECTION_CIRCUIT_HPP
#define FILECOIN_STORAGE_PROOFS_POST_ELECTION_CIRCUIT_HPP

namespace nil {
    namespace filecoin {
        namespace post {
            namespace election {
                /// This is the `ElectionPoSt` circuit.
                template<typename MerkleTreeType, typename Bls12, template<typename> class Circuit>
                struct ElectionPoStCircuit : public Circuit<Bls12> {
                    template<template<typename> class ConstraintSystem>
                    void synthesize(ConstraintSystem<Bls12> &cs) {
                        let comm_r = self.comm_r;
                        let comm_c = self.comm_c;
                        let comm_r_last = self.comm_r_last;
                        let leafs = self.leafs;
                        let paths = self.paths;
                        let partial_ticket = self.partial_ticket;
                        let randomness = self.randomness;
                        let prover_id = self.prover_id;
                        let sector_id = self.sector_id;

                        assert(paths.size() == leafs.size());

                        // 1. Verify comm_r

                        let comm_r_last_num = num::AllocatedNum::alloc(
                            cs.namespace(|| "comm_r_last"),
                            || {comm_r_last.map(Into::into).ok_or_else(|| SynthesisError::AssignmentMissing)}) ?
                            ;

                        let comm_c_num = num::AllocatedNum::alloc(
                            cs.namespace(|| "comm_c"),
                            || {comm_c.map(Into::into).ok_or_else(|| SynthesisError::AssignmentMissing)}) ?
                            ;

                        let comm_r_num = num::AllocatedNum::alloc(
                            cs.namespace(|| "comm_r"),
                            || {comm_r.map(Into::into).ok_or_else(|| SynthesisError::AssignmentMissing)}) ?
                            ;

                        comm_r_num.inputize(cs.namespace(|| "comm_r_input")) ? ;

                        // Verify H(Comm_C || comm_r_last) == comm_r
                        {
                            let hash_num = <Tree::Hasher as Hasher>::Function::hash2_circuit(
                                cs.namespace(|| "H_comm_c_comm_r_last"), &comm_c_num, &comm_r_last_num, ) ?
                                ;

                            // Check actual equality
                            constraint::equal(cs, || "enforce_comm_c_comm_r_last_hash_comm_r", &comm_r_num,
                                              &hash_num, );
                        }

                        // 2. Verify Inclusion Paths
                        for ((i, (leaf, path)) : leafs.iter().zip(paths.iter()).enumerate()) {
                            PoRCircuit::<Tree>::synthesize(
                                cs.namespace(|| format !("challenge_inclusion{}", i)), Root::Val(*leaf),
                                path.clone().into(), Root::from_allocated::<CS>(comm_r_last_num.clone()), true, ) ?
                                ;
                        }

                        // 3. Verify partial ticket

                        // randomness
                        let randomness_num = num::AllocatedNum::alloc(
                            cs.namespace(|| "randomness"),
                            || {randomness.map(Into::into).ok_or_else(|| SynthesisError::AssignmentMissing)}) ?
                            ;

                        // prover_id
                        let prover_id_num = num::AllocatedNum::alloc(
                            cs.namespace(|| "prover_id"),
                            || {prover_id.map(Into::into).ok_or_else(|| SynthesisError::AssignmentMissing)}) ?
                            ;

                        // sector_id
                        let sector_id_num = num::AllocatedNum::alloc(
                            cs.namespace(|| "sector_id"),
                            || {sector_id.map(Into::into).ok_or_else(|| SynthesisError::AssignmentMissing)}) ?
                            ;

                        let mut partial_ticket_nums = vec ![ randomness_num, prover_id_num, sector_id_num ];
                        for (i, leaf)
                            in leafs.iter().enumerate() {
                                let leaf_num = num::AllocatedNum::alloc(
                                    cs.namespace(|| format !("leaf_{}", i)),
                                    || {leaf.map(Into::into).ok_or_else(|| SynthesisError::AssignmentMissing)}) ?
                                    ;
                                partial_ticket_nums.push(leaf_num);
                            }

                        // pad to a multiple of md arity
                        let arity = PoseidonMDArity::to_usize();
                        while (partial_ticket_nums.size() % arity) {
                                partial_ticket_nums.push(num::AllocatedNum::alloc(
                                    cs.namespace(|| format!("padding_{}", partial_ticket_nums.len())),
                                || Ok(Fr::zero()),
                                )?);
                        }

                        // hash it
                        let partial_ticket_num = PoseidonFunction::hash_md_circuit::<_>(
                            &mut cs.namespace(|| "partial_ticket_hash"), &partial_ticket_nums, ) ?
                            ;

                        // allocate expected input
                        let expected_partial_ticket_num = num::AllocatedNum::alloc(
                            cs.namespace(|| "partial_ticket"),
                            || {partial_ticket.map(Into::into).ok_or_else(|| SynthesisError::AssignmentMissing)}) ?
                            ;

                        expected_partial_ticket_num.inputize(cs.namespace(|| "partial_ticket_input")) ? ;

                        // check equality
                        constraint::equal(cs, || "enforce partial_ticket is correct", &partial_ticket_num,
                                          &expected_partial_ticket_num);
                    }

                    Fr comm_r;
                    Fr comm_c;
                    Fr comm_r_last;
                    std::vector<Fr> leafs;
                    std::vector<std::vector<std::pair<std::vector<Fr>, std::size_t>>> paths;
                    Fr partial_ticket;
                    Fr randomness;
                    Fr prover_id;
                    Fr sector_id;
                };
            }    // namespace election
        }        // namespace post
    }            // namespace filecoin
}    // namespace nil

#endif
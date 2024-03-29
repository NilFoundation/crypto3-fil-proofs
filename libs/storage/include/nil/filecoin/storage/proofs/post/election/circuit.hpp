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

#ifndef FILECOIN_STORAGE_PROOFS_POST_ELECTION_CIRCUIT_HPP
#define FILECOIN_STORAGE_PROOFS_POST_ELECTION_CIRCUIT_HPP

namespace nil {
    namespace filecoin {
        namespace post {
            namespace election {
                /// This is the `ElectionPoSt` circuit.
                template<typename MerkleTreeType, template<typename> class Circuit>
                struct ElectionPoStCircuit : public Circuit<crypto3::algebra::curves::bls12<381>> {
                    template<template<typename> class ConstraintSystem>
                    void synthesize(ConstraintSystem<crypto3::algebra::curves::bls12<381>> &cs) {
                        assert(paths.size() == leafs.size());

                        // 1. Verify comm_r

                        const auto comm_r_last_num = num::AllocatedNumber::alloc(
                            cs.namespace(|| "comm_r_last"),
                            || {comm_r_last.map(Into::into).ok_or_else(|| SynthesisError::AssignmentMissing)});

                        const auto comm_c_num = num::AllocatedNumber::alloc(
                            cs.namespace(|| "comm_c"),
                            || {comm_c.map(Into::into).ok_or_else(|| SynthesisError::AssignmentMissing)});

                        const auto comm_r_num = num::AllocatedNumber::alloc(
                            cs.namespace(|| "comm_r"),
                            || {comm_r.map(Into::into).ok_or_else(|| SynthesisError::AssignmentMissing)});

                        comm_r_num.inputize(cs.namespace(|| "comm_r_input"));

                        // Verify H(Comm_C || comm_r_last) == comm_r
                        const auto hash_num = <typename MerkleTreeType::hash_type>::Function::hash2_circuit(
                            cs.namespace(|| "H_comm_c_comm_r_last"), &comm_c_num, &comm_r_last_num, );

                        // Check actual equality
                        constraint::equal(cs, || "enforce_comm_c_comm_r_last_hash_comm_r", &comm_r_num, &hash_num, );

                        // 2. Verify Inclusion Paths
                        for ((i, (leaf, path)) : leafs.iter().zip(paths.iter()).enumerate()) {
                            PoRCircuit::<Tree>::synthesize(cs.namespace(|| std::format("challenge_inclusion{}", i)),
                                                           Root::Val(*leaf), path.clone().into(),
                                                           Root::from_allocated::<CS>(comm_r_last_num.clone()), true, );
                        }

                        // 3. Verify partial ticket

                        // randomness
                        const auto randomness_num = num::AllocatedNumber::alloc(
                            cs.namespace(|| "randomness"),
                            || {randomness.map(Into::into).ok_or_else(|| SynthesisError::AssignmentMissing)});

                        // prover_id
                        const auto prover_id_num = num::AllocatedNumber::alloc(
                            cs.namespace(|| "prover_id"),
                            || {prover_id.map(Into::into).ok_or_else(|| SynthesisError::AssignmentMissing)});

                        // sector_id
                        const auto sector_id_num = num::AllocatedNumber::alloc(
                            cs.namespace(|| "sector_id"),
                            || {sector_id.map(Into::into).ok_or_else(|| SynthesisError::AssignmentMissing)});

                        const std::vector<auto> partial_ticket_nums = {randomness_num, prover_id_num, sector_id_num};
                        for ((i, leaf)in leafs.iter().enumerate()) {
                            const auto leaf_num = num::AllocatedNumber::alloc(
                                cs.namespace(|| std::format("leaf_{}", i)),
                                || {leaf.map(Into::into).ok_or_else(|| SynthesisError::AssignmentMissing)});
                            partial_ticket_nums.push(leaf_num);
                        }

                        // pad to a multiple of md arity
                        const auto arity = PoseidonMDArity::to_usize();
                        while (partial_ticket_nums.size() % arity) {
                            partial_ticket_nums.push(num::AllocatedNumber::alloc(
                                cs.namespace(|| std::format("padding_{}", partial_ticket_nums.len())),
                                || Ok(Fr::zero())));
                        }

                        // hash it
                        const auto partial_ticket_num = PoseidonFunction::hash_md_circuit::<_>(
                            cs.namespace(|| "partial_ticket_hash"), &partial_ticket_nums, );

                        // allocate expected input
                        const auto expected_partial_ticket_num = num::AllocatedNumber::alloc(
                            cs.namespace(|| "partial_ticket"),
                            || {partial_ticket.map(Into::into).ok_or_else(|| SynthesisError::AssignmentMissing)});

                        expected_partial_ticket_num.inputize(cs.namespace(|| "partial_ticket_input"));

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

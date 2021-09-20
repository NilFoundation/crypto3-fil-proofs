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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_PROOF_COMPONENTS_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_PROOF_COMPONENTS_HPP

namespace nil {
    namespace filecoin {
        namespace porep {
            namespace stacked {
                namespace components {
                    /// Stacked DRG based Proof of Replication.
                    ///
                    /// # Fields
                    ///
                    /// * `params` - parameters for the curve
                    ///
                    template<typename TField, typename TMerkleTree, typename THasher>
                    class StackedCircuit : public components::component<TField> {
                        
                        typename TMerkleTree::Hasher::Domain replica_id;
                        typename THasher::Domain comm_d;
                        typename TMerkleTree::Hasher::Domain comm_r;
                        typename TMerkleTree::Hasher::Domain comm_r_last;
                        typename TMerkleTree::Hasher::Domain comm_c;

                        components::blueprint_variable<TField> replica_id_var;
                        components::blueprint_variable<TField> comm_d_var;
                        components::blueprint_variable<TField> comm_r_var;
                        components::blueprint_variable<TField> comm_r_last_var;
                        components::blueprint_variable<TField> comm_c_var;
                        components::blueprint_variable<TField> hash_var;
                        components::hash_component hash_component;

                    public:

                        typename StackedDrg<a, TMerkleTree, THasher>::PublicParams public_params;

                        // one proof per challenge
                        std::vector<Proof<TField, TMerkleTree, THasher>> proofs;

                        StackedCircuit clone(){

                            return StackedCircuit (
                                public_params: self.public_params.clone(), 
                                replica_id : self.replica_id, 
                                comm_d : self.comm_d, 
                                comm_r : self.comm_r, 
                                comm_r_last : self.comm_r_last, 
                                comm_c : self.comm_c, 
                                proofs : self.proofs.clone()
                            );
                        }

                        StackedCircuit(components::blueprint<TField> &bp, 
                                       typename StackedDrg<a, TMerkleTree, THasher>::PublicParams public_params, 
                                       std::size_t n_proofs){

                            replica_id_var.allocate(bp);
                            comm_d_var.allocate(bp);
                            comm_r_var.allocate(bp);
                            comm_r_last_var.allocate(bp);
                            comm_c_var.allocate(bp);
                            hash_var.allocate(bp);

                            // pseudo-code. Component should depend on the THasher. It looks like 
                            // it's usually blake2s. But in our current blueprint architecture 
                            // that's not possible to choose hash component by the hash.
                            components::hash_component hash_component(bp, &comm_c_num,
                                &comm_r_last_num, &hash_var);

                            for (std::size_t i = 0; i < n_proofs; i++){
                                proofs.emplace_back(bp, 
                                                    public_params.layer_challenges.layers(), 
                                                    &comm_d_var, 
                                                    &comm_c_var, 
                                                    &comm_r_last_var, 
                                                    &replica_id_bits);
                            }
                        }

                        void generate_r1cs_constraints() {
                            hash_component.generate_r1cs_constraints();

                            this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(
                                1, comm_r_var, hash_var));

                            for (std::vector<Proof<TMerkleTree, THasher>>::iterator proof_it = proofs.begin(); 
                                 proof_it != proofs.end(); 
                                 proof_it++){
                                proof_it->generate_r1cs_constraints();
                            }
                        }

                        void generate_r1cs_witness(
                                typename TMerkleTree::Hasher::Domain replica_id_in, 
                                typename THasher::Domain comm_d_in, 
                                typename TMerkleTree::Hasher::Domain comm_r_in, 
                                typename TMerkleTree::Hasher::Domain comm_r_last_in, 
                                typename TMerkleTree::Hasher::Domain comm_c_in) {
                            replica_id = replica_id_in;
                            comm_d = comm_d_in;
                            comm_r = comm_r_in;
                            comm_r_last = comm_r_last_in;
                            comm_c = comm_c_in;

                            bp.val(replica_id_var) = replica_id;
                            bp.val(comm_d_var) = comm_d;
                            bp.val(comm_r_var) = comm_r;
                            bp.val(comm_r_last_var) = comm_r_last;
                            bp.val(comm_c_var) = comm_c;

                            hash_component.generate_r1cs_witness();

                            for (std::vector<Proof<TMerkleTree, THasher>>::iterator proof_it = proofs.begin(); 
                                 proof_it != proofs.end(); 
                                 proof_it++){
                                proof_it->generate_r1cs_witness();
                            }
                        }
                    };
                }    // namespace components
            }    // namespace stacked
        }    // namespace porep
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_STORAGE_PROOFS_POREP_STACKED_PROOF_COMPONENTS_HPP

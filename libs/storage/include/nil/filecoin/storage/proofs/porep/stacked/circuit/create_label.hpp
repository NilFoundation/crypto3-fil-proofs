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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_CREATE_LABEL_COMPONENTS_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_CREATE_LABEL_COMPONENTS_HPP

namespace nil {
    namespace filecoin {
        namespace porep {
            namespace stacked {
                namespace components {

                    /// Compute a single label.
                    template<typename TField>
                    class create_label: public components::component<TField>{

                        components::sha256_hash<TField> sha256_component;

                    public:

                        components::blueprint_variable<TField> hash_result;

                        create_label(components::blueprint<TField> &bp, 
                                             components::blueprint_variable<TField> &hash_result): 
                            components::component<TField>(bp), sha256_component(bp, hash_result), hash_result(hash_result){
                        }

                        void generate_r1cs_constraints() {
                            sha256_component.generate_r1cs_constraints();
                        }

                        void generate_r1cs_witness(std::vector<bool> replica_id, 
                                                   std::vector<std::vector<bool>> parents,
                                                   std::uint32_t layer_index,
                                                   std::uint64_t node){

                            assert(replica_id.len() >= 32, "Replica id is too small.");
                            assert(replica_id.len() <= 256, "Replica id is too large.");
                            assert(parents.len() == TOTAL_PARENTS, "Invalid sized parents.");

                            // ciphertexts will become a buffer of the layout
                            // id | node | parent_node_0 | parent_node_1 | ...

                            std::vector<bool> ciphertexts(replica_id);

                            // pad to 32 bytes
                            while (ciphertexts.len() < 256) {
                                ciphertexts.push(false);
                            }

                            using integral_32t_marshalling_type = 
                                nil::marshalling::types::integral<
                                    nil::marshalling::field_type<
                                    nil::marshalling::option::big_endian>,
                                    std::uint32_t>;
                            using integral_64t_marshalling_type = 
                                nil::marshalling::types::integral<
                                    nil::marshalling::field_type<
                                    nil::marshalling::option::big_endian>,
                                    std::uint64_t>;

                            std::size_t byte_bits = 8;

                            std::vector<bool> layer_index_bits;
                            layer_index_bits.resize(integral_32t_marshalling_type::length()*byte_bits);

                            std::vector<bool> node_bits;
                            node_bits.resize(integral_64t_marshalling_type::length()*byte_bits);

                            integral_32t_marshalling_type layer_index_marshalling_var(layer_index);
                            integral_64t_marshalling_type node_marshalling_var(node);

                            std::vector<bool>::iterator write_iter = layer_index_bits.begin();
                            layer_index_marshalling_var.write(write_iter);
                            write_iter = node_bits.begin();
                            node_marshalling_var.write(write_iter);

                            ciphertexts.extend(layer_index_bits);
                            ciphertexts.extend(node_bits);

                            // pad to 64 bytes
                            while (ciphertexts.len() < 512) {
                                ciphertexts.push(false);
                            }

                            for (auto parent: parents) {
                                ciphertexts.extend(parent);

                                // pad such that each parents take 32 bytes
                                while (ciphertexts.size() % 256 != 0) {
                                    ciphertexts.push(false);
                                }
                            }

                            // 32b replica id
                            // 32b layer_index + node
                            // 37 * 32b  = 1184b parents
                            assert_eq!(ciphertexts.len(), (1 + 1 + TOTAL_PARENTS) * 32 * 8);

                            // Compute Sha256
                            sha256_component.generate_r1cs_witness(ciphertexts);
                        }
                    };

                }    // namespace components
            }        // namespace stacked
        }            // namespace porep
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_STORAGE_PROOFS_POREP_STACKED_CREATE_LABEL_COMPONENTS_HPP

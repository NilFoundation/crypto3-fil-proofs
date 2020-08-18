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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_GADGETS_PEDERSEN_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_GADGETS_PEDERSEN_HPP

#include <nil/algebra/curves/bls12.hpp>

#include <nil/crypto3/zk/snark/gadgets/basic_gadgets.hpp>
#include <nil/crypto3/zk/snark/gadgets/hashes/hash_io.hpp>
#include <nil/crypto3/zk/snark/gadgets/hashes/sha256/sha256_components.hpp>

namespace nil {
    namespace filecoin {
        namespace gadgets {
            template<typename FieldType>
            struct pedersen_compression_function_gadget : public crypto3::zk::snark::gadget<FieldType> {
                pedersen_compression_function_gadget(crypto3::zk::snark::protoboard<FieldType> &pb) :
                    crypto3::zk::snark::gadget<FieldType>(pb) {
                }

                void generate_r1cs_constraints() {
                }
                void generate_r1cs_witness() {
                }
            };

            template<typename FieldType>
            struct pedersen_compression_num_gadget : public crypto3::zk::snark::gadget<FieldType> {
                pedersen_compression_num_gadget(crypto3::zk::snark::protoboard<FieldType> &pb) : crypto3::zk::snark::gadget<FieldType>(pb) {
                }
                void generate_r1cs_constraints() {
                }
                void generate_r1cs_witness() {
                }
            };

            template<typename FieldType>
            struct pedersen_md_no_padding_gadget : public crypto3::zk::snark::gadget<FieldType> {
                pedersen_md_no_padding_gadget(crypto3::zk::snark::protoboard<FieldType> &pb) : crypto3::zk::snark::gadget<FieldType>(pb) {
                }

                std::shared_ptr<pedersen_compression_num_gadget<FieldType>> num_compression;
                std::shared_ptr<pedersen_compression_function_gadget<FieldType>> compression;

                void generate_r1cs_constraints() {

                }
                void generate_r1cs_witness() {

                }
            };

            template<typename FieldType>
            struct pedersen_hash_gadget : public crypto3::zk::snark::gadget<FieldType> {
                pedersen_hash_gadget(crypto3::zk::snark::protoboard<FieldType> &pb) : crypto3::zk::snark::gadget<FieldType>(pb) {
                }

                void generate_r1cs_constraints() {

                }
                void generate_r1cs_witness() {

                }
            };
        }    // namespace gadgets
    }        // namespace filecoin
}    // namespace nil

#endif
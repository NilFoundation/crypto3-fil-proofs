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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_LABELING_PROOF_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_LABELING_PROOF_HPP

namespace nil {
    namespace filecoin {
        namespace stacked {
            namespace vanilla {
                template<typename Hash>
                struct LabelingProof {
                    typedef Hash hash_type;

                    template<typename LabelHash>
                    typename Hash::domain_type create_label(const typename Hash::domain_type &replica_id) {
                        let mut hasher = Sha256::new ();
                        let mut buffer = [0u8; 64];

                        // replica_id
                        buffer[..32].copy_from_slice(AsRef::<[u8]>::as_ref(replica_id));

                        // layer index
                        buffer[32..36].copy_from_slice(&(self.layer_index as u32).to_be_bytes());

                        // node id
                        buffer[36..44].copy_from_slice(&(self.node as u64).to_be_bytes());

                        hasher.input(&buffer[..]);

                        // parents
                        for (parent : parents) {
                            let data = AsRef::<[u8]>::as_ref(parent);
                            hasher.input(data);
                        }

                        bytes_into_fr_repr_safe(hasher.result().as_ref()).into()
                    }

                    bool verify(const typename Hash::domain_type &replica_id,
                                const typename Hash::domain_type &expected_label) {
                        typename Hash::domain_type label = create_label(replica_id);
                        return expected_label == label;
                    }

                    typename Hash::domain_type parents;
                    std::uint32_t layer_index;
                    std::uint64_t node;
                    Hash &_h;
                };
            }    // namespace vanilla
        }        // namespace stacked
    }            // namespace filecoin
}    // namespace nil

#endif
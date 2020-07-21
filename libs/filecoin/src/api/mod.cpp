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

#include <nil/filecoin/proofs/api/mod.hpp>

namespace nil {
    namespace filecoin {
        void ensure_piece_size(unpadded_bytes_amount piece_size) {
            assert(piece_size >= MINIMUM_PIECE_SIZE);

            padded_bytes_amount padded_piece_size = piece_size;
            assert(padded_piece_size.is_power_of_two());
        }

        void verify_store(StoreConfig &config, std::size_t arity, std::size_t required_configs) {
            let store_path = StoreConfig::data_path(&config.path, config.id);
            if (!Path::new (&store_path).exists()) {
                // Configs may have split due to sector size, so we need to
                // check deterministic paths from here.
                let orig_path = store_path.clone().into_os_string().into_string().unwrap();
                std::vector<StoreConfig> configs(required_configs);
                for (int i = 0; i < required_configs; i++) {
                    let cur_path = orig_path.clone().replace(".dat", format !("-{}.dat", i).as_str());

                    if (Path ::new (&cur_path).exists()) {
                        let path_str = cur_path.as_str();
                        std::vector<std::string> tree_names = {"tree-d", "tree-c", "tree-r-last"};
                        for (const std::string &name : tree_names) {
                            if (path_str.find(name).is_some()) {
                                configs.push_back(StoreConfig::from_config(config, format !("{}-{}", name, i), None, ));
                                break;
                            }
                        }
                    }
                }

                ensure !(configs.len() == required_configs, "Missing store file (or associated split paths): {}",
                         store_path.display());

                let store_len = config.size.unwrap();
                for (const StoreConfig &config : configs) {
                    assert(DiskStore::<DefaultPieceDomain>::is_consistent(store_len, arity, &config));
                }
            } else {
                assert(DiskStore::<DefaultPieceDomain>::is_consistent(config.size.unwrap(), arity, &config));
            }
        }
    }    // namespace filecoin
}    // namespace nil

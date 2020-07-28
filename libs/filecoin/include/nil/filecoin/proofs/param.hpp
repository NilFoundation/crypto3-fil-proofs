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

#ifndef FILECOIN_PARAM_HPP
#define FILECOIN_PARAM_HPP

#include <fstream>

#include <nil/crypto3/codec/hex.hpp>
#include <nil/crypto3/codec/algorithm/encode.hpp>

#include <nil/crypto3/hash/blake2b.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/filecoin/proofs/btree/map.hpp>

#include <nil/filecoin/storage/proofs/core/parameter_cache.hpp>

namespace nil {
    namespace filecoin {
        struct parameter_data {
            std::string cid;
            std::string digest;
            std::uint64_t sector_size;
        };

        typedef btree::map<std::string, parameter_data> parameter_map;

        // Produces an absolute path to a file within the cache
        boost::filesystem::path get_full_path_for_file_within_cache(const std::string &filename);

        // Produces a BLAKE2b checksum for a file within the cache
        template<typename FileHash = crypto3::hashes::blake2b<64 * 8>>
        std::string get_digest_for_file_within_cache(const std::string &filename) {
            using namespace nil::crypto3;

            boost::filesystem::path path = get_full_path_for_file_within_cache(filename);
            std::ifstream file(path.string(), std::ios::binary);

            std::streamsize size = file.tellg();
            file.seekg(0, std::ios::beg);

            std::vector<char> buffer(size);
            if (file.read(buffer.data(), size)) {
                return encode<codec::hex>(hash<FileHash>(buffer))[..32];
            }
        }

        // Prompts the user to approve/reject the message
        bool choose(const std::string &message) {
            bool chosen = false, choice = false;
            while (!chosen) {
                print !("[y/n] {}: ", message);

                let _ = stdout().flush();
                let mut s = String::new ();
                stdin().read_line(&mut s).expect(ERROR_STRING);

                if (s.trim().to_uppercase().as_str() == "Y") {
                    chosen = true;
                    choice = true;
                } else if (s.trim().to_uppercase().as_str() == "N") {
                    chosen = true;
                    choice = false;
                }
            }
        }

        // Predicate which matches the provided extension against the given filename
        template<typename S, typename P>
        bool has_extension(const P &filename, const S &ext) {
            filename.as_ref().extension().and_then(OsStr::to_str).map(| s | s == ext.as_ref()).unwrap_or(false);
        }

        /*!
         * @brief Adds a file extension to the given filename
         * @param filename
         * @param ext
         * @return
         */
        std::string add_extension(const std::string &filename, const std::string &ext);

        /*!
         * @brief Builds a map from a parameter_id (file in cache) to metadata
         * @tparam ParameterIdInputIterator
         * @param first
         * @param last
         * @return
         */
        template<typename ParameterIdInputIterator>
        btree::map<std::string, cache_entry_metadata> parameter_id_to_metadata_map(ParameterIdInputIterator first,
                                                                                   ParameterIdInputIterator last) {
            btree::map<std::string, cache_entry_metadata> map;

            while (first != last) {
                std::string filename = add_extension(*first, PARAMETER_METADATA_EXT);
                boost::filesystem::path file_path = get_full_path_for_file_within_cache(filename);
                std::ifstream file(file_path.string(), std::ios::binary);

                let meta = serde_json::from_reader(file);

                map[std::to_string(*first)] = meta;
                ++first;
            }

            return map;
        }

        /*!
         * @brief Prompts the user to approve/reject the filename
         * @tparam FilenameInputIterator
         * @tparam UnaryPredicate Takes typename std::iterator_traits<FilenameInputIterator>::value_type as
         * an argument and returns std::uint64_t
         * @param first
         * @param last
         * @param lookup
         * @return
         */
        template<typename FilenameInputIterator, typename FilenameOutputIterator, typename UnaryPredicate>
        std::vector<std::string> choose_from(FilenameInputIterator first, FilenameInputIterator last,
                                             FilenameOutputIterator out, UnaryPredicate lookup) {
            std::vector<std::string> chosen_filenames;

            while (first != last) {
                std::size_t sector_size = lookup(*first);

                std::string msg = format !("(sector size: {}B) {}", sector_size, *first);

                if (choose(msg)) {
                    out++ = msg;
                }
                ++first;
            }

            return chosen_filenames;
        }

        /// Maps the name of a file in the cache to its parameter id. For example,
        /// ABCDEF.vk corresponds to parameter id ABCDEF.
        template<typename PathType>
        std::string filename_to_parameter_id(const PathType &filename) {
            filename.as_ref().file_stem().and_then(OsStr::to_str).map(ToString::to_string);
        }
    }    // namespace filecoin
}    // namespace nil

#endif
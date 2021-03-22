//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nemo@nil.foundation>
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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_PARAMETER_CACHE_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_PARAMETER_CACHE_HPP

#define BOOST_FILESYSTEM_NO_DEPRECATED

#include <string>

#include <boost/filesystem/path.hpp>
#include <boost/filesystem/operations.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark.hpp>

namespace nil {
    namespace filecoin {
        constexpr static const std::size_t VERSION = 27;
        constexpr static const char *PARAMETER_CACHE_ENV_VAR = "FIL_PROOFS_PARAMETER_CACHE";
        constexpr static const char *PARAMETER_CACHE_DIR = "/var/tmp/filecoin-proof-parameters/";
        constexpr static const char *GROTH_PARAMETER_EXT = "params";
        constexpr static const char *PARAMETER_METADATA_EXT = "meta";
        constexpr static const char *VERIFYING_KEY_EXT = "vk";

        std::string parameter_cache_dir_name() {
            return std::getenv(PARAMETER_CACHE_ENV_VAR);
        }

        boost::filesystem::path parameter_cache_dir() {
            return parameter_cache_dir_name();
        }

        boost::filesystem::path parameter_cache_params_path(const std::string &parameter_set_identifier) {
            return boost::filesystem::path(
                (parameter_cache_dir_name() + "/v" + std::to_string(VERSION) + "-" + parameter_set_identifier + ".")
                    .append(GROTH_PARAMETER_EXT));
        }

        boost::filesystem::path parameter_cache_metadata_path(const std::string &parameter_set_identifier) {
            return boost::filesystem::path(
                (parameter_cache_dir_name() + "/v" + std::to_string(VERSION) + "-" + parameter_set_identifier + ".")
                    .append(PARAMETER_METADATA_EXT));
        }

        boost::filesystem::path parameter_cache_verifying_key_path(const std::string &parameter_set_identifier) {
            return boost::filesystem::path(
                (parameter_cache_dir_name() + "/v" + std::to_string(VERSION) + "-" + parameter_set_identifier + ".")
                    .append(VERIFYING_KEY_EXT));
        }

        boost::filesystem::path ensure_ancestor_dirs_exist(const boost::filesystem::path &cache_entry_path) {
            boost::filesystem::path parent_dir = cache_entry_path.parent_path();
            if (boost::filesystem::exists(parent_dir.status())) {
                return cache_entry_path;
            } else {
                throw std::invalid_argument(cache_entry_path.string() + " has no parent directory");
            }
        }

        struct parameter_set_metadata {
            virtual std::string identifier() const = 0;
            virtual std::size_t sector_size() const = 0;
        };

        struct cache_entry_metadata {
            std::size_t sector_size;
        };

        cache_entry_metadata read_cached_metadata(const boost::filesystem::path &cache_entry_path) {
            with_exclusive_read_lock(
                cache_entry_path, [&](const boost::filesystem::path &file) { return serde_json::from_reader(file); });
        }

        cache_entry_metadata write_cached_metadata(const boost::filesystem::path &cache_entry_path,
                                                   cache_entry_metadata value) {
            with_exclusive_lock(cache_entry_path, [&](const boost::filesystem::path &file) {
                serde_json::to_writer(file, value);

                return value;
            });
        }

        template<template<typename> class Groth16MappedParams>
        Groth16MappedParams<crypto3::algebra::curves::bls12<381>>
            read_cached_params(const boost::filesystem::path &cache_entry_path) {
            with_exclusive_read_lock(cache_entry_path,
                                     [&]() -> Groth16MappedParams<crypto3::algebra::curves::bls12<381>> {
                                         Groth16MappedParams<crypto3::algebra::curves::bls12<381>> params =
                                             Parameters::build_mapped_parameters(cache_entry_path, false);
                                     });
        }

        crypto3::zk::snark::r1cs_ppzksnark_verification_key<crypto3::algebra::curves::bls12<381>>
            read_cached_verifying_key(const boost::filesystem::path &cache_entry_path) {
            with_exclusive_read_lock(cache_entry_path, [&](const boost::filesystem::path &file) {
                return r1cs_ppzksnark_verification_key<algebra::curves::bls12<381>>::read(file);
            });
        }

        crypto3::zk::snark::r1cs_ppzksnark_verification_key<crypto3::algebra::curves::bls12<381>>
            write_cached_verifying_key(
                const boost::filesystem::path &cache_entry_path,
                const crypto3::zk::snark::r1cs_ppzksnark_verification_key<crypto3::algebra::curves::bls12<381>>
                    &value) {
            with_exclusive_lock(cache_entry_path, [&](const boost::filesystem::path &file) {
                value.write(file);

                return value;
            });
        }

        template<template<typename> class Groth16Parameters>
        Groth16Parameters<crypto3::algebra::curves::bls12<381>>
            write_cached_params(const boost::filesystem::path &cache_entry_path,
                                Groth16Parameters<crypto3::algebra::curves::bls12<381>>
                                    value) {
            with_exclusive_lock(cache_entry_path, [&](const boost::filesystem::path &file) {
                value.write(file);
                return value;
            });
        }

        template<template<typename> class Circuit, typename ParameterSetMetadata = parameter_set_metadata>
        struct cacheable_parameters {
            typedef Circuit<crypto3::algebra::curves::bls12<381>> C;
            typedef ParameterSetMetadata P;

            virtual std::string cache_prefix() const = 0;

            cache_entry_metadata cache_meta(const P &pub_params) {
                return {pub_params.graph.sector_size()};
            }

            virtual std::string cache_identifier(const P &pub_params) {
                using namespace nil::crypto3;

                std::string circuit_hash = crypto3::hash<crypto3::hashes::sha2<256>>(pub_params.identifier());
                std::format("{}-{:02x}", cache_prefix(), circuit_hash.iter().format(""))
            }

            cache_entry_metadata get_param_metadata(const C &circuit, const P &pub_params) {
                std::string id = cache_identifier(pub_params);

                // generate (or load) metadata
                boost::filesystem::path meta_path = ensure_ancestor_dirs_exist(parameter_cache_metadata_path(id));
                try {
                    read_cached_metadata(meta_path);
                } catch (...) {
                    write_cached_metadata(meta_path, cache_meta(pub_params));
                }
            }

            template<template<typename> class Groth16MappedParams, typename UniformRandomGenerator>
            Groth16MappedParams<crypto3::algebra::curves::bls12<381>>
                get_groth_params(UniformRandomGenerator &r, const C &circuit, const P &pub_params) {
                std::string id = cache_identifier(pub_params);

                const auto generate = [&]() {
                    return groth16::generate_random_parameters<crypto3::algebra::curves::bls12<381>>(circuit, r);
                };

                boost::filesystem::path cache_path = ensure_ancestor_dirs_exist(parameter_cache_params_path(id));

                try {
                    return read_cached_params(cache_path);
                } catch (...) {
                    return write_cached_params(cache_path, generate());
                }
            }

            template<typename UniformRandomGenerator>
            crypto3::zk::snark::r1cs_ppzksnark_verification_key<crypto3::algebra::curves::bls12<381>>
                get_verifying_key(UniformRandomGenerator &r, const C &circuit, const P &pub_params) {
                std::string id = cache_identifier(pub_params);

                const auto generate =
                    [&]() -> crypto3::zk::snark::r1cs_ppzksnark_verification_key<crypto3::algebra::curves::bls12<381>> {
                    return get_groth_params(r, circuit, pub_params).vk;
                };

                boost::filesystem::path cache_path = ensure_ancestor_dirs_exist(parameter_cache_verifying_key_path(id));
                try {
                    return read_cached_verifying_key(cache_path);
                } catch (...) {
                    return write_cached_verifying_key(cache_path, generate());
                }
            }
        };
    }    // namespace filecoin
}    // namespace nil

#endif

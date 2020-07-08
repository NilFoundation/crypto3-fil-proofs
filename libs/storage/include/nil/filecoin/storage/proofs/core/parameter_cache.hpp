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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_PARAMETER_CACHE_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_PARAMETER_CACHE_HPP

#include <boost/filesystem/path.hpp>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

namespace nil {
    namespace filecoin {
        constexpr static const std::size_t VERSION = 27;
        constexpr static const const char *PARAMETER_CACHE_ENV_VAR = "FIL_PROOFS_PARAMETER_CACHE";
        constexpr static const const char *PARAMETER_CACHE_DIR = "/var/tmp/filecoin-proof-parameters/";
        constexpr static const *GROTH_PARAMETER_EXT = "params";
        constexpr static const *PARAMETER_METADATA_EXT = "meta";
        constexpr static const *VERIFYING_KEY_EXT = "vk";

        namespace detail {
            std::string parameter_cache_dir_name() {
                return std::getenv(PARAMETER_CACHE_ENV_VAR);
            }

            boost::filesystem::path parameter_cache_dir() {
                return parameter_cache_dir_name();
            }

            boost::filesystem::path parameter_cache_params_path(const std::string &parameter_set_identifier) {
                let dir = Path::new (&parameter_cache_dir_name()).to_path_buf();
                dir.join(format !("v{}-{}.{}", VERSION, parameter_set_identifier, GROTH_PARAMETER_EXT))
            }

            boost::filesystem::path parameter_cache_metadata_path(const std::string &parameter_set_identifier) {
                let dir = Path::new (&parameter_cache_dir_name()).to_path_buf();
                dir.join(format !("v{}-{}.{}", VERSION, parameter_set_identifier, PARAMETER_METADATA_EXT))
            }

            boost::filesystem::path parameter_cache_verifying_key_path(const std::string &parameter_set_identifier) {
                let dir = Path::new (&parameter_cache_dir_name()).to_path_buf();
                dir.join(format !("v{}-{}.{}", VERSION, parameter_set_identifier, VERIFYING_KEY_EXT))
            }

            boost::filesystem::path ensure_ancestor_dirs_exist(const boost::filesystem::path &cache_entry_path) {
                info !("ensuring that all ancestor directories for: {:?} exist", cache_entry_path);

                if let
                    Some(parent_dir) = cache_entry_path.parent() {
                        if let
                            Err(err) = create_dir_all(&parent_dir) {
                                match err.kind() {
                                    io::ErrorKind::AlreadyExists = > {
                                    }
                                    _ = > return Err(From::from(err)),
                                }
                            }
                    }
                else {
                    bail !("{:?} has no parent directory", cache_entry_path);
                }

                Ok(cache_entry_path)
            }
        }    // namespace detail

        struct parameter_set_metadata {
            virtual std::string identifier() const = 0;
            virtual std::size_t sector_size() const = 0;
        };

        struct cache_entry_metadata {
            std::size_t sector_size;
        };

        template<template<typename> class Circuit, typename Bls12,
                 typename ParameterSetMetadata = parameter_set_metadata>
        struct cacheable_parameters {
            typedef Circuit<Bls12> C;
            typedef ParameterSetMetadata P;

            virtual std::string cache_prefix() const = 0;

            cache_entry_metadata cache_meta(const P &pub_params) {
                return {pub_params.sector_size()};
            }

            virtual std::string cache_identifier(const P &pub_params) {
                using namespace nil::crypto3;

                std::string circuit_hash = hash<hashes::sha2<256>>(pub_params.identifier());
                format !("{}-{:02x}", cache_prefix(), circuit_hash.iter().format(""))
            }

            cache_entry_metadata get_param_metadata(const C &circuit, const P &pub_params) {
                let id = cache_identifier(pub_params);

                // generate (or load) metadata
                boost::filesystem::path meta_path =
                    detail::ensure_ancestor_dirs_exist(parameter_cache_metadata_path(&id));
                read_cached_metadata(&meta_path)
                    .or_else(| _ | write_cached_metadata(&meta_path, cache_meta(pub_params)))
            }

            template<typename Bls12, typename UniformRandomGenerator>
            groth::mapped_params<Bls12> get_groth_params(UniformRandomGenerator &r, const C &circiut,
                                                         const P &pub_params) {
                std::string id = cache_identifier(pub_params);

                auto generate = [&]() {
                    if let
                        Some(rng) = rng {
                            use std::time::Instant;

                            info !("Actually generating groth params. (id: {})", &id);
                            let start = Instant::now();
                            let parameters = groth16::generate_random_parameters::<Bls12, _, _>(circuit, rng) ? ;
                            let generation_time = start.elapsed();
                            info !("groth_parameter_generation_time: {:?} (id: {})", generation_time, &id);
                            Ok(parameters)
                        }
                    else {
                        bail !("No cached parameters found for {}", id);
                    }
                };

                boost::filesystem::path cache_path = ensure_ancestor_dir_exist(parameter_cache_params_path(id));

                if (read_cached_params(cache_path)) {
                    Ok(x) = > Ok(x), Err(_) = > {
                    write_cached_params(&cache_path, generate()?).unwrap_or_else(|e| {
                        panic!("{}: failed to write generated parameters to cache", e)
                    });
                    Ok(read_cached_params(&cache_path)?)
                    }
                }
            }

            template<typename Bls12, typename UniformRandomGenerator>
            groth16::verifying_key<Bls12> get_verifying_key(UniformRandomGenerator &r, const C &circuit,
                                                            const P &pub_params) {
                std::string id = cache_identifier(pub_params);

                auto generate = [&]() groth16::verifying_key<Bls12> {
                    auto groth_params = get_groth_params(rng, circuit, pub_params);
                    return groth_params.vk;
                };

                boost::filesystem::path cache_path = ensure_ancestor_dirs_exist(parameter_cache_verifying_key_path(id));
            read_cached_verifying_key(&cache_path)
                .or_else(|_| write_cached_verifying_key(&cache_path, generate()?));
            }
        };

        template<typename Bls12>
        groth16::mapped_params<Bls12> read_cached_params(const boost::filesystem::path &cache_entry_path) {
            with_exclusive_read_lock(cache_entry_path, [&]() -> groth16::mapped_params<Bls12> {
                groth16::mapped_params<Bls12> params =
                    Parameters::build_mapped_parameters(cache_entry_path.to_path_buf(), false) ?
                    ;
                info !("read parameters from cache {:?} ", cache_entry_path);
            });
        }

        template<typename Bls12>
        groth16::verifying_key<Bls12> read_cached_verifying_key(const boost::filesystem &path) {
            with_exclusive_read_lock(cache_entry_path, [&](const boost::filesystem::path &file) {
                return groth16::verifying_key<Bls12>::read(file);
            });
        }

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

        template<typename Bls12>
        groth16::verifying_key<Bls12> write_cached_verifying_key(const boost::filesystem::path &cache_entry_path,
                                                                 groth16::verifying_key<Bls12>
                                                                     value) {
            with_exclusive_lock(cache_entry_path, [&](const boost::filesystem::path &file) {
                value.write(file);

                return value;
            });
        }

        template<typename Bls12>
        groth16::parameters<Bls12> write_cached_params(const boost::filesystem::path &cache_entry_path,
                                                       groth16::parameters<Bls12> value) {
            with_exclusive_lock(cache_entry_path, [&](const boost::filesystem::path &file) {
                value.write(file);
                return value;
            });
        }
    }    // namespace filecoin
}    // namespace nil

#endif
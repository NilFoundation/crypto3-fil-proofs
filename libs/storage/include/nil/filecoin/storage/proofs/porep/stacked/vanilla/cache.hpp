//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020 Wukong Moscow Algorithm Lab
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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_HASH_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_HASH_HPP

#define BOOST_FILESYSTEM_NO_DEPRECATED

#include <boost/filesystem/path.hpp>
#include <boost/log/trivial.hpp>

#include <nil/crypto3/detail/pack.hpp>

#include <nil/crypto3/codec/hex.hpp>
#include <nil/crypto3/codec/algorithm/encode.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/filecoin/storage/proofs/core/parameter_cache.hpp>

#include <nil/filecoin/storage/proofs/porep/stacked/vanilla/graph.hpp>

namespace nil {
    namespace filecoin {
        namespace stacked {
            namespace vanilla {
                /// Path in which to store the parents caches.
                constexpr static const char *PARENT_CACHE_DIR = "/var/tmp/filecoin-parents";

                /// u32 = 4 bytes
                constexpr static const std::size_t NODE_BYTES = 4;

                struct CacheData {
                    /// Change the cache to point to the newly passed in offset.
                    ///
                    /// The `new_offset` must be set, such that `new_offset + len` does not
                    /// overflow the underlying data.
                    void shift(std::uint32_t new_offset) {
                        if (offset == new_offset) {
                            return;
                        }

                        std::size_t offset = new_offset * DEGREE * NODE_BYTES;
                        std::size_t len = len * DEGREE * NODE_BYTES;

                        data = unsafe {memmap::MmapOptions::new ()
                                           .offset(std::size_t(offset))
                                           .len(len)
                                           .map(self.file.as_ref())
                                           .context("could not shift mmap}") ? };
                        offset = new_offset;
                    }

                    /// Returns true if this node is in the cached range.
                    bool contains(std::uint32_t node) {
                        return node >= offset && node < offset + len;
                    }

                    /// Read the parents for the given node from cache.
                    ///
                    /// Panics if the `node` is not in the cache.
                    std::array<std::uint32_t, DEGREE> read(std::uint32_t node) {
                        BOOST_ASSERT_MSG(node >= offset, "node not in cache");
                        std::size_t start = (node - offset) * DEGREE * NODE_BYTES;
                        std::size_t end = start + DEGREE * NODE_BYTES;

                        std::array<std::uint32_t, DEGREE> res;
                        res.fill(0);
                        crypto3::detail::pack_to<crypto3::stream_endian::little_octet_big_bit>(data, res);
                        return res;
                    }

                    void reset() {
                        if (offset == 0) {
                            return;
                        }

                        shift(0);
                    }

                    static CacheData open(std::uint32_t offset, std::uint32_t len,
                                          const boost::filesystem::path &path) {
                        std::size_t min_cache_size = (offset + len) * DEGREE * NODE_BYTES;

                        const auto file = LockedFile::open_shared_read(path).with_context(
                            || std::format("could not open path={}", path.display())) ?;

                        const auto actual_len = file.as_ref().metadata().len();
                        if (actual_len < min_cache_size) {
                            bail !("corrupted cache: {}, expected at least {}, got {} bytes",
                                   path.display(),
                                   min_cache_size,
                                   actual_len);
                        }

                        const auto data = unsafe {memmap::MmapOptions::new ()
                                               .offset(std_uint_64(std::size_t(offset) * DEGREE * NODE_BYTES))
                                               .len(std::size_t(len) * DEGREE * NODE_BYTES)
                                               .map(file.as_ref())
                                               .with_context(|| std::format("could not mmap path={}", path.display())) ? };

                        return {data, file, len, offset};
                    }

                    /// This is a large list of fixed (parent) sized arrays.
                    memmap::mmap data;
                    /// Offset in nodes.
                    std::uint32_t offset;
                    /// Len in nodes.
                    std::uint32_t len;
                    /// The underlyling file.
                    LockedFile file;
                };

                // StackedGraph will hold two different (but related) `ParentCache`,
                struct ParentCache {
                    template<template<typename, typename> class StackedGraph, typename Hash, typename Graph>
                    ParentCache(std::uint32_t len, std::uint32_t cache_entries, StackedGraph<Hash, Graph> &graph) {
                        boost::filesystem::path path = cache_path(cache_entries, graph);
                        if (path) {
                            open(len, cache_entries, path);
                        } else {
                            generate(len, cache_entries, graph, path);
                        }
                    }

                    /// Opens an existing cache from disk.
                    static ParentCache open(std::uint32_t len, std::uint32_t cache_entries,
                                            const boost::filesystem::path &path) {

                        CacheData cache = CacheData::open(0, len, path);

                        return {path, cache_entries, cache};
                    }

                    /// Generates a new cache and stores it on disk.
                    template<template<typename, typename> class StackedGraph, typename Hash, typename Graph>
                    static ParentCache generate(std::uint32_t len, std::uint32_t cache_entries,
                                                StackedGraph<Hash, Graph> &graph, const boost::filesystem::path &path) {

                        with_exclusive_lock(path, [&](const boost::filesystem::path &file) {
                            std::size_t cache_size = cache_entries * NODE_BYTES * DEGREE;
                            file.set_len(cache_size);

                            auto data =
                                unsafe {memmap::MmapOptions::new ()
                                            .map_mut(file.as_ref())
                                            .with_context(|| std::format("could not mmap path={}", path.display())) ? };

                            data.par_chunks_mut(DEGREE * NODE_BYTES)
                                .enumerate()
                                .try_for_each(| (node, entry) |->Result<()> {
                                    auto parents = [0u32; DEGREE];
                                    graph.base_graph().parents(node, parents[..BASE_DEGREE]) ? ;
                                    graph.generate_expanded_parents(node, parents[BASE_DEGREE..]);

                                    LittleEndian::write_u32_into(&parents, entry);
                                    Ok(())
                                });

                            BOOST_LOG_TRIVIAL(info) << "parent cache: generated";
                            data.flush().context("failed to flush parent cache");
                            drop(data);

                            BOOST_LOG_TRIVIAL(info) << "parent cache: written to disk";
                        });

                        return {CacheData::open(0, len, &path), path, cache_entries};
                    }

                    /// Read a single cache element at position `node`.
                    std::array<std::uint32_t, DEGREE> read(std::uint32_t node) {
                        if (cache.contains(node)) {
                            return cache.read(node);
                        }

                        // not in memory, shift cache
                        BOOST_ASSERT_MSG(node >= cache.offset + cache.len, "cache must be read in ascending order");

                        // Shift cache by its current size.
                        std::size_t new_offset = (num_cache_entries - cache.len).min(cache.offset + cache.len);
                        cache.shift(new_offset);

                        return cache.read(node);
                    }

                    /// Resets the partial cache to the beginning.
                    void reset() {
                        cache.reset();
                    }

                    /// Disk path for the cache.
                    boost::filesystem::path path;
                    /// The total number of cache entries.
                    std::uint32_t num_cache_entries;
                    CacheData cache;
                };

                std::string parent_cache_dir_name() {
                    return settings::SETTINGS.lock().parent_cache.clone();
                }

                template<template<typename, typename> class StackedGraph, typename Hash, typename Graph,
                         typename FormatHash = crypto3::hashes::sha2<256>>
                boost::filesystem::path cache_path(std::uint32_t cache_entries, StackedGraph<Hash, Graph> &graph) {
                    using namespace nil::crypto3;

                    accumulator_set<FormatHash> acc;
                    hash<FormatHash>(FormatHash::name, acc);
                    hash<FormatHash>(graph.identifier(), acc);

                    for (const auto key : graph.feistel_keys) {
                        hash<FormatHash>(key, acc);
                    }

                    hash<FormatHash>(cache_entries, acc);

                    typename FormatHash::digest_type h = accumulators::extract::hash<FormatHash>(acc);
                    return boost::filesystem::path(parent_cache_dir_name() + "v" + std::to_string(VERSION) +
                                                   "-sdr-parent-" +
                                                   encode<codec::hex>(h) + ".cache");
                }
            }    // namespace vanilla
        }        // namespace stacked
    }            // namespace filecoin
}    // namespace nil

#endif

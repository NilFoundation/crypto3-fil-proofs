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

#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_HASH_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_VANILLA_HASH_HPP

namespace nil {
    namespace filecoin {
        /// Path in which to store the parents caches.
        const PARENT_CACHE_DIR : &str = "/var/tmp/filecoin-parents";

        /// u32 = 4 bytes
        const NODE_BYTES : usize = 4;

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
                                   .offset(offset as u64)
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
                assert(("node not in cache", node >= self.offset));
                std::size_t start = (node - offset) * DEGREE * NODE_BYTES;
                std::size_t end = start + DEGREE * NODE_BYTES;

                std::array<std::uint32_t, DEGREE> res;
                res.fill(0);
                LittleEndian::read_u32_into(&self.data[start..end], &mut res);
                return res;
            }

            void reset(&mut self) {
                if (offset == 0) {
                    return;
                }

                shift(0)
            }

            static CacheData open(std::uint32_t offset, std::uint32_t len, boost::filesystem::path &path) {
                std::size_t min_cache_size = (offset + len) * DEGREE * NODE_BYTES;

                let file = LockedFile::open_shared_read(path).with_context(
                    || format !("could not open path={}", path.display())) ?
                    ;

                let actual_len = file.as_ref().metadata() ?.len();
                if (actual_len < min_cache_size) {
                    bail !("corrupted cache: {}, expected at least {}, got {} bytes",
                           path.display(),
                           min_cache_size,
                           actual_len);
                }

                let data = unsafe {memmap::MmapOptions::new ()
                                       .offset((offset as usize * DEGREE * NODE_BYTES) as u64)
                                       .len(len as usize * DEGREE * NODE_BYTES)
                                       .map(file.as_ref())
                                       .with_context(|| format !("could not mmap path={}", path.display())) ? };

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
        }

        // StackedGraph will hold two different (but related) `ParentCache`,
        struct ParentCache {
            template<template<typename, typename> class StackedGraph, typename Hash, typename Graph>
            ParentCache(std::uint32_t len, std::uint32_t cache_entries, StackedGraph<Hash, Graph> &graph) {
                boost::filesystem::path path = cache_path(cache_entries, graph);
                if (path.exists()) {
                    Self::open(len, cache_entries, path)
                } else {
                    Self::generate(len, cache_entries, graph, path)
                }
            }

            /// Opens an existing cache from disk.
            static ParentCache open(std::uint32_t len, std::uint32_t cache_entries,
                                    const boost::filesystem::path &path) {
                info !("parent cache: opening {}", path.display());

                CacheData cache = CacheData::open(0, len, &path);
                info !("parent cache: opened");

                return {cache, path, cache_entries};
            }

            /// Generates a new cache and stores it on disk.
            template<template<typename, typename> class StackedGraph, typename Hash, typename Graph>
            static ParentCache generate(std::uint32_t len, std::uint32_t cache_entries,
                                        StackedGraph<Hash, Graph> &graph, const boost::filesystem::path &path) {
                info !("parent cache: generating {}", path.display());

                with_exclusive_lock(
                    &path.clone(),
                    | file |
                        {
                            let cache_size = cache_entries as usize * NODE_BYTES * DEGREE;
                            file.as_ref()
                                .set_len(cache_size as u64)
                                .with_context(|| format !("failed to set length: {}", cache_size)) ?
                                ;

                            let mut data =
                                unsafe {memmap::MmapOptions::new ()
                                            .map_mut(file.as_ref())
                                            .with_context(|| format !("could not mmap path={}", path.display())) ? };

                            data.par_chunks_mut(DEGREE * NODE_BYTES)
                                .enumerate()
                                .try_for_each(
                                    | (node, entry) |
                                          ->Result<()> {
                                              let mut parents = [0u32; DEGREE];
                                              graph.base_graph().parents(node, &mut parents[..BASE_DEGREE]) ? ;
                                              graph.generate_expanded_parents(node, &mut parents[BASE_DEGREE..]);

                                              LittleEndian::write_u32_into(&parents, entry);
                                              Ok(())
                                          }) ?
                                ;

                            info !("parent cache: generated");
                            data.flush().context("failed to flush parent cache") ? ;
                            drop(data);

                            info !("parent cache: written to disk");
                            Ok(())
                        }) ?
                    ;

                return {CacheData::open(0, len, &path), path, cache_entries};
            }

            /// Read a single cache element at position `node`.
            std::array<std::uint32_t, DEGREE> read(std::uint32_t node) {
                if (cache.contains(node)) {
                    return cache.read(node);
                }

                // not in memory, shift cache
                ensure !(node >= self.cache.offset + self.cache.len,
                         "cache must be read in ascending order {} < {} + {}", node, self.cache.offset,
                         self.cache.len, );

                // Shift cache by its current size.
                let new_offset = (self.num_cache_entries - self.cache.len).min(self.cache.offset + self.cache.len);
                self.cache.shift(new_offset) ? ;

                Ok(self.cache.read(node))
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

        template<template<typename, typename> class StackedGraph, typename Hash, typename Graph>
        boost::filesystem::path cache_path(std::uint32_t cache_entries, StackedGraph<Hash, Graph> &graph) {
            let mut hasher = Sha256::default();

            hasher.input(H::name());
            hasher.input(graph.identifier());
            for (key : graph.feistel_keys) {
                hasher.input(key.to_le_bytes());
            }
            hasher.input(cache_entries.to_le_bytes());
            let h = hasher.result();
            return PathBuf::from(PARENT_CACHE_DIR).join(format !("v{}-sdr-parent-{}.cache", VERSION, hex::encode(h)))
        }
    }    // namespace filecoin
}    // namespace nil

#endif
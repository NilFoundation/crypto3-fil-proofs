//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//


#ifndef FILECOIN_MMAP_HPP
#define FILECOIN_MMAP_HPP

#include <stdio.h>
#include <vector>

#include <boost/filesystem.hpp>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>


#include <nil/filecoin/storage/proofs/core/merkle/processing/storage/utilities.hpp>

namespace nil {
    namespace filecoin {
        namespace merkletree {
            template<typename Element>
            struct MmapStore {
                MmapStore(size_t size, size_t branches, StoreConfig config) {
                    boost::filesystem::path data_path = StoreConfig::data_path(config.path_, config.id_);
                    // If the specified file exists, load it from disk.
                    if (boost::filesystem::exists(data_path)) {
                        return self.new_from_disk(size, branches, &config);
                    }
                    // Otherwise, create the file and allow it to be the on-disk store.
                    let file = OpenOptions::new().write(true).read(true).create_new(true).open(&data_path)?;

                    let store_size = E::byte_len() * size;
                    file.set_len(store_size as u64)?;

                    let map = unsafe { MmapMut::map_mut(&file)? };

                    self.path = data_path;
                    self.map = map;
                    self.file = file;
                    self.len = 0;
                    self.store_size = store_size;
                }

                MmapStore(size_t size) {
                    let store_size = E::byte_len() * size;

                    FILE* file = tempfile::NamedTempFile::new()?;
                    file.as_file().set_len(store_size as u64)?;
                    let (file, path) = file.into_parts();
                    let map = unsafe { MmapMut::map_mut(&file)? };

                    self.path = path;
                    self.map = map;
                    self.file = file;
                    self.len = 0;
                    self.store_size = store_size;
                }

                MmapStore(size_t size, size_t _branches, StoreConfig config) {
                    boost::filesystem::path data_path = StoreConfig::data_path(&config.path, &config.id);

                    let file = OpenOptions::new().write(true).read(true).open(&data_path)?;
                    let metadata = file.metadata()?;
                    let store_size = metadata.len() as usize;

                    // Sanity check.
                    assert(store_size == size * E::byte_len(),
                           "Invalid formatted file provided. Expected {} bytes, found {} bytes", size * E::byte_len(), store_size);

                    let map = unsafe { MmapMut::map_mut(&file)? };
                    self.path = data_path;
                    self.map = map;
                    self.file = file;
                    self.len = size;
                    self.store_size = store_size;
                }

                void write_at(Element el, size_t index) {
                    size_t start = index * Element::byte_len();
                    size_t end = start + Element::byte_len();

                    if (self.map.is_none()) {
                        self.reinit()?;
                    }

                    self.map.as_mut().unwrap()[start..end].copy_from_slice(el.as_ref());
                    self.len = std::cmp::max(self.len, index + 1);
                }

                void copy_from_slice(buf: &[u8], size_t start) {
                    assert(buf.len() % E::byte_len() == 0, "buf size must be a multiple of {}", Element::byte_len());

                    let map_start = start * E::byte_len();
                    let map_end = map_start + buf.len();

                    if (self.map.is_none()) {
                        self.reinit()?;
                    }

                    self.map.as_mut().unwrap()[map_start..map_end].copy_from_slice(buf);
                    self.len = std::cmp::max(self.len, start + (buf.len() / E::byte_len()));
                }

                MmapStore(size_t size, size_t branches, data: &[u8], StoreConfig config) {
                    assert( data.len() % E::byte_len() == 0, "data size must be a multiple of {}", Element::byte_len());

                    let mut store = Self::new_with_config(size, branches, config)?;

                    // If the store was loaded from disk (based on the config
                    // information, avoid re-populating the store at this point
                    // since it can be assumed by the config that the data is
                    // already correct).
                    if (!store.loaded_from_disk()) {
                        if store.map.is_none() {
                            store.reinit()?;
                        }

                        let len = data.len();

                        store.map.as_mut().unwrap()[0..len].copy_from_slice(data);
                        store.len = len / E::byte_len();
                    }

                    Ok(store)
                }

                MmapStore(size_t size, data: &[u8]) {
                    assert(data.len() % Element::byte_len() == 0, "data size must be a multiple of {}", Element::byte_len());

                    let mut store = Self::new(size)?;
                    assert(store.map.is_some(), "Internal map needs to be initialized");

                    let len = data.len();
                    store.map.as_mut().unwrap()[0..len].copy_from_slice(data);
                    store.len = len / E::byte_len();

                    Ok(store)
                }

                Element read_at(size_t index) {
                    assert(self.map.is_some(), "Internal map needs to be initialized");

                    let start = index * Element::byte_len();
                    let end = start + Element::byte_len();
                    let len = self.len * Element::byte_len();

                    assert(start < len, "start out of range {} >= {}", start, len);
                    assert(end <= len, "end out of range {} > {}", end, len);

                    return Element::from_slice(&self.map.as_ref().unwrap()[start..end]))
                }

                void read_into(size_t index, buf: &mut [u8]) {
                    assert(self.map.is_some(), "Internal map needs to be initialized");

                    let start = index * Element::byte_len();
                    let end = start + Element::byte_len();
                    let len = self.len * Element::byte_len();

                    assert(start < len, "start out of range {} >= {}", start, len);
                    assert(end <= len, "end out of range {} > {}", end, len);

                    buf.copy_from_slice(&self.map.as_ref().unwrap()[start..end]);
                }

                void read_range_into(size_t _start, size_t _end, _buf: &mut [u8]) {
                    assert("Not required here");
                }

                std::vector<Element> read_range(r: ops::Range<usize>) {
                    assert(self.map.is_some(), "Internal map needs to be initialized");

                    let start = r.start * Element::byte_len();
                    let end = r.end * Element::byte_len();
                    let len = self.len * Element::byte_len();

                    assert(start < len, "start out of range {} >= {}", start, len);
                    assert(end <= len, "end out of range {} > {}", end, len);

                    return (self.map.as_ref().unwrap()[start..end]
                           .chunks(E::byte_len())
                           .map(E::from_slice)
                           .collect())
                }

                size_t len() {
                    self.len
                }

                bool loaded_from_disk() {
                    return false
                }

                bool compact(size_t _branches: usize, StoreConfig _config, uint32_t _store_version) {
                    let map = self.map.take();
                    return map.is_some();
                }

                void reinit() {
                    self.map = unsafe { Some(MmapMut::map_mut(&self.file)?) };
                    assert(self.map.is_some(), "Re-init mapping failed");
                }

                bool is_empty() {
                    return self.len == 0;
                }

                void push(Element el) {
                    let l = self.len;
                    if (self.map.is_none()) {
                        self.reinit()?;
                    }

                    assert((l + 1) * E::byte_len() <= self.map.as_ref().unwrap().len(), "not enough space");
                    self.write_at(el, l)
                }

                boost::filesystem::path path;
                map: Option<MmapMut>;
                FILE *file;
                size_t len;
                size_t store_size;
            };
        }    // namespace merkletree
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_MMAP_HPP

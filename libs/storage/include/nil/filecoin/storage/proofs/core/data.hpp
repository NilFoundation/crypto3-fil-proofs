#ifndef FILECOIN_STORAGE_PROOFS_CORE_DATA_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_DATA_HPP

#include <boost/filesystem/path.hpp>

#include <boost/interprocess/file_mapping.hpp>

namespace nil {
    namespace filecoin {
        struct raw_data {
            std::vector<std::uint8_t> slice;
            boost::interprocess::file_mapping file;
        };
        struct data {
            raw_data raw;
            boost::filesystem::path path;
            std::size_t len;
        };
    }    // namespace filecoin

#endif
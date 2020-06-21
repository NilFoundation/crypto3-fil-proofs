#ifndef FILECOIN_STORAGE_PROOFS_CORE_SETTINGS_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_SETTINGS_HPP

namespace nil {
    namespace filecoin {
        constexpr static const char *settings_path = "config.ini";

        struct configuration {
            bool maximize_caching = false;
            std::uint32_t pedersen_hash_exp_window_size = 16;
            bool use_gpu_column_builder = false;
            std::uint32_t max_gpu_column_batch_size = 400000;
            std::uint32_t column_write_batch_size = 262144;
            bool use_gpu_tree_builder = false;
            std::uint32_t max_gpu_tree_batch_size = 700000;
            std::uint32_t rows_to_discard = 2;
        };

    }    // namespace filecoin
}    // namespace nil

#endif
#ifndef FILECOIN_STORAGE_PROOFS_POREP_DRG_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_DRG_HPP

#include <nil/filecoin/storage/proofs/core/gadgets/variables.hpp>

#include <nil/crypto3/hash/hash_state.hpp>
#include <nil/crypto3/hash/sha2.hpp>

namespace nil {
    namespace filecoin {
        /*!
         * @brief DRG based Proof of Replication.

         # Fields

         * `params` - parameters for the curve

         ----> Private `replica_node` - The replica node being proven.

         * `replica_node` - The replica node being proven.
         * `replica_node_path` - The path of the replica node being proven.
         * `replica_root` - The merkle root of the replica.

         * `replica_parents` - A list of all parents in the replica, with their value.
         * `replica_parents_paths` - A list of all parents paths in the replica.

         ----> Private `data_node` - The data node being proven.

         * `data_node_path` - The path of the data node being proven.
         * `data_root` - The merkle root of the data.
         * `replica_id` - The id of the replica.

         * @tparam Hash
         * @tparam Bls12
         */
        template<typename Hash, template<typename> class ConstraintSystem, typename Bls12, typename Fr>
        struct drg_porep_circuit {
            typedef Hash hash_type;

            std::vector<Fr> replica_nodes;
            std::vector<std::vector<std::pair<Fr, std::size_t>>> replica_nodes_paths;
            root<Bls12> replica_root;
            std::vector<std::vector<Fr>> replica_parents;
            std::vector<std::vector<std::vector<std::pair<std::vector<Fr>, std::size_t>>>> replica_parents_paths;
            std::vector<Fr> data_nodes;
            std::vector<std::vector<std::pair<std::vector<Fr>, std::size_t>>> data_nodes_paths;
            root<Bls12> data_root;
            Fr replica_id;
            bool priv;
            crypto3::hash::accumulator_set<Hash> _h;
        };
    }    // namespace filecoin
}    // namespace nil

#endif
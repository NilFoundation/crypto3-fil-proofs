//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nemo@nil.foundation>

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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_DRGRAPH_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_DRGRAPH_HPP

#include <boost/graph/directed_graph.hpp>

#include <nil/crypto3/random/chacha.hpp>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/filecoin/storage/proofs/core/utilities.hpp>
#include <nil/filecoin/storage/proofs/core/parameter_cache.hpp>

#include <nil/filecoin/storage/proofs/core/crypto/domain_seed.hpp>

namespace nil {
    namespace filecoin {
        constexpr static const bool PARALLEL_MERKLE = true;

        /// The base degree used for all DRG graphs. One degree from this value is used to ensure that a
        /// given node always has its immediate predecessor as a parent, thus ensuring unique topological
        /// ordering of the graph nodes.
        constexpr static const std::size_t BASE_DEGREE = 6;

        std::array<std::uint8_t, 28> derive_drg_seed(const std::array<std::uint8_t, 32> &porep_id) {
            std::array<std::uint8_t, 28> drg_seed {};
            std::array<std::uint8_t, 32> raw_seed = derive_porep_domain_seed(DRSAMPLE_DST, porep_id);
            std::copy(raw_seed.begin(), raw_seed.begin() + 28, drg_seed.begin());
            return drg_seed;
        }

        template<std::size_t Arity>
        std::size_t graph_height(std::size_t number_of_leafs) {
            return merkletree::merkle::get_merkle_tree_row_count(number_of_leafs, Arity);
        }

        /// A depth robust graph.
        template<typename Hash, typename KeyType>
        struct Graph {
            typedef KeyType key_type;
            typedef Hash hash_type;

            /// Returns the expected size of all nodes in the graph.
            virtual std::size_t expected_size() const {
                return size() * NODE_SIZE;
            }

            /// Returns the merkle tree depth.
            virtual std::uint64_t merkle_tree_depth() const {
                return graph_height<PoseidonArity>(size());
            }

            /// Returns a sorted list of all parents of this node. The parents may be repeated.
            ///
            /// If a node doesn't have any parents, then this vector needs to return a vector where
            /// the first element is the requested node. This will be used as indicator for nodes
            /// without parents.
            ///
            /// The `parents` parameter is used to store the result. This is done fore performance
            /// reasons, so that the vector can be allocated outside this call.
            virtual void parents(std::size_t node, std::vector<std::uint32_t> &parents) const = 0;

            /// Returns the size of the graph (number of nodes).
            virtual std::size_t size() const = 0;

            /// Returns the number of parents of each node in the graph.
            virtual std::size_t degree() const = 0;

            virtual std::array<std::uint8_t, 28> seed() const = 0;

            /// Creates the encoding key.
            /// The algorithm for that is `Sha256(id | encodedParentNode1 | encodedParentNode1 | ...)`.
            virtual key_type create_key(const typename hash_type::digest_type &id, std::size_t node,
                                        const std::vector<std::uint32_t> &parents,
                                        const std::vector<std::uint8_t> &parents_data,
                                        const std::vector<std::uint8_t> &exp_parents_data) = 0;
        };

        template<typename Hash, typename ParentsHash = crypto3::hashes::sha2<256>>
        struct BucketGraph : public parameter_set_metadata, public Graph<Hash, typename Hash::digest_type> {
            typedef typename Graph<Hash, typename Hash::digest_type>::hash_type hash_type;
            typedef typename Graph<Hash, typename Hash::digest_type>::key_type key_type;

            BucketGraph(size_t nodes, size_t base_degree, size_t expansion_degree,
                        const std::array<uint8_t, 32> &porep_id) :
                nodes(nodes),
                base_degree(base_degree) {
                BOOST_ASSERT_MSG(expansion_degree == 0, "Expansion degree must be zero.");

                // The number of metagraph nodes must be less than `2u64^54` as to not incur rounding errors
                // when casting metagraph node indexes from `std::uint64_t` to `double` during parent generation.
                std::size_t m_prime = base_degree - 1;
                std::size_t n_metagraph_nodes = nodes * m_prime;
                BOOST_ASSERT_MSG(n_metagraph_nodes <= 1ULL << 54,
                                 "The number of metagraph nodes must be precisely castable to `double`");

                seed = derive_drg_seed(porep_id);
            }

            virtual size_t expected_size() const override {
                return Graph<Hash, typename Hash::digest_type>::expected_size();
            }
            virtual uint64_t merkle_tree_depth() const override {
                return Graph<Hash, typename Hash::digest_type>::merkle_tree_depth();
            }
            inline virtual void parents(std::size_t node, std::vector<uint32_t> &parents) const override {
                std::size_t m = degree();

                if (node == 0 || node == 1) {
                    // There are special cases for the first and second node: the first node self
                    // references, the second node only references the first node.
                    // Use the degree of the current graph (`m`) as `parents.len()` might be bigger than
                    // that (that's the case for Stacked Graph).
                    for (auto parent = parents.begin(); parent < parents.begin() + m; ++parent) {
                        *parent = 0;
                    }
                } else {
                    // DRG node indexes are guaranteed to fit within a `u32`.
                    std::array<std::uint8_t, 32> s32;
                    boost::copy(seed, s32);
                    crypto3::detail::pack_to<crypto3::stream_endian::little_octet_big_bit>({node}, seed);
                    crypto3::random::chacha rng(seed);

                    std::size_t m_prime = m - 1;
                    // Large sector sizes require that metagraph node indexes are `u64`.
                    std::size_t metagraph_node = node * m_prime;
                    std::size_t n_buckets = std::ceil(std::log2(static_cast<double>(metagraph_node)));

                    for (typename std::vector<uint32_t>::iterator parent = parents.begin();
                         parent < parents.begin() + m_prime;
                         ++parent) {
                        std::uint64_t bucket_index = (rng() % n_buckets) + 1;
                        std::size_t largest_distance_in_bucket = std::min(metagraph_node, 1UL << bucket_index);
                        std::size_t smallest_distance_in_bucket = std::max(2UL, largest_distance_in_bucket >> 1UL);

                        // Add 1 becuase the number of distances in the bucket is inclusive.
                        std::size_t n_distances_in_bucket =
                            largest_distance_in_bucket - smallest_distance_in_bucket + 1;

                        std::size_t distance = smallest_distance_in_bucket + (rng() % n_distances_in_bucket);

                        std::uint32_t metagraph_parent = metagraph_node - distance;

                        // Any metagraph node mapped onto the DRG can be safely cast back to `u32`.
                        std::uint32_t mapped_parent = (metagraph_parent / m_prime);

                        if (mapped_parent == node) {
                            *parent = node - 1;
                        } else {
                            *parent = mapped_parent;
                        }
                    }

                    parents[m_prime] = node - 1;
                }
            }
            virtual size_t size() const override {
                return 0;
            }
            virtual size_t degree() const override {
                return 0;
            }
            virtual key_type create_key(const typename hash_type::digest_type &id, std::size_t node,
                                        const std::vector<uint32_t> &parents, const std::vector<uint8_t> &parents_data,
                                        const std::vector<uint8_t> &exp_parents_data) override {
                using namespace nil::crypto3;
                accumulator_set<ParentsHash> acc;
                hash<ParentsHash>(id, acc);

                // The hash is about the parents, hence skip if a node doesn't have any parents
                if (node != parents[0]) {
                    for (std::uint32_t parent : parents) {
                        std::size_t offset = data_at_node_offset(parent);
                        hash<ParentsHash>(parents_data.begin(), parents_data.begin() + NODE_SIZE, acc);
                    }
                }

                typename ParentsHash::digest_type hash = accumulators::extract::hash<ParentsHash>(acc);
                return bytes_into_fr_repr_safe(hash);
            }

            virtual std::string identifier() const override {
                return std::string();
            }
            virtual size_t sector_size() const override {
                return nodes * NODE_SIZE;
            }

            std::size_t nodes;
            std::size_t base_degree;
            std::array<std::uint8_t, 28> seed;
        };
    }    // namespace filecoin
}    // namespace nil

#endif

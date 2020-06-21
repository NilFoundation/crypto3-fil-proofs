#ifndef FILECOIN_STORAGE_PROOFS_CORE_POR_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_POR_HPP

#include <nil/filecoin/storage/proofs/core/parameter_cache.hpp>
#include <nil/filecoin/storage/proofs/core/proof/proof.hpp>

namespace nil {
    namespace filecoin {
        template<typename MerkleProofType>
        struct data_proof {
            typedef MerkleProofType proof_type;
            proof_type proof;
        };

        /// The parameters shared between the prover and verifier.
        struct public_params : public parameter_set_metadata {
            virtual std::string identifier() const override {
                return "merklepor::PublicParams{{leaves: {}; private: {}}}" + std::to_string(leaves) +
                       std::to_string(priv);
            }
            virtual size_t sector_size() const override {
                return 0;
            }

            /// How many leaves the underlying merkle tree has.
            std::size_t leaves;
            bool priv;
        };

        template<typename Domain>
        struct public_inputs {
            typedef Domain domain_type;

            domain_type commitment;
            std::size_t challenge;
        };

        template<typename MerkleTreeType>
        struct private_inputs {
            typedef MerkleTreeType tree_type;

            typename tree_type::hash_type::domain_type leaf;
            tree_type tree;
        };

        struct setup_params {
            std::size_t leaves;
            bool priv;
        };

        template<typename MerkleTreeType>
        struct por {
            typedef MerkleTreeType tree_type;

            tree_type &_tree;
        };

        template<typename MerkleTreeType>
        class por_proof_scheme
            : public proof_scheme<
                  public_params, setup_params, public_inputs<typename MerkleTreeType::hash_type::domain_type>,
                  private_inputs<MerkleTreeType>, data_proof<typename MerkleTreeType::proof_type>, no_requirements> {
            typedef proof_scheme<
                public_params, setup_params, public_inputs<typename MerkleTreeType::hash_type::domain_type>,
                private_inputs<MerkleTreeType>, data_proof<typename MerkleTreeType::proof_type>, no_requirements>
                policy_type;

        public:
            typedef typename policy_type::public_params_type public_params_type;
            typedef typename policy_type::setup_params_type setup_params_type;
            typedef typename policy_type::public_inputs_type public_inputs_type;
            typedef typename policy_type::private_inputs_type private_inputs_type;
            typedef typename policy_type::proof_type proof_type;

            typedef typename private_inputs_type::tree_type tree_type;

            virtual public_params setup(const setup_params_type &p) override {
                return {p.leaves, p.priv};
            }
            virtual proof_type prove(const public_params_type &params, const public_inputs_type &inputs,
                                     const private_inputs_type &pinputs) override {
                std::size_t challenge = inputs.challenge % params.leaves;
                tree_type tree = pinputs.tree;

                if (inputs.commitmenr != tree.root()) {
                    return false;
                }

                auto proof = tree.gen_proof(challenge);
                return {proof, pinputs.leaf};
            }
            virtual bool verify(const public_params_type &pub_params, const public_inputs_type &pub_inputs,
                                const proof_type &pr) override {
                // This was verify_proof_meta.
                bool commitments_match = pub_inputs.commitment ? pub_inputs.commitment == pr.proof.root() : true;

                std::size_t expected_path_length = pr.proof.expected_len(pub_params.leaves);
                bool path_length_match = expected_path_length == pr.proof.path().len();

                if (!commitments_match && path_length_match) {
                    return false;
                }
                bool data_valid = pr.proof.validate_data(pr.data);
                bool path_valid = pr.proof.validate(pub_inputs.challenge);

                return data_valid && path_valid;
            }
        };
    }    // namespace filecoin
}    // namespace nil

#endif
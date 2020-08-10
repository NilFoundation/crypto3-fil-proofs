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

#ifndef FILECOIN_STORAGE_PROOFS_POST_ELECTION_VANILLA_HPP
#define FILECOIN_STORAGE_PROOFS_POST_ELECTION_VANILLA_HPP

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/filecoin/storage/proofs/core/merkle/proof.hpp>
#include <nil/filecoin/storage/proofs/core/btree/map.hpp>
#include <nil/filecoin/storage/proofs/core/parameter_cache.hpp>
#include <nil/filecoin/storage/proofs/core/sector.hpp>

namespace nil {
    namespace filecoin {
        namespace post {
            namespace election {
                struct SetupParams {
                    /// Size of the sector in bytes.
                    std::uint64_t sector_size;
                    std::size_t challenge_count;
                    std::size_t challenged_nodes;
                };

                struct PublicParams : public parameter_set_metadata {
                    virtual std::string identifier() const override {
                        return "ElectionPoSt::PublicParams{{sector_size: " + sector_size() +
                               ", count: " + challenge_count + ", nodes: " + challenged_nodes + "}}";
                    }
                    virtual size_t sector_size() const override {
                        return ssize;
                    }

                    /// Size of the sector in bytes.
                    std::uint64_t ssize;
                    std::size_t challenge_count;
                    std::size_t challenged_nodes;
                };

                template<typename Domain>
                struct PublicInputs {
                    Domain randomness;
                    sector_id_type sector_id;
                    Domain prover_id;
                    Domain comm_r;
                    Fr partial_ticket;
                    std::uint64_t sector_challenge_index;
                };

                template<typename MerkleTreeType>
                struct PrivateInputs {
                    MerkleTreeWrapper<MerkleTreeType::Hasher, MerkleTreeType::Store, MerkleTreeType::Arity,
                                      MerkleTreeType::SubTreeArity, MerkleTreeType::TopTreeArity>
                        tree;
                    typename MerkleTreeType::hash_type::digest_type comm_c;
                    typename MerkleTreeType::hash_type::digest_type comm_r_last;
                };

                struct Candidate {
                    sector_id_type sector_id;
                    Fr partial_ticket;
                    std::array<std::uint8_t, 32> ticket;
                    std::uint64_t sector_challenge_index;
                };

                template<typename MerkleProofTrait>
                struct Proof {
                    std::vector<typename MerkleProofTrait::hash_type::digest_type> leafs() {
                        return inclusion_proofs.iter().map(MerkleProof::leaf).collect();
                    }

                    typename MerkleProofTrait::hash_type::digest_type comm_r_last() {
                        return inclusion_proofs[0].root();
                    }

                    std::vector<typename MerkleProofTrait::hash_type::digest_type> commitments() {
                        return inclusion_proofs.iter().map(MerkleProof::root).collect();
                    }

                    std::vector<std::vector<
                        std::pair<std::vector<typename MerkleProofTrait::hash_type::digest_type>, std::size_t>>>
                        paths() {
                        return inclusion_proofs.iter().map(MerkleProof::path).collect();
                    }

                    std::vector<MerkleProof<typename MerkleProofTrait::hash, MerkleProofTrait::BaseArity,
                                            MerkleProofTrait::SubTreeArity, MerkleProofTrait::TopTreeArity>>
                        inclusion_proofs;

                    std::array<std::uint8_t, 32> ticket;
                    typename MerkleProofTrait::hash_type::digest_type comm_c;
                };

                template<typename MerkleTreeType>
                class ElectionPoSt
                    : public proof_scheme<
                          PublicParams, SetupParams, PublicInputs<typename MerkleTreeType::hash_type::digest_type>,
                          PrivateInputs<MerkleTreeType>, Proof<typename MerkleTreeType::proof_type>, no_requirements> {
                    typedef proof_scheme<
                        PublicParams, SetupParams, PublicInputs<typename MerkleTreeType::hash_type::digest_type>,
                        PrivateInputs<MerkleTreeType>, Proof<typename MerkleTreeType::proof_type>, no_requirements>
                        policy_type;

                public:
                    typedef typename policy_type::public_params_type public_params_type;
                    typedef typename policy_type::setup_params setup_params_type;
                    typedef typename policy_type::public_inputs public_inputs_type;
                    typedef typename policy_type::private_inputs private_inputs_type;
                    typedef typename policy_type::proof_type proof_type;
                    typedef typename policy_type::requirements_type requirements_type;

                    virtual public_params_type setup(const setup_params_type &p) override {
                        return {p.sector_size, p.challenge_count, p.challenged_nodes};
                    }
                    virtual proof_type prove(const public_params_type &params, const public_inputs_type &inputs,
                                             const private_inputs_type &pinputs) override {
                        // 1. Inclusions proofs of all challenged leafs in all challenged ranges
                        auto tree = pinputs.tree;
                        std::size_t tree_leafs = tree.leafs();

                        trace !("Generating proof for tree of len {} with leafs {}", tree.len(), tree_leafs, );

                        let inclusion_proofs = measure_op(
                            Operation::PostInclusionProofs,
                            || {(0..pub_params.challenge_count)
                                    .into_par_iter()
                                    .flat_map(
                                        | n |
                                        {
                                            // TODO: replace unwrap with proper error handling
                                            let challenged_leaf_start =
                                                generate_leaf_challenge(pub_params, pub_inputs.randomness,
                                                                        pub_inputs.sector_challenge_index, n as u64, )
                                                    ;
                                            (0..pub_params.challenged_nodes)
                                                .into_par_iter()
                                                .map(move | i |
                                                     {tree.gen_cached_proof(challenged_leaf_start as usize + i, None)})
                                        })
                                    .collect::<Result<Vec<_>>>()});

                        // 2. correct generation of the ticket from the partial_ticket (add this to the candidate)
                        let ticket =
                            measure_op(Operation::PostFinalizeTicket, || {finalize_ticket(&pub_inputs.partial_ticket)});

                        return {inclusion_proofs, ticket, pinputs.comm_c};
                    }
                    virtual bool verify(const public_params_type &pub_params, const public_inputs_type &pub_inputs,
                                        const proof_type &pr) override {
                        // verify that H(Comm_c || Comm_r_last) == Comm_R
                        // comm_r_last is the root of the proof
                        let comm_r_last = pr.inclusion_proofs[0].root();
                        let comm_c = pr.comm_c;
                        let comm_r = &pub_inputs.comm_r;

                        if (AsRef ::<[u8]>::as_ref(&<Tree::Hasher as Hasher>::Function::hash2(
                                &comm_c, &comm_r_last, )) != AsRef::<[u8]>::as_ref(comm_r)) {
                            return false;
                        }

                        for (int n = 0; n < pub_params.challenge_count; n++) {
                            let challenged_leaf_start = generate_leaf_challenge(pub_params, pub_inputs.randomness,
                                                                                pub_inputs.sector_challenge_index, n);
                            for (int i = 0; i < pub_params.challenged_nodes; i++) {
                                let merkle_proof = &proof.inclusion_proofs[n * pub_params.challenged_nodes + i];

                                // validate all comm_r_lasts match
                                if (merkle_proof.root() != comm_r_last) {
                                    return false;
                                }

                                // validate the path length
                                let expected_path_length =
                                    merkle_proof.expected_len(pub_params.sector_size / NODE_SIZE);

                                if (expected_path_length != merkle_proof.path().size()) {
                                    return false;
                                }

                                if (!merkle_proof.validate(challenged_leaf_start + i)) {
                                    return false;
                                }
                            }
                        }

                        return true;
                    }
                };

                template<typename MerkleTreeType>
                std::vector<Candidate> generate_candidates(
                    const PublicParams &pub_params, const std::vector<sector_id_type> &challenged_sectors,
                    const btree::map<sector_id_type,
                                     MerkleTreeWrapper<typename MerkleTreeType::hash_type,
                                                       typename MerkleTreeType::store_type, MerkleTreeType::BaseArity,
                                                       MerkleTreeType::SubTreeArity, MerkleTreeType::TopTreeArity>>
                        &trees,
                    const typename MerkleTreeType::hash_type::digest_type &prover_id,
                    const typename MerkleTreeType::hash_type::digest_type &randomness) {
                    challenged_sectors.par_iter()
                        .enumerate()
                        .map(| (sector_challenge_index, sector_id) |
                             {
                                 let tree = match trees.get(sector_id) {
                                     Some(tree) = > tree,
                                     None = > bail !(Error::MissingPrivateInput("tree", (*sector_id).into())),
                                 };

                                 generate_candidate::<Tree>(pub_params, tree, prover_id, *sector_id, randomness,
                                                            sector_challenge_index as u64, )
                             })
                        .collect()
                }

                template<typename MerkleTreeType>
                Candidate generate_candidate(
                    const PublicParams &pub_params,
                    const MerkleTreeWrapper<typename MerkleTreeType::hash_type, typename MerkleTreeType::store_type,
                                            MerkleTreeType::BaseArity, MerkleTreeType::SubTreeArity,
                                            MerkleTreeType::TopTreeArity> &tree,
                    const typename MerkleTreeType::hash_type::digest_type &prover_id, sector_id_type sector_id,
                    const typename MerkleTreeType::hash_type::digest_type &randomness,
                    std::uint64_t sector_challenge_index) {
                    Fr randomness_fr = randomness.into();
                    Fr prover_id_fr = prover_id.into();
                    std::vector<PoseidonDomain> data = {randomness_fr.into(), prover_id_fr.into(),
                                                        Fr::from(sector_id).into()};

                    for (int n = 0; n < pub_params.challenge_count; n++) {
                        auto challenge = generate_leaf_challenge(pub_params, randomness, sector_challenge_index, n);

                        Fr val = measure_op(Operation::PostReadChallengedRange, || {tree.read_at(challenge as usize)})
                                     .into();
                        data.push_back(val.into());
                    }

                    // pad for md
                    std::size_t arity = PoseidonMDArity;
                    while (data.size() % arity) {
                        data.push(PoseidonDomain::default());
                    }

                    Fr partial_ticket =
                        measure_op(Operation::PostPartialTicketHash, || {PoseidonFunction::hash_md(&data)}).into();

                    // ticket = sha256(partial_ticket)
                    std::array<std::uint8_t, 32> ticket = finalize_ticket(&partial_ticket);

                    return {sector_challenge_index, sector_id, partial_ticket, ticket};
                }

                template<typename FinalizationHash = crypto3::hashes::sha2<256>>
                std::array<std::uint8_t, 32> finalize_ticket(const Fr &partial_ticket) {
                    let bytes = fr_into_bytes(partial_ticket);
                    let ticket_hash = Sha256::digest(&bytes);
                    std::array<std::uint8_t, 32> ticket;
                    ticket.fill(0);
                    ticket.copy_from_slice(&ticket_hash[..]);
                    return ticket;
                }

                bool is_valid_sector_challenge_index(std::uint64_t challenge_count, std::uint64_t index) {
                    return index < challenge_count;
                }

                template<typename Domain>
                std::vector<sector_id_type> generate_sector_challenges(const Domain &randomness,
                                                                       std::uint64_t challenge_count,
                                                                       const ordered_sector_set &sectors) {
                    (0..challenge_count)
                        .into_par_iter()
                        .map(| n | generate_sector_challenge(randomness, n as usize, sectors))
                        .collect();
                }

                template<typename Domain, typename FinalizationHash = crypto3::hashes::sha2<256>>
                sector_id_type generate_sector_challenge(const Domain &randomness, std::size_t n,
                                                         const ordered_sector_set &sectors) {
                    let mut hasher = Sha256::new ();
                    hasher.input(AsRef::<[u8]>::as_ref(&randomness));
                    hasher.input(&n.to_le_bytes()[..]);
                    let hash = hasher.result();

                    let sector_challenge = LittleEndian::read_u64(&hash.as_ref()[..8]);
                    let sector_index = (sector_challenge % sectors.len() as u64) as usize;
                    let sector = *sectors.iter().nth(sector_index).context("invalid challenge generated") ? ;

                    return sector;
                }

                /// Generate all challenged leaf ranges for a single sector, such that the range fits into the sector.
                template<typename Domain>
                std::vector<std::uint64_t>
                    generate_leaf_challenges(const PublicParams &pub_params, const Domain &randomness,
                                             std::uint64_t sector_challenge_index, std::size_t challenge_count) {
                    std::vector<std::uint64_t> challenges(challenge_count);

                    for (int leaf_challenge_index = 0; leaf_challenge_index < challenge_count; leaf_challenge_index++) {
                        challenges.emplace_back(generate_leaf_challenge(pub_params, randomness, sector_challenge_index,
                                                                        leaf_challenge_index));
                    }

                    return challenges;
                }

                /// Generates challenge, such that the range fits into the sector.
                template<typename Domain, typename LeafHash = crypto3::hashes::sha2<256>>
                std::uint64_t generate_leaf_challenge(const PublicParams &pub_params, const Domain &randomness,
                                                      std::uint64_t sector_challenge_index,
                                                      std::uint64_t leaf_challenge_index) {
                    assert(
                        ("sector size is too small", pub_params.sector_size > pub_params.challenged_nodes * NODE_SIZE));

                    let mut hasher = Sha256::new ();
                    hasher.input(AsRef::<[u8]>::as_ref(&randomness));
                    hasher.input(&sector_challenge_index.to_le_bytes()[..]);
                    hasher.input(&leaf_challenge_index.to_le_bytes()[..]);
                    let hash = hasher.result();

                    let leaf_challenge = LittleEndian::read_u64(&hash.as_ref()[..8]);

                    std::uint64_t challenged_range_index =
                        leaf_challenge % (pub_params.sector_size / (pub_params.challenged_nodes * NODE_SIZE));

                    return challenged_range_index * pub_params.challenged_nodes;
                }
            }    // namespace election
        }        // namespace post
    }            // namespace filecoin
}    // namespace nil

#endif
#ifndef FILECOIN_STORAGE_PROOFS_CORE_MULTI_PROOF_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_MULTI_PROOF_HPP

#include <vector>

namespace filecoin {
    template<template<typename> class Groth16Proof, template<typename> class Groth16VerifyingKey, typename Bls12>
    struct multi_proof {
        std::vector<Groth16Proof<Bls12>> circuit_proofs;
        std::vector<Groth16VerifyingKey<Bls12>> verifying_key;

        multi_proof(const Groth16Proof<Bls12> &proof, const Groth16VerifyingKey<Bls12> &key) :
            circuit_proofs(proof), verifying_key(key) {
        }

        std::size_t size() {
            return circuit_proofs.size();
        }

        bool empty() {
            return circuit_proofs.empty();
        }
    };
}    // namespace filecoin

#endif
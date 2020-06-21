#ifndef FILECOIN_STORAGE_PROOFS_POREP_STACKED_CIRCUIT_HPP
#define FILECOIN_STORAGE_PROOFS_POREP_STACKED_CIRCUIT_HPP

namespace filecoin {
    struct column {
        std::vector<Fr> rows;
    };

    template<template<typename> class AllocatedNum, typename Bls12>
    struct allocated_column {
        std::vector<AllocatedNum<Bls12>> rows;
    };
}    // namespace filecoin

#endif
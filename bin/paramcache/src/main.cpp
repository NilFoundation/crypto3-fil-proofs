//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the Server Side Public License, version 1,
// as published by the author.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// Server Side Public License for more details.
//
// You should have received a copy of the Server Side Public License
// along with this program. If not, see
// <https://github.com/NilFoundation/dbms/blob/master/LICENSE_1_0.txt>.
//---------------------------------------------------------------------------//

#include <array>
#include <fstream>
#include <iostream>

constexpr static const std::array<std::uint64_t, 10> PUBLISHED_SECTOR_SIZES = {
    SECTOR_SIZE_2_KIB,  SECTOR_SIZE_4_KIB,   SECTOR_SIZE_16_KIB, SECTOR_SIZE_32_KIB, SECTOR_SIZE_8_MIB,
    SECTOR_SIZE_16_MIB, SECTOR_SIZE_512_MIB, SECTOR_SIZE_1_GIB,  SECTOR_SIZE_32_GIB, SECTOR_SIZE_64_GIB};

template<typename MerkleTreeType>
void cache_porep_params(const porep_config &conig) {
    info !("PoRep params");

    let public_params = public_params(PaddedBytesAmount::from(porep_config),
                                      usize::from(PoRepProofPartitions::from(porep_config)), porep_config.porep_id, )
                            .unwrap();

    {
        let circuit = <StackedCompound<Tree, DefaultPieceHasher>
                           as CompoundProof<StackedDrg<Tree, DefaultPieceHasher>, _, >>::blank_circuit(&public_params);
        let _ = StackedCompound::<Tree, DefaultPieceHasher>::get_param_metadata(circuit, &public_params, );
    }
    {
        let circuit = <StackedCompound<Tree, DefaultPieceHasher>
                           as CompoundProof<StackedDrg<Tree, DefaultPieceHasher>, _, >>::blank_circuit(&public_params);
        StackedCompound::<Tree, DefaultPieceHasher>::get_groth_params(Some(&mut OsRng), circuit, &public_params, )
            .expect("failed to get groth params");
    }
    {
        let circuit = <StackedCompound<Tree, DefaultPieceHasher>
                           as CompoundProof<StackedDrg<Tree, DefaultPieceHasher>, _, >>::blank_circuit(&public_params);

        StackedCompound::<Tree, DefaultPieceHasher>::get_verifying_key(Some(&mut OsRng), circuit, &public_params, )
            .expect("failed to get verifying key");
    }
}

template<typename MerkleTreeType>
void cache_winning_post_params(const post_config &config) {
    info !("Winning PoSt params");

    let post_public_params = winning_post_public_params::<Tree>(post_config).unwrap();

    {
        let post_circuit
            : FallbackPoStCircuit<Tree> =
                  <FallbackPoStCompound<Tree> as CompoundProof<FallbackPoSt<Tree>, FallbackPoStCircuit<Tree>, >>::
                      blank_circuit(&post_public_params);
        let _ = <FallbackPoStCompound<Tree>>::get_param_metadata(post_circuit, &post_public_params)
                    .expect("failed to get metadata");
    }
    {
        let post_circuit
            : FallbackPoStCircuit<Tree> =
                  <FallbackPoStCompound<Tree> as CompoundProof<FallbackPoSt<Tree>, FallbackPoStCircuit<Tree>, >>::
                      blank_circuit(&post_public_params);
        <FallbackPoStCompound<Tree>>::get_groth_params(Some(&mut OsRng), post_circuit, &post_public_params, )
            .expect("failed to get groth params");
    }
    {
        let post_circuit
            : FallbackPoStCircuit<Tree> =
                  <FallbackPoStCompound<Tree> as CompoundProof<FallbackPoSt<Tree>, FallbackPoStCircuit<Tree>, >>::
                      blank_circuit(&post_public_params);

        <FallbackPoStCompound<Tree>>::get_verifying_key(Some(&mut OsRng), post_circuit, &post_public_params, )
            .expect("failed to get verifying key");
    }
}

template<typename MerkleTreeType>
void cache_window_post_params(const post_config &config) {
    info !("Window PoSt params");

    let post_public_params = window_post_public_params<MerkleTreeType>(config).unwrap();

    {
        FallbackPoStCircuit<MerkleTreeType> post_circuit = <FallbackPoStCompound<MerkleTreeType> as CompoundProof<
            FallbackPoSt<MerkleTreeType>, FallbackPoStCircuit<MerkleTreeType>>>::blank_circuit(post_public_params);
        let _ = <FallbackPoStCompound<MerkleTreeType>>::get_param_metadata(post_circuit, post_public_params)
                    .expect("failed to get metadata");
    }
    {
        FallbackPoStCircuit<MerkleTreeType> post_circuit = <FallbackPoStCompound<MerkleTreeType> as CompoundProof<
            FallbackPoSt<Tree>, FallbackPoStCircuit<MerkleTreeType>>>::blank_circuit(post_public_params);
        <FallbackPoStCompound<MerkleTreeType>>::get_groth_params(Some(&mut OsRng), post_circuit, post_public_params)
            .expect("failed to get groth params");
    }
    {
        FallbackPoStCircuit<MerkleTreeType> post_circuit = <FallbackPoStCompound<MerkleTreeType> as CompoundProof<
            FallbackPoSt<Tree>, FallbackPoStCircuit<MerkleTreeType>>>::blank_circuit(post_public_params);

        <FallbackPoStCompound<MerkleTreeType>>::get_verifying_key(Some(&mut OsRng), post_circuit, post_public_params)
            .expect("failed to get verifying key");
    }
}

/// Generate and persist Groth parameters and verifying keys for filecoin-proofs.
struct Opt {
    /// Only generate parameters for post.
    bool only_post;
    std::vector<std::uint64_t> params_for_sector_sizes;
};

void generate_params_post(std::uint64_t sector_size) {
    with_shape !(sector_size, cache_winning_post_params, &PoStConfig {
        sector_size : SectorSize(sector_size),
        challenge_count : WINNING_POST_CHALLENGE_COUNT,
        sector_count : WINNING_POST_SECTOR_COUNT,
        typ : PoStType::Winning,
        priority : true,
    });

    with_shape !(sector_size, cache_window_post_params, &PoStConfig {
        sector_size : SectorSize(sector_size),
        challenge_count : WINDOW_POST_CHALLENGE_COUNT,
        sector_count : *WINDOW_POST_SECTOR_COUNT.read().unwrap().get(&sector_size).unwrap(),
        typ : PoStType::Window,
        priority : true,
    });
}

void generate_params_porep(std::uint64_t sector_size) {
    with_shape !(
        sector_size, cache_porep_params, PoRepConfig {
            sector_size:
                SectorSize(sector_size),
                    partitions
                    : PoRepProofPartitions(
                          *POREP_PARTITIONS.read().unwrap().get(&sector_size).expect("missing sector size"), ),
                      porep_id : [0; 32],
        });
}

int main(int argc, char *argv[]) {
    // The logger is used and every message from this tool is also logged into those logs.
    // Though the information is also printed to stdout, so that users who haven't set the
    // `RUST_LOG` environment variable also see warngings/progress.
    fil_logger::init();

    let opts = Opt::from_args();

    // Display interactive menu if no sizes are given
    std::vector<std::uint64_t> sizes;
    if (opts.params_for_sector_sizes.is_empty()) {
        let sector_sizes = PUBLISHED_SECTOR_SIZES.iter()
                               .map(| sector_size |
                                    {// Right aligning the numbers makes them easier to read
                                     format !("{: >7}", sector_size.file_size(file_size_opts::BINARY).unwrap(), )})
                               .collect::<Vec<_>>();

        let selected_sector_sizes =
            MultiSelect::with_theme(&ColorfulTheme::default())
                .with_prompt(
                    "Select the sizes that should be generated if not already cached [use space key to select]")
                .items(&sector_sizes[..])
                .interact()
                .unwrap();

        // Extract the selected sizes
        sizes = PUBLISHED_SECTOR_SIZES.iter()
                    .enumerate()
                    .filter_map(| (index, size) |
                                {
                                    if (selected_sector_sizes.contains(&index)) {
                                        Some(*size)
                                    } else {
                                        None
                                    }
                                })
                    .collect();
    } else {
        sizes = opts.params_for_sector_sizes.into_iter()
                    .filter(| size |
                            {
                                if (PUBLISHED_SECTOR_SIZES.contains(size)) {
                                    return true;
                                }
                                warn !("ignoring invalid sector size: {}", size);
                                println !("ignoring invalid sector size: {}", size);
                                return false;
                            })
                    .collect();
    };

    if (sizes.is_empty()) {
        info !("No valid sector sizes given. Abort.");
        println !("No valid sector sizes given. Abort.");
    }

    let only_post = opts.only_post;

    for (std::uint64_t sector_size : sizes) {
        let human_size = sector_size.file_size(file_size_opts::BINARY).unwrap();
        let message = format !("Generating sector size: {}", human_size);
        info !("{}", &message);

        let spinner = ProgressBar::new_spinner();
        spinner.set_message(&message);
        spinner.enable_steady_tick(100);

        generate_params_post(sector_size);

        if (!only_post) {
            generate_params_porep(sector_size);
        }
        spinner.finish_with_message(&format !("✔ {}", &message));
    }
}
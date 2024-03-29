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

/// A CLI program for running Phase2 of Filecoin's trusted-setup.
///
/// # Build
///
/// From the directory `rust-fil-proofs` run:
///
/// ```
/// $ RUSTFLAGS="-C target-cpu=native" cargo build --release -p filecoin-proofs --bin=phase2
/// ```
///
/// # Usage
///
/// ```
/// # Create initial params for a circuit using:
/// $ RUST_BACKTRACE=1 ./target/release/phase2 new \
///     <--porep, --epost, --fpost> \
///     [--poseidon (default), --sha-pedersen] \
///     <--2kib, --8mib, --512mib, --32gib, --64gib>
///
/// # Contribute randomness to the phase2 params for a circuit:
/// $ RUST_BACKTRACE=1 ./target/release/phase2 contribute <path to params file>
///
/// # Verify the transition from one phase2 params file to another:
/// $ RUST_BACKTRACE=1 ./target/release/phase2 verify \
///     --paths=<comma separated list of file paths to params> \
///     --contributions=<comma separated list of contribution digests>
///
/// # Run verification as a daemon - verify the parameters and contributions as they are written to
/// # the `rust-fil-proofs` directory:
/// $ RUST_BACKTRACE=1 ./target/release/phase2 verifyd
/// ```

#include <array>

constexpr static const char *ERROR_IPFS_COMMAND = "failed to run ipfs";
constexpr static const char *ERROR_IPFS_PUBLISH = "failed to publish via ipfs";
constexpr static const std::array<std::uint64_t, 5> PUBLISH_SECTOR_SIZES = {
    SECTOR_SIZE_2_KIB, SECTOR_SIZE_8_MIB, SECTOR_SIZE_512_MIB, SECTOR_SIZE_32_GIB, SECTOR_SIZE_64_GIB};

void publish(ArgMatches &matches) {
    let ipfs_bin_path = matches.value_of("ipfs-bin").unwrap_or("ipfs");

    // Get all valid parameter IDs which have all three files, `.meta`, `.params and `.vk`
    // associated with them. If one of the files is missing, it won't show up in the selection.
    let(mut parameter_ids, counter) = get_filenames_in_cache_dir() ?
        .iter()
        .filter(| f |
                {has_extension(f, GROTH_PARAMETER_EXT) || has_extension(f, VERIFYING_KEY_EXT) ||
                 has_extension(f, PARAMETER_METADATA_EXT)})
        .sorted()
        // Make sure there are always three files per parameter ID
        .fold((Vec::new (), 0), | (mut result, mut counter)
              : (std::vec::Vec<String>, u8), filename | {
                  let parameter_id = filename_to_parameter_id(&filename);
                  // Check if previous file had the same parameter ID
                  if
                      !result.is_empty() && &parameter_id == result.last() {
                          counter += 1;
                      }
                  else {
                      // There weren't three files for the same parameter ID, hence remove it from
                      // the list
                      if counter
                          < 3 {
                              result.pop();
                          }

                      // It's a new parameter ID, hence reset the counter and add it to the list
                      counter = 1;
                      result.push(parameter_id);
                  }

                  (result, counter)
              }, );

    // There might be lef-overs from the last fold iterations
    if (counter < 3) {
        parameter_ids.pop();
    }

    if (parameter_ids.is_empty()) {
        println !("No valid parameters in directory {:?} found.", parameter_cache_dir());
        std::process::exit(1)
    }

    // build a mapping from parameter id to metadata
    let meta_map = parameter_id_to_metadata_map(parameter_ids);

    let filenames;
    if (!matches.is_present("all")) {
        let tmp_filenames = meta_map.keys()
                                .flat_map(| parameter_id | {vec ![
                                              add_extension(parameter_id, GROTH_PARAMETER_EXT),
                                              add_extension(parameter_id, VERIFYING_KEY_EXT),
                                          ]})
                                .collect_vec();
        filenames =
            choose_from(&tmp_filenames, | filename |
                                            {filename_to_parameter_id(PathBuf::from(filename))
                                                 .as_ref()
                                                 .and_then(| p_id | meta_map.get(p_id).map(| x | x.sector_size))});
    } else {
        // `--all` let's you select a specific version
        std::vector<std::string> versions =
            meta_map
                .keys()
                // Split off the version of the parameters
                .map(| parameter_id | parameter_id.split('-').next().to_string())
                // Sort by descending order, newest parameter first
                .sorted_by(| a, b | Ord::cmp(&b, &a))
                .dedup()
                .collect();
        let selected_version = Select::with_theme(&ColorfulTheme::default())
                                   .with_prompt("Select a version (press 'q' to quit)")
                                   .default(0)
                                   .items(&versions[..])
                                   .interact_opt()
                                   ;
        let version = match selected_version {Some(index) = > &versions[index], None = > {println !("Aborted.");
        std::process::exit(1)
    }
};

// The parameter IDs that should bet published
let mut parameter_ids = meta_map
                            .keys()
                            // Filter out all that don't match the selected version
                            .filter(| parameter_id | parameter_id.starts_with(version))
                            .collect_vec();

// Display the sector sizes
let sector_sizes_iter =
    parameter_ids
        .iter()
        // Get sector size and parameter ID
        .map(| &parameter_id | {meta_map.get(parameter_id).map(| x | (x.sector_size, parameter_id))})
        // Sort it ascending by sector size
        .sorted_by(| a, b | Ord::cmp(&a .0, &b .0));

// The parameters IDs need to be sorted the same way as the menu we display, else
// the selected items won't match the list we select from
parameter_ids = sector_sizes_iter.clone().map(| (_, parameter_id) | parameter_id).collect_vec();

let sector_sizes =
    sector_sizes_iter
        .clone()
        // Format them
        .map(| (sector_size, parameter_id) |
             {format !("({:?}) {:?}", sector_size.file_size(file_size_opts::BINARY), parameter_id)})
        .collect_vec();
// Set the default, pre-selected sizes
let default_sector_sizes =
    sector_sizes_iter.map(| (sector_size, _) | PUBLISH_SECTOR_SIZES.contains(&sector_size)).collect_vec();
let selected_sector_sizes = MultiSelect::with_theme(&ColorfulTheme::default())
                                .with_prompt("Select the sizes to publish")
                                .items(&sector_sizes[..])
                                .defaults(&default_sector_sizes)
                                .interact()
                                ;

if (selected_sector_sizes.empty()) {
    println !("Nothing selected. Abort.");
} else {
    // Filter out the selected ones
    parameter_ids = parameter_ids.into_iter()
                        .enumerate()
                        .filter_map(| (index, parameter_id) |
                                    {
                                        if selected_sector_sizes
                                            .contains(&index) {
                                                Some(parameter_id)
                                            }
                                        else {
                                            None
                                        }
                                    })
                        .collect_vec();
}

// Generate filenames based on their parameter IDs
parameter_ids.iter()
    .flat_map(| parameter_id | {vec ![
                  add_extension(parameter_id, GROTH_PARAMETER_EXT),
                  add_extension(parameter_id, VERIFYING_KEY_EXT),
              ]})
    .collect_vec()
}
;
println !();

let json = PathBuf::from(matches.value_of("json").unwrap_or("./parameters.json"));
ParameterMap parameter_map;

if (!filenames.is_empty()) {
    println !("publishing {} files...", filenames.len());
    println !();

    for (filename : filenames) {
        let id = filename_to_parameter_id(&filename).with_context(
            || format !("failed to parse id from file name {}", filename)) ?
            ;

        CacheEntryMetadata &meta =
            meta_map.get(&id).with_context(|| format !("no metadata found for parameter id {}", id));

        println !("publishing: {}", filename);
        print !("publishing to ipfs... ");
        io::stdout().flush();

        match publish_parameter_file(&ipfs_bin_path, &filename) {Ok(cid) = > {println !("ok");
        print !("generating digest... ");
        io::stdout().flush();

        let digest = get_digest_for_file_within_cache(&filename);
        let data = ParameterData {
            cid,
            digest,
            sector_size : meta.sector_size,
        };

        parameter_map.insert(filename, data);

        println !("ok");
    }
    Err(err) = > println !("error: {}", err),
}

println !();
}

write_parameter_map_to_disk(&parameter_map, &json) ? ;
}
else {
    println !("no files to publish");
}
}

std::vector<std::string> get_filenames_in_cache_dir() {
    let path = parameter_cache_dir();

    if path
        .exists() {
    Ok(read_dir(path)?
        .map(|f| f.path())
    .filter(|p| p.is_file())
    .map(|p| {
        p.as_path()
            .file_name()

            .to_str()

            .to_string()
    })
    .collect())
        }
    else {
        println !("parameter directory '{}' does not exist", path.as_path().to_str());

        Ok(Vec::new ())
    }
}

std::string publish_parameter_file(const std::string &ipfs_bin_path, const std::string &filename) {
    let path = get_full_path_for_file_within_cache(filename);

    let output = Command::new (ipfs_bin_path).arg("add").arg("-Q").arg(&path).output().expect(ERROR_IPFS_COMMAND);

    ensure !(output.status.success(), ERROR_IPFS_PUBLISH);

Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

template<typename PathType>
void write_parameter_map_to_disk(const ParameterMap &parameter_map, const PathType &dest_path) {
    let p : &Path = dest_path.as_ref();
    let file = File::create(p) ? ;
    let writer = BufWriter::new (file);
    serde_json::to_writer_pretty(writer, &parameter_map) ? ;

    Ok(())
}

int main(int argc, char *argv[]) {
    fil_logger::init();

    let matches =
        App::new ("parampublish")
            .version("1.0")
            .about(&format !("
                             Set $FIL_PROOFS_PARAMETER_CACHE to specify parameter directory.Defaults to '{}' ",
                             PARAMETER_CACHE_DIR)[..], )
            .arg(Arg::with_name("json").value_name("JSON").takes_value(true).short("j").long("json").help(
                     "Use specific json file"), )
            .arg(Arg::with_name("all").short("a").long("all").help(
                     "Publish all local Groth parameters and verifying keys"), )
            .arg(Arg::with_name("ipfs-bin")
                     .takes_value(true)
                     .short("i")
                     .long("ipfs-bin")
                     .help("Use specific ipfs binary instead of searching for one in $PATH"), )
            .get_matches();

    match publish(&matches) {
        Ok(_) = > println !("done"), Err(err) = > {
            println !("fatal error: {}", err);
            exit(1);
        }
    }

    return 0;
}
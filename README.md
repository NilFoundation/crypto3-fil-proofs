# =nil; Crypto3 C++ Filecoin Proving Subsystem

This repository contains =nil; Crypto3's C++ Filecoin Proofs implementation. In particular it replaces:

1. [rust-fil-proofs](https://github.com/filecoin-project/rust-fil-proofs.git)
2. [bellperson](https://github.com/filecoin-project/bellperson.git)
3. [rust-filecoin-proofs-api](https://github.com/filecoin-project/rust-filecoin-proofs-api.git)
4. [filecoin-ffi](https://github.com/filecoin-project/filecoin-ffi.git)'s Rust-based part.

## Documentation

Project documentation, circuit definitions, API references etc can be found at
https://filecoin.nil.foundation/projects/prover.

## Dependencies

Libraries requirements are as follows:
* Boost (https://boost.org) (>= 1.76)

Compiler/environment requirements are as follows:
* CMake (https://cmake.org) (>= 3.13)
* GCC (>= 10.3) / Clang (>= 9.0.0) / AppleClang (>= 11.0.0)

## Building

`mkdir build && cd build && cmake .. && make aux-proof-gen`

## Usage

## Community

Issue reports are preferred to be done with Github Issues in here:
https://github.com/nilfoundation/evm-mina-verification.git.

Usage and development questions a preferred to be asked in a Telegram chat: https:/t.me/nil_crypto3
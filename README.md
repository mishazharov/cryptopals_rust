# Cryptopals solutions in rust
This repository contains my current solutions for the cryptopals problem set (https://cryptopals.com/).

## Dependencies
Tested with `rustc --version`:
```
rustc 1.44.1 (c7087fe00 2020-06-17)
```
Other dependencies are listed in `Cargo.toml`
## Running
All of the solutions have tests associated with them which can be compiled and executed with `cargo test`.

## Project layout
The project structure follows the cryptopals convention of splitting challenges into sets. Folders representing sets can be found under the `src` folder. Individual challenges are under `src/sX/cY.rs` where `X` is a valid set number, and `Y` is a valid challenge number.

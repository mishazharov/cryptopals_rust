:: This is a build script for windows. On other platforms you can
:: just run `cargo test`
::
:: Prior to using this script:
:: * install x86-64 static OpenSSL
:: * make sure that you are using the x86-64 rust toolchain
set RUSTFLAGS=-Ctarget-feature=+crt-static
cargo test -- --nocapture

# cross-authenticode

    THIS CRATE IS CURRENTLY WORK IN PROGRESS
    There will be frequent breaking changes until the first 1.*.* release

Cross platform library to check authenticode signatures and certificate hashes of PE files. It's focus is on a seamless cross platform experience, so that you can use the same code on Windows, Linux and macOS.

## Current State

- [x] Extract all certificates from a PE file
- [x] Compute the `SHA-1` and `SHA-256` hash (thumbprint/fingerprint) of a certificate
- [ ] Find the signing certificate of the PE file from the certificate chain
- [ ] Verify the signature of a PE file

## Documentation

The documentation can be found [docs.rs/cross-authenticode](https://docs.rs/cross-authenticode)

## Related Projects

There are a few other projects on crates.io that deal with authenticode signatures. Here is a list of them and why I decided to write my own:

- [authenticode](https://crates.io/crates/authenticode): Does not compute the thumbprint of the certificates
- [authenticate-parser](https://crates.io/crates/authenticode-parser): Depends on `openssl` which makes it hard to cross-compile

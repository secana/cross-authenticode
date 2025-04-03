# cross-authenticode

Cross platform library to check authenticode signatures and certificate hashes of PE files. It's focus is on a seamless cross platform experience, so that you can use the same code on Windows, Linux and macOS.

## Features

- [x] Extract all certificates from a PE file
- [x] Compute the `SHA-1` and `SHA-256` (or other) hash (thumbprint/fingerprint) of a certificate
- [x] Verify the signature of a PE file by computing the hash of the file and comparing it to the hash in the signature


## Documentation

The documentation can be found [docs.rs/cross-authenticode](https://docs.rs/cross-authenticode)

## Related Projects

There are a few other projects on crates.io that deal with authenticode signatures. Here is a list of them and why I decided to write my own:

- [authenticode](https://crates.io/crates/authenticode): Does not compute the thumbprint of the certificates
- [authenticate-parser](https://crates.io/crates/authenticode-parser): Depends on `openssl` which makes it hard to cross-compile

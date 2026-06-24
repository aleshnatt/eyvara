# eyvara_vrf

Post-quantum lattice-based Verifiable Random Function (VRF) from Module-LWE with tight uniqueness in the Quantum Random Oracle Model.

[![Crates.io](https://img.shields.io/crates/v/eyvara_vrf.svg)](https://crates.io/crates/eyvara_vrf)
[![docs.rs](https://img.shields.io/docsrs/eyvara_vrf)](https://docs.rs/eyvara_vrf)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)]()

## Overview

A verifiable random function lets a secret-key holder compute a pseudorandom output for an input and publish a proof that anyone can verify with the public key. Verification checks both the proof and the claimed output, so a valid proof binds the input to one public VRF value.

Eyvara is a research implementation of a lattice-based VRF built from Module-LWE using Fiat-Shamir with Aborts. Its proof follows a Dilithium-style commitment, challenge, response, and hint structure so the verifier can recover the high bits of the commitment and recompute the expected output.

Post-quantum VRFs are intended for settings where classical elliptic-curve assumptions are not acceptable. This crate provides reference parameter sets targeting 128-bit and 192-bit classical security levels for experimentation and review.

## Security Notice

This crate is a research prototype. It is not audited for production deployment and should not be used in security-critical systems without an independent professional cryptographic review.

The current implementation addresses audit findings for output binding (VULN-01), zeroization of evaluation intermediates (VULN-02), and documented timing risk around coefficient norm computation with a constant-time-oriented alternative (VULN-03). These remediations do not replace a full implementation and protocol audit.

## Quick Start

```rust
use eyvara_vrf::{eyvara_eval, eyvara_keygen, eyvara_verify, EYVARA_128};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

let mut rng = ChaCha20Rng::seed_from_u64(42);
let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);

let input = b"example input";
let (output, proof) = eyvara_eval(&EYVARA_128, &sk, input, &mut rng)
    .expect("evaluation should succeed");

assert!(eyvara_verify(&EYVARA_128, &pk, input, &output, &proof));
```

## Parameter Sets

| Parameter set | n | k | q | Security level |
|---|---:|---:|---:|---|
| `EYVARA_128` | 256 | 2 | 8,380,417 | 128-bit classical |
| `EYVARA_192` | 256 | 3 | 8,380,417 | 192-bit classical |

## Features

The crate has no default optional features.

Enable `serde` to derive `Serialize` and `Deserialize` for public parameter metadata:

```toml
eyvara_vrf = { version = "0.1.0", features = ["serde"] }
```

Enable `hex` when downstream applications want the optional dependency available for encoding integration:

```toml
eyvara_vrf = { version = "0.1.0", features = ["hex"] }
```

## Installation

```toml
[dependencies]
eyvara_vrf = "0.1.0"
```

## Building

```sh
cargo build --release
```

The pre-publish checklist is available as an executable script:

```sh
./scripts/pre_publish.sh
```

## Testing

```sh
cargo test
cargo test --doc
```

## Benchmarks

```sh
cargo bench
```

## Paper

Eyvara: A Post-Quantum Lattice-Based Verifiable Random Function from Module-LWE. An IACR ePrint link will be added when available. This crate is the reference implementation.

## License

Licensed under MIT OR Apache-2.0.

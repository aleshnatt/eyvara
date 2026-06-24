# eyvara_vrf

[![Crates.io](https://img.shields.io/crates/v/eyvara_vrf.svg)](https://crates.io/crates/eyvara_vrf)
[![docs.rs](https://img.shields.io/docsrs/eyvara_vrf)](https://docs.rs/eyvara_vrf)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)]()

## What is a VRF

A verifiable random function (VRF) lets a secret-key holder compute a deterministic pseudorandom output for an input and publish a proof that anyone can verify with the corresponding public key. For a fixed secret key and input, the output is unique; without the secret key, it should be computationally infeasible to predict the output before seeing a valid proof.

Post-quantum VRFs target deployments where long-term security should not depend on classical elliptic-curve assumptions. Eyvara is a lattice-based construction from Module-LWE.

## Security Notice

Known limitations: `infinity_norm` is not constant-time, and the rejection
sampling loop has input-dependent timing. Do not use in systems where
side-channel resistance is required.

## Quick Start

```rust
use eyvara_vrf::{eyvara_eval, eyvara_keygen, eyvara_verify, EyvaraError};
use eyvara_vrf::params::EYVARA_128;
use rand::rngs::OsRng;

fn main() -> Result<(), EyvaraError> {
    let mut rng = OsRng;
    let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
    let input = b"my application input";
    let (output, proof) = eyvara_eval(&EYVARA_128, &sk, input, &mut rng)?;
    let valid = eyvara_verify(&EYVARA_128, &pk, input, &output, &proof)?;
    assert!(valid);
    Ok(())
}
```

## Parameter Sets

| Name | Security | Proof Size | Key Size |
|------|----------|------------|----------|
| EYVARA_128 | NIST Cat. 1 (~128-bit classical) | ~1.3 KB | ~4 KB public, ~8 KB secret |
| EYVARA_192 | NIST Cat. 3 (~192-bit classical) | ~2.0 KB | ~6 KB public, ~12 KB secret |

## Optional Features

The `serde` feature enables `Serialize` and `Deserialize` for `PublicKey`, `EyvaraProof`, and `EyvaraOutput`. `SecretKey` supports `Serialize` only, so explicit key import from untrusted data is not provided by this crate.

```toml
eyvara_vrf = { version = "0.1", features = ["serde"] }
```

## Building, Testing, Benchmarking

```sh
cargo build --release
cargo test
cargo test --doc
cargo test --features serde
cargo bench
```

## License

MIT OR Apache-2.0

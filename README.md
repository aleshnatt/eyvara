# Eyvara VRF

A lattice-based Verifiable Random Function (VRF) from Module-LWE with tight uniqueness in the Quantum Random Oracle Model (QROM).

## Overview

Eyvara is a post-quantum VRF construction built on the hardness of the Module Learning With Errors (MLWE) and Module Short Integer Solution (MSIS) problems. It uses the Fiat-Shamir with Aborts paradigm (Lyubashevsky 2012) to produce compact proofs and achieves the three standard VRF security properties—pseudorandomness, provability, and uniqueness—with tight reductions in the QROM.

## ⚠️ Security Notice

**This is a reference implementation for research purposes only.** It has not been audited for production use. Do not use this in security-critical applications without a thorough independent cryptographic review. The implementation prioritizes clarity and correctness over side-channel resistance.

## Parameter Sets

| Parameter | Eyvara-I | Eyvara-III |
|-----------|----------|------------|
| NIST Category | 1 (128-bit) | 3 (192-bit) |
| Ring dimension (n) | 256 | 256 |
| Module rank (k) | 2 | 3 |
| Modulus (q) | 8,380,417 | 8,380,417 |
| Secret bound (η) | 2 | 2 |
| Challenge weight (τ) | 39 | 49 |
| Masking range (γ₁) | 2¹⁷ | 2¹⁹ |
| Proof size | ~1,250 bytes | ~2,051 bytes |
| Output size | 64 bytes | 64 bytes |

## Build

```bash
cargo build --release
```

## Test

```bash
cargo test
```

## Benchmark

```bash
cargo bench
```

Benchmarks use the [Criterion](https://github.com/bheisler/criterion.rs) framework and measure key generation, evaluation, verification, and full round-trip performance.

## Usage

```rust
use eyvara_vrf::params::EYVARA_I;
use eyvara_vrf::keygen::eyvara_keygen;
use eyvara_vrf::eval::eyvara_eval;
use eyvara_vrf::verify::eyvara_verify;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn main() {
    let mut rng = ChaCha20Rng::from_entropy();
    
    // Key generation
    let (pk, sk) = eyvara_keygen(&EYVARA_I, &mut rng);
    
    // VRF evaluation
    let input = b"example VRF input";
    let (beta, proof) = eyvara_eval(&EYVARA_I, &sk, input, &mut rng)
        .expect("evaluation should succeed");
    
    // Verification
    assert!(eyvara_verify(&EYVARA_I, &pk, input, &beta, &proof));
    
    println!("VRF output: {}", hex::encode(&beta));
}
```

## Crate Structure

| Module | Description |
|--------|-------------|
| `params` | System parameters for Eyvara-I and Eyvara-III |
| `poly` | Polynomial arithmetic over R_q, sampling, HighBits/LowBits |
| `ntt` | Number Theoretic Transform for fast polynomial multiplication |
| `challenge` | Challenge polynomial sampling (SampleInBall) and hashing |
| `keygen` | MLWE-based key generation |
| `eval` | VRF evaluation with Fiat-Shamir with Aborts |
| `verify` | VRF proof verification |
| `tests` | Integration test suite |

## Paper

The accompanying paper describes the construction, security proofs, and parameter derivation in detail:

> "Eyvara: A Lattice-Based Verifiable Random Function from Module-LWE with Tight Uniqueness in the Quantum Random Oracle Model"

See the `paper/` directory for the LaTeX source.

## License

This project is licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

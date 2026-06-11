//! # Eyvara VRF
//!
//! A lattice-based Verifiable Random Function (VRF) from the Module Learning
//! With Errors (MLWE) assumption, with tight uniqueness in the Quantum Random
//! Oracle Model (QROM).
//!
//! ## Security Notice
//!
//! This is a **reference implementation** for research purposes. It has not been
//! audited for production use. Do not deploy this in security-critical applications
//! without a thorough cryptographic review.
//!
//! ## Overview
//!
//! Eyvara provides three algorithms:
//! - **KeyGen**: Generate a public/secret key pair from MLWE parameters.
//! - **Eval**: Compute a deterministic pseudorandom output and verifiable proof.
//! - **Verify**: Check that a proof is valid for a given public key and input.
//!
//! Two parameter sets are supported:
//! - **Eyvara-I**: NIST Category 1 (≥128-bit classical security)
//! - **Eyvara-III**: NIST Category 3 (≥192-bit classical security)
//!
//! ## Example
//!
//! ```rust
//! use eyvara_vrf::params::EYVARA_I;
//! use eyvara_vrf::keygen::eyvara_keygen;
//! use eyvara_vrf::eval::eyvara_eval;
//! use eyvara_vrf::verify::eyvara_verify;
//! use rand::SeedableRng;
//! use rand_chacha::ChaCha20Rng;
//!
//! let mut rng = ChaCha20Rng::seed_from_u64(42);
//! let (pk, sk) = eyvara_keygen(&EYVARA_I, &mut rng);
//!
//! let input = b"example input";
//! let (beta, proof) = eyvara_eval(&EYVARA_I, &sk, input, &mut rng).unwrap();
//!
//! assert!(eyvara_verify(&EYVARA_I, &pk, input, &beta, &proof));
//! ```

pub mod params;
pub mod poly;
pub mod ntt;
pub mod challenge;
pub mod keygen;
pub mod eval;
pub mod verify;

// Re-export primary types for convenience
pub use params::{Params, EYVARA_I, EYVARA_III};
pub use keygen::{PublicKey, SecretKey, eyvara_keygen};
pub use eval::{VrfOutput, VrfProof, eyvara_eval};
pub use verify::eyvara_verify;

#[cfg(test)]
mod tests;

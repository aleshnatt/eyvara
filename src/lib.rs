#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::assign_op_pattern)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::explicit_iter_loop)]
#![allow(clippy::if_not_else)]
#![allow(clippy::inline_always)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::unreadable_literal)]
#![allow(dead_code)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]

//! # eyvara_vrf
//!
//! `eyvara_vrf` is a research implementation of a post-quantum,
//! lattice-based Verifiable Random Function from Module-LWE.
//!
//! The public API consists of key generation, evaluation, verification, and
//! two parameter sets.
//!
//! ```rust
//! use eyvara_vrf::{eyvara_eval, eyvara_keygen, eyvara_verify, EYVARA_128};
//! use rand::SeedableRng;
//! use rand_chacha::ChaCha20Rng;
//!
//! let mut rng = ChaCha20Rng::seed_from_u64(42);
//! let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
//!
//! let input = b"example input";
//! let (output, proof) = eyvara_eval(&EYVARA_128, &sk, input, &mut rng)
//!     .expect("evaluation should succeed");
//!
//! assert!(eyvara_verify(&EYVARA_128, &pk, input, &output, &proof));
//! ```

pub(crate) mod challenge;
pub mod eval;
pub mod keygen;
pub(crate) mod ntt;
pub mod params;
pub(crate) mod poly;
pub mod verify;

pub use eval::{eyvara_eval, EyvaraOutput, EyvaraProof};
pub use keygen::{eyvara_keygen, PublicKey, SecretKey};
pub use params::{Params, EYVARA_128, EYVARA_192};
pub use verify::eyvara_verify;

#[cfg(test)]
mod tests;

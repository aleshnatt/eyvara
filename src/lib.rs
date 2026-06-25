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

//!
//! ```rust
//! use eyvara::{eyvara_eval, eyvara_keygen, eyvara_verify, EyvaraError, EYVARA_128};
//! use rand::rngs::OsRng;
//!
//! fn main() -> Result<(), EyvaraError> {
//!     let mut rng = OsRng;
//!     let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
//!     let msg = b"example input";
//!     let (out, proof) = eyvara_eval(&EYVARA_128, &sk, msg)?;
//!     assert!(eyvara_verify(&EYVARA_128, &pk, msg, &out, &proof)?);
//!     Ok(())
//! }
//! ```
//!

pub(crate) mod challenge;
pub mod error;
pub mod eval;
pub mod keygen;
pub(crate) mod ntt;
pub mod params;
pub(crate) mod poly;
pub mod verify;

pub use error::EyvaraError;
pub use eval::{eyvara_eval, EyvaraOutput, EyvaraProof, VrfOutput, VrfProof};
pub use keygen::{eyvara_keygen, PublicKey, SecretKey};
pub use params::{Params, EYVARA_128, EYVARA_192};
pub use verify::eyvara_verify;

#[cfg(test)]
mod tests;

//! System parameters for the Eyvara VRF.
//!
//! This module defines the sealed cryptographic parameters for Eyvara-I
//! (NIST Category 1) and Eyvara-III (NIST Category 3). The public API supports
//! only the predefined parameter sets because invalid custom parameters can
//! silently break security.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Ring dimension. The polynomial ring is `Z[X]/(X^N + 1)`.
pub const N: usize = 256;

/// Prime modulus for the polynomial ring `R_q = Z_q[X]/(X^N + 1)`.
pub const Q: i64 = 8_380_417;

/// Half of Q, used for centered reduction.
pub const Q_HALF: i64 = (Q - 1) / 2;

/// Montgomery parameter: R = 2^32 mod Q, used for Montgomery multiplication.
pub const MONT_R: i64 = 4_193_792;

/// Inverse of R in Z_q: R^{-1} * R == 1 mod Q.
pub const MONT_R_INV: i64 = 8_265_825;

/// Q^{-1} mod 2^32, used in Montgomery reduction.
pub const Q_INV: i64 = 58_728_449;

/// Maximum number of Fiat-Shamir with Aborts iterations before returning an error.
pub const MAX_ATTEMPTS: usize = 256;

/// Size of the VRF output in bytes. Produced by SHAKE-256.
pub const OUTPUT_SIZE: usize = 64;

/// Size of the challenge seed in bytes. Produced by SHAKE-256.
pub const CHALLENGE_SEED_SIZE: usize = 32;

/// Size of the public seed rho in bytes.
pub const SEED_SIZE: usize = 32;

/// Domain separation tag for the challenge hash H_1.
pub const DOMAIN_CHALLENGE: &[u8] = b"eyvara-challenge";

/// Domain separation tag for the output hash H_2.
pub const DOMAIN_OUTPUT: &[u8] = b"eyvara-output";

/// Domain separation tag for matrix expansion.
pub const DOMAIN_MATRIX: &[u8] = b"vrf-matrix\x00\x00\x00\x00\x00\x00";

/// System parameters for the Eyvara VRF scheme.
///
/// The fields are private; use [`EYVARA_128`] or [`EYVARA_192`]. Custom
/// parameters are not part of the public API because bad choices break security.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    n: usize,
    k: usize,
    q: i64,
    eta: i64,
    gamma_1: i64,
    gamma_2: i64,
    tau: usize,
    beta: i64,
    omega: usize,
}

impl Params {
    #[allow(clippy::too_many_arguments)]
    const fn new(
        n: usize,
        k: usize,
        q: i64,
        eta: i64,
        gamma_1: i64,
        gamma_2: i64,
        tau: usize,
        beta: i64,
        omega: usize,
    ) -> Self {
        assert!(tau <= n, "tau must not exceed n");
        assert!(tau > 0, "tau must be positive");
        assert!(gamma_1 > beta, "gamma_1 must exceed beta");
        assert!(gamma_2 > 0, "gamma_2 must be positive");
        assert!(beta > 0, "beta must be positive");
        assert!(eta > 0, "eta must be positive");
        assert!(omega > 0, "omega must be positive");
        assert!(k > 0, "k must be positive");
        assert!(q > 0, "q must be positive");
        Self {
            n,
            k,
            q,
            eta,
            gamma_1,
            gamma_2,
            tau,
            beta,
            omega,
        }
    }

    /// Returns the ring dimension.
    pub const fn n(&self) -> usize {
        self.n
    }

    /// Returns the module rank.
    pub const fn k(&self) -> usize {
        self.k
    }

    /// Returns the modulus.
    pub const fn q(&self) -> i64 {
        self.q
    }

    /// Returns the centered binomial distribution parameter.
    pub const fn eta(&self) -> i64 {
        self.eta
    }

    /// Returns the masking range bound.
    pub const fn gamma_1(&self) -> i64 {
        self.gamma_1
    }

    /// Returns the rounding divisor parameter.
    pub const fn gamma_2(&self) -> i64 {
        self.gamma_2
    }

    /// Returns the number of nonzero challenge coefficients.
    pub const fn tau(&self) -> usize {
        self.tau
    }

    /// Returns beta = tau * eta.
    pub const fn beta(&self) -> i64 {
        self.beta
    }

    /// Returns the maximum allowed hint weight.
    pub const fn omega(&self) -> usize {
        self.omega
    }

    /// Rejection sampling bound: gamma_1 - beta.
    pub const fn rejection_bound(&self) -> i64 {
        self.gamma_1 - self.beta
    }
}

/// NIST Category 1 parameter set. Suitable for most applications.
pub const EYVARA_128: Params = Params::new(256, 2, 8_380_417, 2, 131_072, 95_232, 39, 78, 80);

/// NIST Category 3 parameter set. Use when a higher security margin is
/// required, at the cost of larger proofs and slower operations.
pub const EYVARA_192: Params = Params::new(256, 3, 8_380_417, 2, 524_288, 261_888, 49, 98, 120);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eyvara_i_rejection_bound() {
        assert_eq!(EYVARA_128.rejection_bound(), 131_072 - 78);
    }

    #[test]
    fn test_eyvara_iii_rejection_bound() {
        assert_eq!(EYVARA_192.rejection_bound(), 524_288 - 98);
    }

    #[test]
    fn test_gamma2_divides_q_minus_1() {
        assert_eq!((Q - 1) % (2 * EYVARA_128.gamma_2()), 0);
        assert_eq!((Q - 1) % (2 * EYVARA_192.gamma_2()), 0);
    }

    #[test]
    fn test_domain_tags_are_nonempty() {
        assert_eq!(DOMAIN_CHALLENGE.len(), 16);
        assert!(!DOMAIN_OUTPUT.is_empty());
        assert_eq!(DOMAIN_MATRIX.len(), 16);
    }
}

//! System parameters for the Eyvara VRF.
//!
//! This module defines the cryptographic parameters for Eyvara-I (NIST Category 1)
//! and Eyvara-III (NIST Category 3). All constants are derived from the security
//! analysis in the accompanying paper and are compatible with CRYSTALS-Dilithium
//! parameter choices.

use serde::{Deserialize, Serialize};

/// Ring dimension. The polynomial ring is Z[X]/(X^N + 1).
/// N = 256 is a power of two, enabling efficient NTT-based multiplication.
pub const N: usize = 256;

/// Prime modulus for the polynomial ring R_q = Z_q[X]/(X^N + 1).
/// q = 8380417 = 2^23 - 2^13 + 1, chosen for NTT-friendliness:
/// the multiplicative group Z_q* contains a primitive 512th root of unity.
pub const Q: i64 = 8_380_417;

/// Half of Q, used for centered reduction: coefficients are kept in [-(Q-1)/2, (Q-1)/2].
pub const Q_HALF: i64 = (Q - 1) / 2;

/// Montgomery parameter: R = 2^32 mod Q, used for Montgomery multiplication in the NTT.
pub const MONT_R: i64 = 4_193_792; // 2^32 mod Q

/// Inverse of R in Z_q: R^{-1} * R ≡ 1 (mod Q).
pub const MONT_R_INV: i64 = 8_265_825;

/// Q^{-1} mod 2^32, used in Montgomery reduction.
pub const Q_INV: i64 = 58_728_449; // q^(-1) mod 2^32

/// Maximum number of Fiat-Shamir with Aborts iterations before returning an error.
/// The expected number of iterations is ~1.36 for Eyvara-I, so 256 provides
/// an overwhelming margin (failure probability < 2^{-490}).
pub const MAX_ATTEMPTS: usize = 256;

/// Size of the VRF output in bytes. Produced by SHAKE-256.
pub const OUTPUT_SIZE: usize = 64;

/// Size of the challenge seed in bytes. Produced by SHAKE-256.
pub const CHALLENGE_SEED_SIZE: usize = 32;

/// Size of the public seed rho in bytes.
pub const SEED_SIZE: usize = 32;

/// Domain separation tag for the challenge hash H_1.
pub const DOMAIN_CHALLENGE: &[u8] = b"vrf-challenge\x00\x00\x00";

/// Domain separation tag for the output hash H_2.
pub const DOMAIN_OUTPUT: &[u8] = b"vrf-output\x00\x00\x00\x00\x00\x00";

/// Domain separation tag for matrix expansion.
pub const DOMAIN_MATRIX: &[u8] = b"vrf-matrix\x00\x00\x00\x00\x00\x00";

/// Parameter set for an Eyvara instance.
///
/// Each field corresponds to a parameter from the paper's Table I.
/// Two const instances are provided: `EYVARA_I` and `EYVARA_III`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Params {
    /// Module rank. k=2 for Category 1, k=3 for Category 3.
    pub k: usize,

    /// Bound on secret and noise coefficients. Coefficients of s, e are sampled
    /// from the centered binomial distribution with parameter eta, producing
    /// values in {-eta, ..., eta}.
    pub eta: i64,

    /// Number of nonzero (±1) coefficients in the challenge polynomial c.
    /// Determines the challenge space size |C| = C(256, tau) * 2^tau.
    pub tau: usize,

    /// Masking range bound. The masking vector y has coefficients sampled
    /// uniformly from [-gamma1+1, gamma1]. Larger gamma1 increases acceptance
    /// probability but also increases proof size.
    pub gamma1: i64,

    /// Rounding divisor. Used in HighBits/LowBits decomposition:
    /// HighBits(r, 2*gamma2) = floor((r + gamma2) / (2*gamma2)).
    /// Chosen so that q-1 is divisible by 2*gamma2.
    pub gamma2: i64,

    /// Maximum Hamming weight of the hint vector h. Proofs with hints exceeding
    /// this weight are rejected to bound proof size and prevent manipulation.
    pub omega: usize,

    /// Number of dropped low-order bits of t for public key compression.
    /// t1 = t >> d is stored; t0 = t - (t1 << d) is implicit.
    pub d: usize,

    /// Bits per coefficient of z in proof encoding.
    /// Equal to ceil(log2(2*gamma1)).
    pub z_bits: usize,
}

impl Params {
    /// Rejection sampling bound: gamma1 - tau * eta.
    /// The response z is accepted only if ||z||_inf < beta_rej.
    pub const fn rejection_bound(&self) -> i64 {
        self.gamma1 - (self.tau as i64) * self.eta
    }
}

/// Eyvara-I parameter set targeting NIST Category 1 (≥128-bit classical security).
///
/// Module rank k=2, giving MLWE dimension n*k = 512. The masking range
/// gamma1 = 2^17 and challenge weight tau = 39 yield an acceptance probability
/// of approximately 0.74 per iteration and a challenge space of ~2^196.
pub const EYVARA_I: Params = Params {
    k: 2,
    eta: 2,
    tau: 39,
    gamma1: 1 << 17, // 131072
    gamma2: (Q - 1) / 88,
    omega: 80,
    d: 13,
    z_bits: 18,
};

/// Eyvara-III parameter set targeting NIST Category 3 (≥192-bit classical security).
///
/// Module rank k=3, giving MLWE dimension n*k = 768. The larger masking range
/// gamma1 = 2^19 increases acceptance probability to ~0.87 and the challenge
/// space to ~2^237, at the cost of larger proofs (20 bits per z coefficient).
pub const EYVARA_III: Params = Params {
    k: 3,
    eta: 2,
    tau: 49,
    gamma1: 1 << 19, // 524288
    gamma2: (Q - 1) / 32,
    omega: 55,
    d: 13,
    z_bits: 20,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eyvara_i_rejection_bound() {
        assert_eq!(EYVARA_I.rejection_bound(), 131072 - 78);
    }

    #[test]
    fn test_eyvara_iii_rejection_bound() {
        assert_eq!(EYVARA_III.rejection_bound(), 524288 - 98);
    }

    #[test]
    fn test_gamma2_divides_q_minus_1() {
        assert_eq!((Q - 1) % (2 * EYVARA_I.gamma2), 0);
        assert_eq!((Q - 1) % (2 * EYVARA_III.gamma2), 0);
    }

    #[test]
    fn test_domain_tags_are_16_bytes() {
        assert_eq!(DOMAIN_CHALLENGE.len(), 16);
        assert_eq!(DOMAIN_OUTPUT.len(), 16);
        assert_eq!(DOMAIN_MATRIX.len(), 16);
    }
}

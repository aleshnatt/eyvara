//! Challenge polynomial sampling for the Eyvara VRF.
//!
//! This module implements the `SampleInBall` function that derives a sparse
//! ternary challenge polynomial from a 32-byte seed, and the
//! `hash_to_challenge_seed` function that computes the challenge seed from
//! the commitment, public key, and input.
//!
//! The challenge polynomial c has exactly tau nonzero coefficients, each ±1,
//! giving a challenge space of size |C| = C(N, tau) * 2^tau.

use crate::params::{N, CHALLENGE_SEED_SIZE, DOMAIN_CHALLENGE, DOMAIN_OUTPUT, OUTPUT_SIZE};
use crate::poly::{Poly, poly_zero, poly_vec_to_bytes};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

/// Derive a sparse ternary challenge polynomial from a 32-byte seed.
///
/// `SampleInBall(seed, tau)` produces a polynomial c ∈ R with exactly tau
/// nonzero coefficients, each in {-1, +1}. The positions and signs are
/// determined deterministically by the seed via SHAKE-256.
///
/// The algorithm follows the CRYSTALS-Dilithium specification:
/// 1. Initialize SHAKE-256 with the seed.
/// 2. For i = N-tau to N-1:
///    a. Sample j uniformly from [0, i] using rejection sampling.
///    b. Swap c[i] and c[j].
///    c. Set c[i] to ±1 based on the next sign bit.
///
/// This produces a uniformly random polynomial with exactly tau nonzero
/// entries, where each entry is ±1 with equal probability.
pub fn sample_in_ball(seed: &[u8; CHALLENGE_SEED_SIZE], tau: usize) -> Poly {
    let mut c = poly_zero();

    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    // Read 8 bytes for sign bits
    let mut sign_buf = [0u8; 8];
    reader.read(&mut sign_buf);
    let mut signs = u64::from_le_bytes(sign_buf);

    for i in (N - tau)..N {
        // Rejection sampling for j in [0, i]
        let j = loop {
            let mut buf = [0u8; 1];
            reader.read(&mut buf);
            let val = buf[0] as usize;
            if val <= i {
                break val;
            }
        };

        // Swap c[i] and c[j]
        c[i] = c[j];

        // Set c[j] based on sign bit: +1 if bit is 0, -1 if bit is 1
        c[j] = if signs & 1 == 0 { 1 } else { -1 };
        signs >>= 1;
    }

    c
}

/// Compute the challenge seed by hashing the commitment, public key, and input.
///
/// The challenge seed is computed as:
///   c_tilde = SHAKE-256(DOMAIN_CHALLENGE || w1_bytes || t_bytes || x)
///
/// where w1 is the high-order bits of the commitment vector, t is the public
/// key vector, and x is the VRF input. The domain tag ensures separation from
/// the output hash H_2.
///
/// Returns a 32-byte seed suitable for `sample_in_ball`.
pub fn hash_to_challenge_seed(
    w1: &[Poly],
    t: &[Poly],
    x: &[u8],
) -> [u8; CHALLENGE_SEED_SIZE] {
    let mut hasher = Shake256::default();
    hasher.update(DOMAIN_CHALLENGE);
    hasher.update(&poly_vec_to_bytes(w1));
    hasher.update(&poly_vec_to_bytes(t));
    hasher.update(x);

    let mut reader = hasher.finalize_xof();
    let mut seed = [0u8; CHALLENGE_SEED_SIZE];
    reader.read(&mut seed);
    seed
}

/// Compute the VRF output hash H_2.
///
/// The VRF output is computed as:
///   beta = SHAKE-256(DOMAIN_OUTPUT || s_bytes || x)
///
/// where s_bytes is the serialized secret key vector s and x is the VRF input.
/// The output is 64 bytes (512 bits), providing 256-bit collision resistance.
///
/// This function is deterministic: for a fixed (s, x), the output is always
/// the same, as required by the VRF correctness definition.
pub fn hash_vrf_output(
    s_bytes: &[u8],
    x: &[u8],
) -> [u8; OUTPUT_SIZE] {
    let mut hasher = Shake256::default();
    hasher.update(DOMAIN_OUTPUT);
    hasher.update(s_bytes);
    hasher.update(x);

    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; OUTPUT_SIZE];
    reader.read(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::EYVARA_I;

    #[test]
    fn test_sample_in_ball_weight() {
        let seed = [42u8; CHALLENGE_SEED_SIZE];
        let c = sample_in_ball(&seed, EYVARA_I.tau);

        // Count nonzero coefficients
        let weight: usize = c.iter().filter(|&&v| v != 0).count();
        assert_eq!(weight, EYVARA_I.tau, "challenge should have exactly tau nonzero coefficients");

        // All nonzero coefficients should be ±1
        for &v in c.iter() {
            assert!(v == -1 || v == 0 || v == 1, "coefficient {} not in {{-1, 0, 1}}", v);
        }
    }

    #[test]
    fn test_sample_in_ball_deterministic() {
        let seed = [7u8; CHALLENGE_SEED_SIZE];
        let c1 = sample_in_ball(&seed, 39);
        let c2 = sample_in_ball(&seed, 39);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_sample_in_ball_different_seeds() {
        let seed1 = [1u8; CHALLENGE_SEED_SIZE];
        let seed2 = [2u8; CHALLENGE_SEED_SIZE];
        let c1 = sample_in_ball(&seed1, 39);
        let c2 = sample_in_ball(&seed2, 39);
        assert_ne!(c1, c2, "different seeds should produce different challenges");
    }

    #[test]
    fn test_hash_vrf_output_deterministic() {
        let s_bytes = b"test_secret_key_bytes";
        let x = b"test_input";
        let o1 = hash_vrf_output(s_bytes, x);
        let o2 = hash_vrf_output(s_bytes, x);
        assert_eq!(o1, o2);
    }

    #[test]
    fn test_hash_vrf_output_different_inputs() {
        let s_bytes = b"test_secret_key_bytes";
        let o1 = hash_vrf_output(s_bytes, b"input1");
        let o2 = hash_vrf_output(s_bytes, b"input2");
        assert_ne!(o1, o2, "different inputs should produce different outputs");
    }

    #[test]
    fn test_hash_vrf_output_size() {
        let o = hash_vrf_output(b"key", b"input");
        assert_eq!(o.len(), OUTPUT_SIZE);
    }
}

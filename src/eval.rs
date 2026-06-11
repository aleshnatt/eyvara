//! VRF evaluation for the Eyvara VRF.
//!
//! Implements Algorithm 2 from the paper: given a secret key and an input,
//! produces a deterministic VRF output and a proof using the Fiat-Shamir
//! with Aborts protocol.

use crate::params::{Params, OUTPUT_SIZE, CHALLENGE_SEED_SIZE, MAX_ATTEMPTS};
use crate::poly::{
    PolyVec, expand_a, poly_matrix_mul_ntt,
    poly_scalar_mul, poly_vec_add, poly_vec_sub,
    infinity_norm_vec, high_bits_vec, low_bits_vec,
    make_hint_vec, poly_vec_to_bytes,
    sample_uniform_gamma1_vec,
};
use crate::challenge::{hash_to_challenge_seed, sample_in_ball, hash_vrf_output};
use crate::keygen::SecretKey;
use rand::Rng;

/// VRF output: a 64-byte (512-bit) pseudorandom value.
///
/// The output is deterministic for a given (secret key, input) pair,
/// computed as beta = H_2("vrf-output" || s_bytes || x).
pub type VrfOutput = [u8; OUTPUT_SIZE];

/// VRF proof enabling public verification of the output.
///
/// The proof consists of:
/// - `c_tilde`: 32-byte challenge seed (hash of commitment and input)
/// - `z`: response vector (k polynomials with bounded coefficients)
/// - `h`: hint vector (k*N bits) for recovering high-order bits during verification
#[derive(Debug, Clone)]
pub struct VrfProof {
    /// Challenge seed: c_tilde = H_1("vrf-challenge" || w1 || t || x).
    pub c_tilde: [u8; CHALLENGE_SEED_SIZE],

    /// Response vector: z = y + c*s, where y is the masking vector and c is
    /// the challenge polynomial. Accepted only if ||z||_inf < gamma1 - tau*eta.
    pub z: PolyVec,

    /// Hint vector for recovering HighBits(w) from HighBits(Az - ct).
    /// Encoded as k*N signed bytes (each 0 or 1).
    pub h: Vec<i8>,
}

/// Evaluate the Eyvara VRF on input x.
///
/// Implements Algorithm 2 from the paper. The evaluation proceeds as follows:
///
/// 1. Compute the VRF output deterministically:
///    beta = H_2("vrf-output" || s_bytes || x)
///
/// 2. Generate the proof via Fiat-Shamir with Aborts:
///    a. Sample masking vector y uniformly from [-gamma1+1, gamma1]^k.
///    b. Compute commitment w = Ay mod q.
///    c. Extract high-order bits w1 = HighBits(w, 2*gamma2).
///    d. Compute challenge seed c_tilde = H_1("vrf-challenge" || w1 || t || x).
///    e. Derive challenge polynomial c = SampleInBall(c_tilde, tau).
///    f. Compute response z = y + c*s.
///    g. Reject and restart if ||z||_inf >= gamma1 - tau*eta or if LowBits
///       of Az - ct are too large, or if hint weight exceeds omega.
///    h. Compute hint h = MakeHint(-ct, w, 2*gamma2).
///
/// Returns `Some((beta, proof))` on success, `None` if all MAX_ATTEMPTS fail
/// (probability < 2^{-490} for Eyvara-I).
pub fn eyvara_eval<R: Rng>(
    params: &Params,
    sk: &SecretKey,
    x: &[u8],
    rng: &mut R,
) -> Option<(VrfOutput, VrfProof)> {
    // Expand public matrix A from seed (in NTT domain)
    let a_ntt = expand_a(&sk.rho, params.k);

    // Compute VRF output deterministically from secret key and input
    let s_bytes = poly_vec_to_bytes(&sk.s);
    let beta = hash_vrf_output(&s_bytes, x);

    // Fiat-Shamir with Aborts loop
    for _attempt in 0..MAX_ATTEMPTS {
        // Step (a): Sample masking vector y
        let y = sample_uniform_gamma1_vec(rng, params.k, params.gamma1);

        // Step (b): Compute commitment w = Ay mod q
        let w = poly_matrix_mul_ntt(&a_ntt, &y);

        // Step (c): Extract high-order bits
        let w1 = high_bits_vec(&w, params.gamma2);

        // Step (d): Compute challenge seed
        let c_tilde = hash_to_challenge_seed(&w1, &sk.t, x);

        // Step (e): Derive challenge polynomial
        let c = sample_in_ball(&c_tilde, params.tau);

        // Step (f): Compute response z = y + c*s
        let cs: PolyVec = sk.s.iter().map(|si| poly_scalar_mul(&c, si)).collect();
        let z = poly_vec_add(&y, &cs);

        // Step (g): Rejection sampling check on z norm
        let rejection_bound = params.rejection_bound();
        if infinity_norm_vec(&z) >= rejection_bound {
            continue;
        }

        // Compute r = Az - ct mod q for low-bits check
        let ct: PolyVec = sk.t.iter().map(|ti| poly_scalar_mul(&c, ti)).collect();
        let r = poly_vec_sub(&poly_matrix_mul_ntt(&a_ntt, &z), &ct);

        // Check low-order bits bound
        let low_r = low_bits_vec(&r, params.gamma2);
        if infinity_norm_vec(&low_r) >= params.gamma2 - (params.tau as i64) * params.eta {
            continue;
        }

        // Step (h): Compute hint
        let cs2: PolyVec = sk.e.iter().map(|ei| poly_scalar_mul(&c, ei)).collect();
        let (h, hint_w) = make_hint_vec(&cs2, &r, params.gamma2);

        // Check hint weight
        if hint_w > params.omega {
            continue;
        }

        return Some((beta, VrfProof { c_tilde, z, h }));
    }

    // All attempts exhausted (astronomically unlikely)
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{EYVARA_I, N};
    use crate::keygen::eyvara_keygen;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_eval_produces_output() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_, sk) = eyvara_keygen(&EYVARA_I, &mut rng);
        let result = eyvara_eval(&EYVARA_I, &sk, b"test input", &mut rng);
        assert!(result.is_some(), "evaluation should succeed");
    }

    #[test]
    fn test_eval_output_is_deterministic() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_, sk) = eyvara_keygen(&EYVARA_I, &mut rng);

        let input = b"determinism test";

        let (beta1, _) = eyvara_eval(&EYVARA_I, &sk, input, &mut rng).unwrap();
        let mut rng2 = ChaCha20Rng::seed_from_u64(99); // different rng for proof randomness
        let (beta2, _) = eyvara_eval(&EYVARA_I, &sk, input, &mut rng2).unwrap();

        assert_eq!(beta1, beta2, "VRF output should be deterministic for same (sk, x)");
    }

    #[test]
    fn test_eval_different_inputs_different_outputs() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_, sk) = eyvara_keygen(&EYVARA_I, &mut rng);

        let (beta1, _) = eyvara_eval(&EYVARA_I, &sk, b"input1", &mut rng).unwrap();
        let (beta2, _) = eyvara_eval(&EYVARA_I, &sk, b"input2", &mut rng).unwrap();

        assert_ne!(beta1, beta2, "different inputs should produce different outputs");
    }

    #[test]
    fn test_eval_proof_structure() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_, sk) = eyvara_keygen(&EYVARA_I, &mut rng);

        let (_, proof) = eyvara_eval(&EYVARA_I, &sk, b"test", &mut rng).unwrap();

        assert_eq!(proof.c_tilde.len(), CHALLENGE_SEED_SIZE);
        assert_eq!(proof.z.len(), EYVARA_I.k);
        assert_eq!(proof.h.len(), EYVARA_I.k * N);

        // z norm should be within bounds
        assert!(infinity_norm_vec(&proof.z) < EYVARA_I.rejection_bound());

        // Hint weight should be within bounds
        let hw: usize = proof.h.iter().filter(|&&b| b != 0).count();
        assert!(hw <= EYVARA_I.omega);
    }
}

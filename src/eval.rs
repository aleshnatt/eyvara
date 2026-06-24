//! VRF evaluation for the Eyvara VRF.
//!
//! Implements evaluation with Fiat-Shamir with Aborts. The VRF output is bound
//! to the public commitment high bits `w1`, so verification can recompute it
//! without access to the secret vector.

use crate::challenge::{hash_to_challenge_seed, hash_vrf_output, sample_in_ball};
use crate::keygen::SecretKey;
use crate::params::{Params, CHALLENGE_SEED_SIZE, MAX_ATTEMPTS, OUTPUT_SIZE};
use crate::poly::{
    expand_a, high_bits_vec, infinity_norm_vec, low_bits_vec, make_hint_vec, poly_matrix_mul_ntt,
    poly_scalar_mul, poly_vec_add, poly_vec_sub, sample_uniform_gamma1_vec, PolyVec,
};
use rand::Rng;
use zeroize::Zeroizing;

/// VRF output: a 64-byte pseudorandom value.
///
/// The output is `SHAKE256("eyvara-output" || w1 || x)`, where `w1` is the
/// high-order commitment value recovered by the verifier.
pub type EyvaraOutput = [u8; OUTPUT_SIZE];

/// VRF proof enabling public verification of the output.
#[derive(Debug, Clone)]
pub struct EyvaraProof {
    /// Challenge seed `c_tilde = H_1(w1 || t || x)`.
    pub c_tilde: [u8; CHALLENGE_SEED_SIZE],

    /// Response vector `z = y + c*s`.
    pub z: PolyVec,

    /// Flattened hint vector used to recover the commitment high bits.
    pub h: Vec<i8>,

    /// High-order commitment value used to derive the challenge and output.
    pub w1: PolyVec,
}

/// Backwards-compatible alias for the VRF output type.
pub type VrfOutput = EyvaraOutput;

/// Backwards-compatible alias for the VRF proof type.
pub type VrfProof = EyvaraProof;

/// Evaluate the Eyvara VRF on input `x`.
///
/// Evaluation repeatedly samples a masking vector `y`, commits to `w = A*y`,
/// hashes the high bits `w1` into a sparse challenge, and forms the response
/// `z = y + c*s`. The loop rejects samples whose response norm, low bits, or
/// hint weight would leak secret-dependent information outside the configured
/// bounds. On an accepted iteration, the returned output is derived from `w1`
/// and the input so the verifier can recompute and bind it to the proof.
///
/// Returns `None` if all `MAX_ATTEMPTS` rejection-sampling iterations fail.
pub fn eyvara_eval<R: Rng>(
    params: &Params,
    sk: &SecretKey,
    x: &[u8],
    rng: &mut R,
) -> Option<(EyvaraOutput, EyvaraProof)> {
    let a_ntt = expand_a(&sk.rho, params.k);

    for _ in 0..MAX_ATTEMPTS {
        let y = Zeroizing::new(sample_uniform_gamma1_vec(rng, params.k, params.gamma1));

        let w = poly_matrix_mul_ntt(&a_ntt, &y);
        let w1 = high_bits_vec(&w, params.gamma2);
        let c_tilde = hash_to_challenge_seed(&w1, &sk.t, x);
        let c = sample_in_ball(&c_tilde, params.tau);

        let cs = Zeroizing::new(
            sk.s.iter()
                .map(|si| poly_scalar_mul(&c, si))
                .collect::<PolyVec>(),
        );
        let z = poly_vec_add(&y, &cs);

        if infinity_norm_vec(&z) >= params.rejection_bound() {
            continue;
        }

        let ct: PolyVec = sk.t.iter().map(|ti| poly_scalar_mul(&c, ti)).collect();
        let r = poly_vec_sub(&poly_matrix_mul_ntt(&a_ntt, &z), &ct);

        let low_r = low_bits_vec(&r, params.gamma2);
        if infinity_norm_vec(&low_r) >= params.gamma2 - (params.tau as i64) * params.eta {
            continue;
        }

        let neg_ce: PolyVec =
            sk.e.iter()
                .map(|ei| {
                    let mut cei = poly_scalar_mul(&c, ei);
                    for coeff in &mut cei {
                        *coeff = -*coeff;
                    }
                    cei
                })
                .collect();
        let (h, hint_w) = make_hint_vec(&neg_ce, &w, params.gamma2);

        if hint_w > params.omega {
            continue;
        }

        let output = hash_vrf_output(&w1, x);
        return Some((output, EyvaraProof { c_tilde, z, h, w1 }));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::eyvara_keygen;
    use crate::params::{EYVARA_128, N};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_eval_produces_output() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
        let result = eyvara_eval(&EYVARA_128, &sk, b"test input", &mut rng);
        assert!(result.is_some(), "evaluation should succeed");
    }

    #[test]
    fn test_eval_different_inputs_different_outputs() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_, sk) = eyvara_keygen(&EYVARA_128, &mut rng);

        let (beta1, _) = eyvara_eval(&EYVARA_128, &sk, b"input1", &mut rng).unwrap();
        let (beta2, _) = eyvara_eval(&EYVARA_128, &sk, b"input2", &mut rng).unwrap();

        assert_ne!(beta1, beta2, "different evaluations should differ");
    }

    #[test]
    fn test_eval_proof_structure() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_, sk) = eyvara_keygen(&EYVARA_128, &mut rng);

        let (_, proof) = eyvara_eval(&EYVARA_128, &sk, b"test", &mut rng).unwrap();

        assert_eq!(proof.c_tilde.len(), CHALLENGE_SEED_SIZE);
        assert_eq!(proof.z.len(), EYVARA_128.k);
        assert_eq!(proof.h.len(), EYVARA_128.k * N);
        assert_eq!(proof.w1.len(), EYVARA_128.k);
        assert!(infinity_norm_vec(&proof.z) < EYVARA_128.rejection_bound());

        let hw = proof.h.iter().filter(|&&b| b != 0).count();
        assert!(hw <= EYVARA_128.omega);
    }
}

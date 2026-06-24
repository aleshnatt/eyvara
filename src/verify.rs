//! VRF verification for the Eyvara VRF.
//!
//! Verification checks the proof transcript and recomputes the expected output
//! from the recovered high-order commitment bits.

use crate::challenge::{hash_to_challenge_seed, hash_vrf_output, sample_in_ball};
use crate::error::EyvaraError;
use crate::eval::{EyvaraOutput, EyvaraProof};
use crate::keygen::PublicKey;
use crate::params::{Params, N};
use crate::poly::{
    expand_a, hint_weight, infinity_norm_vec, poly_matrix_mul_ntt, poly_scalar_mul, poly_vec_sub,
    use_hint_vec,
};
use subtle::ConstantTimeEq;

/// Verify an Eyvara VRF proof and its claimed output.
///
/// Returns `Ok(true)` only if every check succeeds. Malformed public input is
/// reported as an error instead of panicking.
///
/// # Errors
///
/// Returns [`EyvaraError`] when the public key or proof is malformed, when
/// proof bounds are exceeded, or when the recomputed challenge or output does
/// not match the supplied values.
pub fn eyvara_verify(
    params: &Params,
    pk: &PublicKey,
    x: &[u8],
    output: &EyvaraOutput,
    proof: &EyvaraProof,
) -> Result<bool, EyvaraError> {
    if pk.t.len() != params.k() {
        return Err(EyvaraError::MalformedPublicKey);
    }

    if proof.z.len() != params.k() {
        return Err(EyvaraError::MalformedProof);
    }

    if proof.h.len() != params.k() * N {
        return Err(EyvaraError::MalformedProof);
    }

    if proof.h.iter().any(|&h| h != 0 && h != 1) {
        return Err(EyvaraError::MalformedProof);
    }

    if infinity_norm_vec(&proof.z) >= params.rejection_bound() {
        return Err(EyvaraError::NormBoundExceeded);
    }

    if hint_weight(&proof.h) > params.omega() {
        return Err(EyvaraError::HintWeightExceeded);
    }

    let a_ntt = expand_a(&pk.rho, params.k());
    let c = sample_in_ball(&proof.c_tilde, params.tau());

    let az = poly_matrix_mul_ntt(&a_ntt, &proof.z);
    let ct =
        pk.t.iter()
            .map(|ti| poly_scalar_mul(&c, ti))
            .collect::<Vec<_>>();
    let r = poly_vec_sub(&az, &ct)?;
    let w1_prime = use_hint_vec(&proof.h, &r, params.gamma_2())?;

    let c_tilde_prime = hash_to_challenge_seed(&w1_prime, &pk.t, x);
    if c_tilde_prime != proof.c_tilde {
        return Err(EyvaraError::ChallengeMismatch);
    }

    let expected_output = EyvaraOutput(hash_vrf_output(&w1_prime, x));
    if bool::from(expected_output.0.ct_eq(&output.0)) {
        Ok(true)
    } else {
        Err(EyvaraError::OutputMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval::eyvara_eval;
    use crate::keygen::eyvara_keygen;
    use crate::params::EYVARA_128;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_verify_honest_proof() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
        let input = b"verify test";
        let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, input, &mut rng).unwrap();

        assert!(
            eyvara_verify(&EYVARA_128, &pk, input, &beta, &proof).unwrap(),
            "honest proof should verify"
        );
    }

    #[test]
    fn test_verify_wrong_input() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
        let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, b"correct input", &mut rng).unwrap();

        assert_eq!(
            eyvara_verify(&EYVARA_128, &pk, b"wrong input", &beta, &proof),
            Err(EyvaraError::ChallengeMismatch)
        );
    }

    #[test]
    fn test_verify_wrong_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
        let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, b"test", &mut rng).unwrap();

        let mut rng2 = ChaCha20Rng::seed_from_u64(99);
        let (pk2, _) = eyvara_keygen(&EYVARA_128, &mut rng2);

        assert_eq!(
            eyvara_verify(&EYVARA_128, &pk2, b"test", &beta, &proof),
            Err(EyvaraError::ChallengeMismatch)
        );
    }

    #[test]
    fn test_verify_tampered_proof() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
        let (beta, mut proof) = eyvara_eval(&EYVARA_128, &sk, b"tamper test", &mut rng).unwrap();

        proof.c_tilde[0] ^= 1;

        assert_eq!(
            eyvara_verify(&EYVARA_128, &pk, b"tamper test", &beta, &proof),
            Err(EyvaraError::ChallengeMismatch)
        );
    }
}

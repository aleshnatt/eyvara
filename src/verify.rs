//! VRF verification for the Eyvara VRF.
//!
//! Verification checks the proof transcript and recomputes the expected output
//! from the recovered high-order commitment bits.

use crate::challenge::{hash_to_challenge_seed, hash_vrf_output, sample_in_ball};
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
/// Verification performs five checks:
///
/// 1. The response vector has the expected length and norm bound.
/// 2. The hint vector has the expected length, binary entries, and bounded
///    Hamming weight.
/// 3. The verifier recomputes `r = A*z - c*t` and recovers `w1_prime` with
///    `UseHint`.
/// 4. The Fiat-Shamir challenge seed is recomputed from `w1_prime`, the public
///    key vector, and the input, then compared with the proof challenge.
/// 5. The expected output `SHAKE256("eyvara-output" || w1_prime || x)` is
///    recomputed and compared with the claimed output using constant-time byte
///    equality.
///
/// Returns `true` only if every check succeeds.
pub fn eyvara_verify(
    params: &Params,
    pk: &PublicKey,
    x: &[u8],
    output: &EyvaraOutput,
    proof: &EyvaraProof,
) -> bool {
    if proof.z.len() != params.k || proof.w1.len() != params.k {
        return false;
    }

    if proof.h.len() != params.k * N {
        return false;
    }

    if infinity_norm_vec(&proof.z) >= params.rejection_bound() {
        return false;
    }

    if hint_weight(&proof.h) > params.omega {
        return false;
    }

    if proof.h.iter().any(|&h| h != 0 && h != 1) {
        return false;
    }

    let a_ntt = expand_a(&pk.rho, params.k);
    let c = sample_in_ball(&proof.c_tilde, params.tau);

    let az = poly_matrix_mul_ntt(&a_ntt, &proof.z);
    let ct =
        pk.t.iter()
            .map(|ti| poly_scalar_mul(&c, ti))
            .collect::<Vec<_>>();
    let r = poly_vec_sub(&az, &ct);
    let w1_prime = use_hint_vec(&proof.h, &r, params.gamma2);

    if w1_prime != proof.w1 {
        return false;
    }

    let c_tilde_prime = hash_to_challenge_seed(&w1_prime, &pk.t, x);
    if c_tilde_prime != proof.c_tilde {
        return false;
    }

    let expected_output = hash_vrf_output(&w1_prime, x);
    expected_output.ct_eq(output).into()
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
            eyvara_verify(&EYVARA_128, &pk, input, &beta, &proof),
            "honest proof should verify"
        );
    }

    #[test]
    fn test_verify_wrong_input() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
        let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, b"correct input", &mut rng).unwrap();

        assert!(
            !eyvara_verify(&EYVARA_128, &pk, b"wrong input", &beta, &proof),
            "proof should fail for wrong input"
        );
    }

    #[test]
    fn test_verify_wrong_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
        let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, b"test", &mut rng).unwrap();

        let mut rng2 = ChaCha20Rng::seed_from_u64(99);
        let (pk2, _) = eyvara_keygen(&EYVARA_128, &mut rng2);

        assert!(
            !eyvara_verify(&EYVARA_128, &pk2, b"test", &beta, &proof),
            "proof should fail with wrong public key"
        );
    }

    #[test]
    fn test_verify_tampered_proof() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
        let (beta, mut proof) = eyvara_eval(&EYVARA_128, &sk, b"tamper test", &mut rng).unwrap();

        proof.c_tilde[0] ^= 1;

        assert!(
            !eyvara_verify(&EYVARA_128, &pk, b"tamper test", &beta, &proof),
            "tampered proof should fail verification"
        );
    }
}

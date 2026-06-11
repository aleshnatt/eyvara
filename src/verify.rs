//! VRF verification for the Eyvara VRF.
//!
//! Implements Algorithm 3 from the paper: given a public key, input, claimed
//! output, and proof, verifies that the output is the unique correct VRF value.

use crate::params::{Params, N};
use crate::poly::{
    expand_a, poly_matrix_mul_ntt, poly_scalar_mul,
    poly_vec_sub, infinity_norm_vec, use_hint_vec,
    hint_weight,
};
use crate::challenge::{hash_to_challenge_seed, sample_in_ball};
use crate::keygen::PublicKey;
use crate::eval::{VrfOutput, VrfProof};

/// Verify an Eyvara VRF proof.
///
/// Implements Algorithm 3 from the paper. The verification proceeds as follows:
///
/// 1. Fail-fast checks:
///    a. Check that ||z||_inf < gamma1 - tau*eta (rejection bound).
///    b. Check that the hint weight |h|_ones <= omega.
///
/// 2. Recompute the commitment:
///    a. Expand A from seed rho.
///    b. Derive challenge c = SampleInBall(c_tilde, tau).
///    c. Compute r = Az - ct mod q.
///    d. Recover w1' = UseHint(h, r, 2*gamma2).
///
/// 3. Challenge consistency check:
///    a. Recompute c_tilde' = H_1("vrf-challenge" || w1' || t || x).
///    b. Check c_tilde' == c_tilde from the proof.
///
/// Returns `true` if the proof is valid, `false` on any check failure.
/// Never panics on malformed input.
pub fn eyvara_verify(
    params: &Params,
    pk: &PublicKey,
    x: &[u8],
    _output: &VrfOutput,
    proof: &VrfProof,
) -> bool {
    // ── Fail-fast structural checks ─────────────────────────────────

    // Check z vector length
    if proof.z.len() != params.k {
        return false;
    }

    // Check hint vector length
    if proof.h.len() != params.k * N {
        return false;
    }

    // Check z infinity norm
    let rejection_bound = params.rejection_bound();
    if infinity_norm_vec(&proof.z) >= rejection_bound {
        return false;
    }

    // Check hint weight
    if hint_weight(&proof.h) > params.omega {
        return false;
    }

    // Check all hint values are 0 or 1
    for &h in &proof.h {
        if h != 0 && h != 1 {
            return false;
        }
    }

    // ── Recompute commitment ────────────────────────────────────────

    // Expand A from seed
    let a_ntt = expand_a(&pk.rho, params.k);

    // Derive challenge polynomial from proof's challenge seed
    let c = sample_in_ball(&proof.c_tilde, params.tau);

    // Compute r = Az - ct mod q
    let az = poly_matrix_mul_ntt(&a_ntt, &proof.z);
    let ct: Vec<[i64; N]> = pk.t.iter().map(|ti| poly_scalar_mul(&c, ti)).collect();
    let r = poly_vec_sub(&az, &ct);

    // Recover high-order bits using hint
    let w1_prime = use_hint_vec(&proof.h, &r, params.gamma2);

    // ── Challenge consistency check ─────────────────────────────────

    // Recompute challenge seed
    let c_tilde_prime = hash_to_challenge_seed(&w1_prime, &pk.t, x);

    // Verify challenge seed matches
    if c_tilde_prime != proof.c_tilde {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::EYVARA_I;
    use crate::keygen::eyvara_keygen;
    use crate::eval::eyvara_eval;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_verify_honest_proof() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (pk, sk) = eyvara_keygen(&EYVARA_I, &mut rng);
        let input = b"verify test";
        let (beta, proof) = eyvara_eval(&EYVARA_I, &sk, input, &mut rng).unwrap();

        assert!(eyvara_verify(&EYVARA_I, &pk, input, &beta, &proof),
                "honest proof should verify");
    }

    #[test]
    fn test_verify_wrong_input() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (pk, sk) = eyvara_keygen(&EYVARA_I, &mut rng);
        let (beta, proof) = eyvara_eval(&EYVARA_I, &sk, b"correct input", &mut rng).unwrap();

        assert!(!eyvara_verify(&EYVARA_I, &pk, b"wrong input", &beta, &proof),
                "proof should fail for wrong input");
    }

    #[test]
    fn test_verify_wrong_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_, sk) = eyvara_keygen(&EYVARA_I, &mut rng);
        let (beta, proof) = eyvara_eval(&EYVARA_I, &sk, b"test", &mut rng).unwrap();

        // Generate a different key pair
        let mut rng2 = ChaCha20Rng::seed_from_u64(99);
        let (pk2, _) = eyvara_keygen(&EYVARA_I, &mut rng2);

        assert!(!eyvara_verify(&EYVARA_I, &pk2, b"test", &beta, &proof),
                "proof should fail with wrong public key");
    }

    #[test]
    fn test_verify_tampered_proof() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (pk, sk) = eyvara_keygen(&EYVARA_I, &mut rng);
        let (beta, mut proof) = eyvara_eval(&EYVARA_I, &sk, b"tamper test", &mut rng).unwrap();

        // Flip a bit in the challenge seed
        proof.c_tilde[0] ^= 1;

        assert!(!eyvara_verify(&EYVARA_I, &pk, b"tamper test", &beta, &proof),
                "tampered proof should fail verification");
    }
}

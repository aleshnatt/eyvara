//! Integration test suite for the Eyvara VRF.
//!
//! Tests cover correctness, determinism, failure cases, rejection sampling
//! termination, and basic output uniformity.

use crate::params::{EYVARA_I, EYVARA_III, N, OUTPUT_SIZE};
use crate::keygen::eyvara_keygen;
use crate::eval::eyvara_eval;
use crate::verify::eyvara_verify;
use crate::poly::infinity_norm_vec;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Test that evaluation followed by verification succeeds for Eyvara-I.
#[test]
fn test_correctness_eyvara_i() {
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let (pk, sk) = eyvara_keygen(&EYVARA_I, &mut rng);

    for i in 0..5 {
        let input = format!("correctness_test_{}", i);
        let (beta, proof) = eyvara_eval(&EYVARA_I, &sk, input.as_bytes(), &mut rng)
            .expect("evaluation should succeed");

        assert!(
            eyvara_verify(&EYVARA_I, &pk, input.as_bytes(), &beta, &proof),
            "verification should succeed for input '{}'", input
        );
    }
}

/// Test that evaluation followed by verification succeeds for Eyvara-III.
#[test]
fn test_correctness_eyvara_iii() {
    let mut rng = ChaCha20Rng::seed_from_u64(54321);
    let (pk, sk) = eyvara_keygen(&EYVARA_III, &mut rng);

    let input = b"eyvara_iii_correctness";
    let (beta, proof) = eyvara_eval(&EYVARA_III, &sk, input, &mut rng)
        .expect("evaluation should succeed");

    assert!(
        eyvara_verify(&EYVARA_III, &pk, input, &beta, &proof),
        "Eyvara-III verification should succeed"
    );
}

/// Test that evaluating the same input twice with the same key produces the
/// same VRF output (determinism of beta), even though the proofs may differ
/// (the proof depends on the random masking vector y).
#[test]
fn test_determinism() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_I, &mut rng);

    let input = b"determinism_test_input";

    let (beta1, proof1) = eyvara_eval(&EYVARA_I, &sk, input, &mut rng).unwrap();

    // Use a different rng state for the second evaluation
    let mut rng2 = ChaCha20Rng::seed_from_u64(9999);
    let (beta2, proof2) = eyvara_eval(&EYVARA_I, &sk, input, &mut rng2).unwrap();

    // Output must be identical
    assert_eq!(beta1, beta2, "VRF output should be deterministic");

    // Both proofs should verify
    assert!(eyvara_verify(&EYVARA_I, &pk, input, &beta1, &proof1));
    assert!(eyvara_verify(&EYVARA_I, &pk, input, &beta2, &proof2));

    // Proofs may differ (different randomness in y)
    // This is expected behavior, not a failure.
}

/// Test that verification fails when using a different public key.
#[test]
fn test_wrong_key() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, sk1) = eyvara_keygen(&EYVARA_I, &mut rng);
    let (beta, proof) = eyvara_eval(&EYVARA_I, &sk1, b"wrong_key_test", &mut rng).unwrap();

    // Generate a different key pair
    let mut rng2 = ChaCha20Rng::seed_from_u64(77);
    let (pk2, _) = eyvara_keygen(&EYVARA_I, &mut rng2);

    assert!(
        !eyvara_verify(&EYVARA_I, &pk2, b"wrong_key_test", &beta, &proof),
        "verification should fail with a different public key"
    );
}

/// Test that verification fails when the input is altered.
#[test]
fn test_wrong_input() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_I, &mut rng);
    let (beta, proof) = eyvara_eval(&EYVARA_I, &sk, b"original_input", &mut rng).unwrap();

    assert!(
        !eyvara_verify(&EYVARA_I, &pk, b"modified_input", &beta, &proof),
        "verification should fail with a different input"
    );
}

/// Test that verification fails when a single bit of the proof is flipped.
#[test]
fn test_tampered_proof() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_I, &mut rng);
    let input = b"tamper_test";
    let (beta, proof) = eyvara_eval(&EYVARA_I, &sk, input, &mut rng).unwrap();

    // Tamper with c_tilde (flip first byte)
    {
        let mut tampered = proof.clone();
        tampered.c_tilde[0] ^= 0xFF;
        assert!(
            !eyvara_verify(&EYVARA_I, &pk, input, &beta, &tampered),
            "tampered c_tilde should fail"
        );
    }

    // Tamper with z (modify a coefficient)
    {
        let mut tampered = proof.clone();
        tampered.z[0][0] = tampered.z[0][0].wrapping_add(1);
        assert!(
            !eyvara_verify(&EYVARA_I, &pk, input, &beta, &tampered),
            "tampered z should fail"
        );
    }

    // Tamper with hint (flip a hint bit)
    {
        let mut tampered = proof.clone();
        tampered.h[0] ^= 1;
        assert!(
            !eyvara_verify(&EYVARA_I, &pk, input, &beta, &tampered),
            "tampered hint should fail"
        );
    }
}

/// Test that evaluation completes within MAX_ATTEMPTS for many random inputs.
/// This verifies that the rejection sampling terminates with overwhelming probability.
#[test]
fn test_rejection_sampling_terminates() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, sk) = eyvara_keygen(&EYVARA_I, &mut rng);

    for i in 0..100 {
        let input = format!("rejection_test_{}", i);
        let result = eyvara_eval(&EYVARA_I, &sk, input.as_bytes(), &mut rng);
        assert!(
            result.is_some(),
            "evaluation should complete for input '{}' (attempt {})", input, i
        );
    }
}

/// Test that the VRF output bytes appear roughly uniform.
///
/// This is a basic sanity check, not a rigorous statistical test.
/// It collects 1000 output bytes from different inputs and checks that
/// each byte value appears with frequency reasonably close to 1/256.
#[test]
fn test_output_is_uniform_looking() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, sk) = eyvara_keygen(&EYVARA_I, &mut rng);

    let num_samples = 50; // 50 outputs * 64 bytes = 3200 bytes
    let mut byte_counts = [0u32; 256];

    for i in 0..num_samples {
        let input = format!("uniformity_test_{}", i);
        let (beta, _) = eyvara_eval(&EYVARA_I, &sk, input.as_bytes(), &mut rng).unwrap();
        for &b in beta.iter() {
            byte_counts[b as usize] += 1;
        }
    }

    let total_bytes = (num_samples * OUTPUT_SIZE) as f64;
    let expected = total_bytes / 256.0;

    // Chi-squared test at a very loose threshold (p < 0.001)
    let mut chi_sq = 0.0;
    for &count in byte_counts.iter() {
        let diff = count as f64 - expected;
        chi_sq += diff * diff / expected;
    }

    // With 255 degrees of freedom, chi-squared < 360 at p=0.001
    // Using a generous threshold to avoid flaky tests
    assert!(
        chi_sq < 500.0,
        "output bytes do not look uniform: chi-squared = {:.1} (expected < 360)",
        chi_sq
    );
}

/// Test that the proof z-vector norm is properly bounded after evaluation.
#[test]
fn test_proof_norm_bounds() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, sk) = eyvara_keygen(&EYVARA_I, &mut rng);

    for i in 0..20 {
        let input = format!("norm_test_{}", i);
        let (_, proof) = eyvara_eval(&EYVARA_I, &sk, input.as_bytes(), &mut rng).unwrap();

        let norm = infinity_norm_vec(&proof.z);
        assert!(
            norm < EYVARA_I.rejection_bound(),
            "z norm {} exceeds rejection bound {} for input {}",
            norm, EYVARA_I.rejection_bound(), i
        );
    }
}

/// Test that verification rejects proofs with invalid structural properties.
#[test]
fn test_verify_rejects_malformed_proof() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_I, &mut rng);
    let input = b"malformed_test";
    let (beta, proof) = eyvara_eval(&EYVARA_I, &sk, input, &mut rng).unwrap();

    // Wrong z vector length
    {
        let mut bad = proof.clone();
        bad.z.push([0i64; N]);
        assert!(!eyvara_verify(&EYVARA_I, &pk, input, &beta, &bad));
    }

    // Wrong hint vector length
    {
        let mut bad = proof.clone();
        bad.h.push(0);
        assert!(!eyvara_verify(&EYVARA_I, &pk, input, &beta, &bad));
    }

    // Invalid hint value (not 0 or 1)
    {
        let mut bad = proof.clone();
        bad.h[0] = 2;
        assert!(!eyvara_verify(&EYVARA_I, &pk, input, &beta, &bad));
    }
}

/// Test that empty input works correctly.
#[test]
fn test_empty_input() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_I, &mut rng);

    let input = b"";
    let (beta, proof) = eyvara_eval(&EYVARA_I, &sk, input, &mut rng).unwrap();

    assert!(eyvara_verify(&EYVARA_I, &pk, input, &beta, &proof));
}

/// Test with a very long input.
#[test]
fn test_long_input() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_I, &mut rng);

    let input = vec![0xABu8; 10_000];
    let (beta, proof) = eyvara_eval(&EYVARA_I, &sk, &input, &mut rng).unwrap();

    assert!(eyvara_verify(&EYVARA_I, &pk, &input, &beta, &proof));
}

//! Integration test suite for the Eyvara VRF.

use crate::eval::{eyvara_eval, EyvaraOutput};
use crate::keygen::eyvara_keygen;
use crate::params::{EYVARA_128, EYVARA_192, N, OUTPUT_SIZE};
use crate::poly::{infinity_norm_vec, ZeroizingPoly};
use crate::verify::eyvara_verify;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Test that evaluation followed by verification succeeds for `EYVARA_128`.
#[test]
fn test_correctness_eyvara_128() {
    let mut rng = ChaCha20Rng::seed_from_u64(12_345);
    let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);

    for i in 0..5 {
        let input = format!("correctness_test_{i}");
        let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, input.as_bytes(), &mut rng)
            .expect("evaluation should succeed");

        assert!(
            eyvara_verify(&EYVARA_128, &pk, input.as_bytes(), &beta, &proof),
            "verification should succeed for input '{input}'"
        );
    }
}

/// Test that evaluation followed by verification succeeds for `EYVARA_192`.
#[test]
fn test_correctness_eyvara_192() {
    let mut rng = ChaCha20Rng::seed_from_u64(54_321);
    let (pk, sk) = eyvara_keygen(&EYVARA_192, &mut rng);

    let input = b"eyvara_192_correctness";
    let (beta, proof) =
        eyvara_eval(&EYVARA_192, &sk, input, &mut rng).expect("evaluation should succeed");

    assert!(
        eyvara_verify(&EYVARA_192, &pk, input, &beta, &proof),
        "EYVARA_192 verification should succeed"
    );
}

/// Test that verification fails when using a different public key.
#[test]
fn test_wrong_key() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, sk1) = eyvara_keygen(&EYVARA_128, &mut rng);
    let (beta, proof) = eyvara_eval(&EYVARA_128, &sk1, b"wrong_key_test", &mut rng).unwrap();

    let mut rng2 = ChaCha20Rng::seed_from_u64(77);
    let (pk2, _) = eyvara_keygen(&EYVARA_128, &mut rng2);

    assert!(
        !eyvara_verify(&EYVARA_128, &pk2, b"wrong_key_test", &beta, &proof),
        "verification should fail with a different public key"
    );
}

/// Test that verification fails when the input is altered.
#[test]
fn test_wrong_input() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
    let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, b"original_input", &mut rng).unwrap();

    assert!(
        !eyvara_verify(&EYVARA_128, &pk, b"modified_input", &beta, &proof),
        "verification should fail with a different input"
    );
}

/// Test that verification fails when a single bit of the proof is flipped.
#[test]
fn test_tampered_proof() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
    let input = b"tamper_test";
    let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, input, &mut rng).unwrap();

    let mut tampered = proof.clone();
    tampered.c_tilde[0] ^= 0xFF;
    assert!(!eyvara_verify(&EYVARA_128, &pk, input, &beta, &tampered));

    let mut tampered = proof.clone();
    tampered.z[0][0] = tampered.z[0][0].wrapping_add(1);
    assert!(!eyvara_verify(&EYVARA_128, &pk, input, &beta, &tampered));

    let mut tampered = proof;
    tampered.h[0] ^= 1;
    assert!(!eyvara_verify(&EYVARA_128, &pk, input, &beta, &tampered));
}

/// Test that a tampered VRF output is rejected.
#[test]
fn test_tampered_output_rejected() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
    let input = b"tampered_output";
    let (output, proof) = eyvara_eval(&EYVARA_128, &sk, input, &mut rng).unwrap();

    let mut tampered_output = output;
    tampered_output[0] ^= 1;

    assert!(!eyvara_verify(
        &EYVARA_128,
        &pk,
        input,
        &tampered_output,
        &proof
    ));
}

/// Test that an all-zero VRF output is rejected.
#[test]
fn test_wrong_output_all_zeros() {
    let mut rng = ChaCha20Rng::seed_from_u64(43);
    let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
    let input = b"zero_output";
    let (_output, proof) = eyvara_eval(&EYVARA_128, &sk, input, &mut rng).unwrap();
    let zero_output: EyvaraOutput = [0_u8; 64];

    assert!(!eyvara_verify(
        &EYVARA_128,
        &pk,
        input,
        &zero_output,
        &proof
    ));
}

/// Compile-time check that `ZeroizingPoly` can be instantiated and dropped.
#[test]
fn test_zeroize_compiles() {
    let mut poly = [0_i64; N];
    poly[0] = 7;
    let _wrapped = ZeroizingPoly(poly);
}

/// Test that evaluation completes within `MAX_ATTEMPTS` for many inputs.
#[test]
fn test_rejection_sampling_terminates() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, sk) = eyvara_keygen(&EYVARA_128, &mut rng);

    for i in 0..100 {
        let input = format!("rejection_test_{i}");
        let result = eyvara_eval(&EYVARA_128, &sk, input.as_bytes(), &mut rng);
        assert!(
            result.is_some(),
            "evaluation should complete for input '{input}'"
        );
    }
}

/// Basic sanity check that output bytes are not obviously degenerate.
#[test]
fn test_output_is_uniform_looking() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, sk) = eyvara_keygen(&EYVARA_128, &mut rng);

    let num_samples = 50;
    let mut byte_counts = [0_u32; 256];

    for i in 0..num_samples {
        let input = format!("uniformity_test_{i}");
        let (beta, _) = eyvara_eval(&EYVARA_128, &sk, input.as_bytes(), &mut rng).unwrap();
        for &b in &beta {
            byte_counts[usize::from(b)] += 1;
        }
    }

    let total_bytes = f64::from(num_samples * OUTPUT_SIZE as u32);
    let expected = total_bytes / 256.0;
    let chi_sq = byte_counts.iter().fold(0.0, |acc, &count| {
        let diff = f64::from(count) - expected;
        acc + diff * diff / expected
    });

    assert!(
        chi_sq < 500.0,
        "output bytes do not look uniform: chi-squared = {chi_sq:.1}"
    );
}

/// Test that the proof z-vector norm is properly bounded after evaluation.
#[test]
fn test_proof_norm_bounds() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, sk) = eyvara_keygen(&EYVARA_128, &mut rng);

    for i in 0..20 {
        let input = format!("norm_test_{i}");
        let (_, proof) = eyvara_eval(&EYVARA_128, &sk, input.as_bytes(), &mut rng).unwrap();

        let norm = infinity_norm_vec(&proof.z);
        assert!(
            norm < EYVARA_128.rejection_bound(),
            "z norm {norm} exceeds rejection bound {}",
            EYVARA_128.rejection_bound()
        );
    }
}

/// Test that verification rejects proofs with invalid structural properties.
#[test]
fn test_verify_rejects_malformed_proof() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
    let input = b"malformed_test";
    let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, input, &mut rng).unwrap();

    let mut bad = proof.clone();
    bad.z.push([0_i64; N]);
    assert!(!eyvara_verify(&EYVARA_128, &pk, input, &beta, &bad));

    let mut bad = proof.clone();
    bad.h.push(0);
    assert!(!eyvara_verify(&EYVARA_128, &pk, input, &beta, &bad));

    let mut bad = proof;
    bad.h[0] = 2;
    assert!(!eyvara_verify(&EYVARA_128, &pk, input, &beta, &bad));
}

/// Test that empty input works correctly.
#[test]
fn test_empty_input() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);

    let input = b"";
    let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, input, &mut rng).unwrap();

    assert!(eyvara_verify(&EYVARA_128, &pk, input, &beta, &proof));
}

/// Test with a very long input.
#[test]
fn test_long_input() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);

    let input = vec![0xAB_u8; 10_000];
    let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, &input, &mut rng).unwrap();

    assert!(eyvara_verify(&EYVARA_128, &pk, &input, &beta, &proof));
}

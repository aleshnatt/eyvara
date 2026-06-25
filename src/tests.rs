//! Integration test suite for the Eyvara VRF.

use crate::error::EyvaraError;
use crate::eval::{eyvara_eval, EyvaraOutput};
use crate::keygen::eyvara_keygen;
use crate::params::{EYVARA_128, EYVARA_192, N, OUTPUT_SIZE};
use crate::poly::{infinity_norm_vec, ZeroizingPoly};
use crate::verify::eyvara_verify;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn test_correctness_eyvara_128() {
    // Seeded for determinism; real usage requires OsRng.
    let mut rng = ChaCha20Rng::seed_from_u64(12_345);
    let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);

    for i in 0..5 {
        let input = format!("correctness_test_{i}");
        let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, input.as_bytes()).unwrap();

        assert!(
            eyvara_verify(&EYVARA_128, &pk, input.as_bytes(), &beta, &proof).unwrap(),
            "verification should succeed for input '{input}'"
        );
    }
}

#[test]
fn test_correctness_eyvara_192() {
    // Seeded for determinism; real usage requires OsRng.
    let mut rng = ChaCha20Rng::seed_from_u64(54_321);
    let (pk, sk) = eyvara_keygen(&EYVARA_192, &mut rng);

    let input = b"eyvara_192_correctness";
    let (beta, proof) = eyvara_eval(&EYVARA_192, &sk, input).unwrap();

    assert!(
        eyvara_verify(&EYVARA_192, &pk, input, &beta, &proof).unwrap(),
        "EYVARA_192 verification should succeed"
    );
}

#[test]
fn test_eval_is_deterministic() {
    // Seeded for determinism; real usage requires OsRng.
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
    let input = b"deterministic_eval";

    let (output1, proof1) = eyvara_eval(&EYVARA_128, &sk, input).unwrap();
    let (output2, proof2) = eyvara_eval(&EYVARA_128, &sk, input).unwrap();

    assert_eq!(output1, output2);
    assert_eq!(proof1.c_tilde, proof2.c_tilde);
    assert_eq!(proof1.z, proof2.z);
    assert!(eyvara_verify(&EYVARA_128, &pk, input, &output1, &proof1).unwrap());
}

#[test]
fn test_eval_different_inputs_differ() {
    // Seeded for determinism; real usage requires OsRng.
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, sk) = eyvara_keygen(&EYVARA_128, &mut rng);

    let (output_a, _) = eyvara_eval(&EYVARA_128, &sk, b"input_a").unwrap();
    let (output_b, _) = eyvara_eval(&EYVARA_128, &sk, b"input_b").unwrap();

    assert_ne!(output_a, output_b);
}

#[test]
fn test_eval_different_keys_differ() {
    // Seeded for determinism; real usage requires OsRng.
    let mut rng1 = ChaCha20Rng::seed_from_u64(42);
    let (_, sk1) = eyvara_keygen(&EYVARA_128, &mut rng1);
    // Seeded for determinism; real usage requires OsRng.
    let mut rng2 = ChaCha20Rng::seed_from_u64(43);
    let (_, sk2) = eyvara_keygen(&EYVARA_128, &mut rng2);
    let input = b"same_input";

    let (output1, _) = eyvara_eval(&EYVARA_128, &sk1, input).unwrap();
    let (output2, _) = eyvara_eval(&EYVARA_128, &sk2, input).unwrap();

    assert_ne!(output1, output2);
}

#[test]
fn test_wrong_key() {
    // Seeded for determinism; real usage requires OsRng.
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, sk1) = eyvara_keygen(&EYVARA_128, &mut rng);
    let (beta, proof) = eyvara_eval(&EYVARA_128, &sk1, b"wrong_key_test").unwrap();

    // Seeded for determinism; real usage requires OsRng.
    let mut rng2 = ChaCha20Rng::seed_from_u64(77);
    let (pk2, _) = eyvara_keygen(&EYVARA_128, &mut rng2);

    assert_eq!(
        eyvara_verify(&EYVARA_128, &pk2, b"wrong_key_test", &beta, &proof),
        Err(EyvaraError::ChallengeMismatch)
    );
}

#[test]
fn test_wrong_input() {
    // Seeded for determinism; real usage requires OsRng.
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
    let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, b"original_input").unwrap();

    assert_eq!(
        eyvara_verify(&EYVARA_128, &pk, b"modified_input", &beta, &proof),
        Err(EyvaraError::ChallengeMismatch)
    );
}

#[test]
fn test_tampered_proof() {
    // Seeded for determinism; real usage requires OsRng.
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
    let input = b"tamper_test";
    let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, input).unwrap();

    let mut tampered = proof.clone();
    tampered.c_tilde[0] ^= 0xFF;
    assert_eq!(
        eyvara_verify(&EYVARA_128, &pk, input, &beta, &tampered),
        Err(EyvaraError::ChallengeMismatch)
    );

    let mut tampered = proof.clone();
    tampered.z[0][0] = tampered.z[0][0].wrapping_add(1);
    assert!(eyvara_verify(&EYVARA_128, &pk, input, &beta, &tampered).is_err());

    let mut tampered = proof;
    tampered.h[0] ^= 1;
    assert!(eyvara_verify(&EYVARA_128, &pk, input, &beta, &tampered).is_err());
}

#[test]
fn test_tampered_output_rejected() {
    // Seeded for determinism; real usage requires OsRng.
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
    let input = b"tampered_output";
    let (mut output, proof) = eyvara_eval(&EYVARA_128, &sk, input).unwrap();

    output[0] ^= 1;

    assert_eq!(
        eyvara_verify(&EYVARA_128, &pk, input, &output, &proof),
        Err(EyvaraError::OutputMismatch)
    );
}

#[test]
fn test_wrong_output_all_zeros() {
    // Seeded for determinism; real usage requires OsRng.
    let mut rng = ChaCha20Rng::seed_from_u64(43);
    let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
    let input = b"zero_output";
    let (_output, proof) = eyvara_eval(&EYVARA_128, &sk, input).unwrap();
    let zero_output = EyvaraOutput([0_u8; OUTPUT_SIZE]);

    assert_eq!(
        eyvara_verify(&EYVARA_128, &pk, input, &zero_output, &proof),
        Err(EyvaraError::OutputMismatch)
    );
}

#[test]
fn test_zeroize_compiles() {
    let mut poly = [0_i64; N];
    poly[0] = 7;
    let _wrapped = ZeroizingPoly(poly);
}

#[test]
fn test_rejection_sampling_terminates() {
    // Seeded for determinism; real usage requires OsRng.
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, sk) = eyvara_keygen(&EYVARA_128, &mut rng);

    for i in 0..100 {
        let input = format!("rejection_test_{i}");
        let result = eyvara_eval(&EYVARA_128, &sk, input.as_bytes());
        assert!(
            result.is_ok(),
            "evaluation should complete for input '{input}'"
        );
    }
}

#[test]
fn test_output_is_uniform_looking() {
    // Seeded for determinism; real usage requires OsRng.
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, sk) = eyvara_keygen(&EYVARA_128, &mut rng);

    let num_samples = 50;
    let mut byte_counts = [0_u32; 256];

    for i in 0..num_samples {
        let input = format!("uniformity_test_{i}");
        let (beta, _) = eyvara_eval(&EYVARA_128, &sk, input.as_bytes()).unwrap();
        for &b in beta.as_ref() {
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

#[test]
fn test_proof_norm_bounds() {
    // Seeded for determinism; real usage requires OsRng.
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, sk) = eyvara_keygen(&EYVARA_128, &mut rng);

    for i in 0..20 {
        let input = format!("norm_test_{i}");
        let (_, proof) = eyvara_eval(&EYVARA_128, &sk, input.as_bytes()).unwrap();

        let norm = infinity_norm_vec(&proof.z);
        assert!(
            norm < EYVARA_128.rejection_bound(),
            "z norm {norm} exceeds rejection bound {}",
            EYVARA_128.rejection_bound()
        );
    }
}

#[test]
fn test_malformed_proof_returns_err() {
    // Seeded for determinism; real usage requires OsRng.
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
    let input = b"malformed_test";
    let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, input).unwrap();

    let mut bad = proof.clone();
    bad.z.push([0_i64; N]);
    assert_eq!(
        eyvara_verify(&EYVARA_128, &pk, input, &beta, &bad),
        Err(EyvaraError::MalformedProof)
    );

    let mut bad = proof.clone();
    bad.h.push(0);
    assert_eq!(
        eyvara_verify(&EYVARA_128, &pk, input, &beta, &bad),
        Err(EyvaraError::MalformedProof)
    );

    let mut bad = proof;
    bad.h[0] = 2;
    assert_eq!(
        eyvara_verify(&EYVARA_128, &pk, input, &beta, &bad),
        Err(EyvaraError::MalformedProof)
    );
}

#[test]
fn test_malformed_pubkey_returns_err() {
    // Seeded for determinism; real usage requires OsRng.
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (mut pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
    let input = b"malformed_public_key";
    let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, input).unwrap();

    pk.t.pop();
    assert_eq!(
        eyvara_verify(&EYVARA_128, &pk, input, &beta, &proof),
        Err(EyvaraError::MalformedPublicKey)
    );
}

#[test]
fn test_empty_input() {
    // Seeded for determinism; real usage requires OsRng.
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);

    let input = b"";
    let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, input).unwrap();

    assert!(eyvara_verify(&EYVARA_128, &pk, input, &beta, &proof).unwrap());
}

#[test]
fn test_long_input() {
    // Seeded for determinism; real usage requires OsRng.
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);

    let input = vec![0xAB_u8; 10_000];
    let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, &input).unwrap();

    assert!(eyvara_verify(&EYVARA_128, &pk, &input, &beta, &proof).unwrap());
}

#[cfg(feature = "serde")]
#[test]
fn test_serde_roundtrip_type_coverage() {
    fn assert_public_key<T>()
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
    }

    fn assert_proof<T>()
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
    }

    fn assert_output<T>()
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
    }

    assert_public_key::<crate::keygen::PublicKey>();
    assert_proof::<crate::eval::EyvaraProof>();
    assert_output::<EyvaraOutput>();
}

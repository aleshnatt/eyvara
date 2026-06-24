//! VRF evaluation for the Eyvara VRF.
//!
//! Implements evaluation with Fiat-Shamir with Aborts. The VRF output is bound
//! to the commitment high bits recovered by verification.

use crate::challenge::{hash_to_challenge_seed, hash_vrf_output, sample_in_ball};
use crate::error::EyvaraError;
use crate::keygen::SecretKey;
use crate::params::{Params, CHALLENGE_SEED_SIZE, MAX_ATTEMPTS, OUTPUT_SIZE};
use crate::poly::{
    expand_a, high_bits_vec, infinity_norm_vec, low_bits_vec, make_hint_vec, poly_matrix_mul_ntt,
    poly_scalar_mul, poly_vec_add, poly_vec_sub, sample_uniform_gamma1_vec, PolyVec,
};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// VRF output: a 64-byte pseudorandom value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EyvaraOutput(pub [u8; OUTPUT_SIZE]);

impl AsRef<[u8]> for EyvaraOutput {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::Deref for EyvaraOutput {
    type Target = [u8; OUTPUT_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for EyvaraOutput {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// VRF proof enabling public verification of the output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EyvaraProof {
    /// Challenge seed `c_tilde = H_1(w1 || t || x)`.
    pub c_tilde: [u8; CHALLENGE_SEED_SIZE],

    /// Response vector `z = y + c*s`.
    pub z: PolyVec,

    /// Flattened hint vector used to recover the commitment high bits.
    pub h: Vec<i8>,
}

/// Backwards-compatible alias for the VRF output type.
pub type VrfOutput = EyvaraOutput;

/// Backwards-compatible alias for the VRF proof type.
pub type VrfProof = EyvaraProof;

#[cfg(feature = "serde")]
impl serde::Serialize for EyvaraOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for EyvaraOutput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct OutputVisitor;

        impl<'de> serde::de::Visitor<'de> for OutputVisitor {
            type Value = EyvaraOutput;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a 64-byte Eyvara VRF output")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() != OUTPUT_SIZE {
                    return Err(E::invalid_length(value.len(), &self));
                }
                let mut out = [0_u8; OUTPUT_SIZE];
                out.copy_from_slice(value);
                Ok(EyvaraOutput(out))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut out = [0_u8; OUTPUT_SIZE];
                for (idx, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(idx, &self))?;
                }
                Ok(EyvaraOutput(out))
            }
        }

        deserializer.deserialize_bytes(OutputVisitor)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for EyvaraProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("EyvaraProof", 3)?;
        state.serialize_field("c_tilde", &self.c_tilde.as_slice())?;
        state.serialize_field("z", &crate::poly::polyvec_to_nested_vec(&self.z))?;
        state.serialize_field("h", &self.h)?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for EyvaraProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct ProofRepr {
            c_tilde: Vec<u8>,
            z: Vec<Vec<i64>>,
            h: Vec<i8>,
        }

        let repr = ProofRepr::deserialize(deserializer)?;
        if repr.c_tilde.len() != CHALLENGE_SEED_SIZE {
            return Err(serde::de::Error::invalid_length(
                repr.c_tilde.len(),
                &"32-byte challenge seed",
            ));
        }
        let mut c_tilde = [0_u8; CHALLENGE_SEED_SIZE];
        c_tilde.copy_from_slice(&repr.c_tilde);
        let z = crate::poly::nested_vec_to_polyvec(repr.z).map_err(serde::de::Error::custom)?;
        Ok(Self {
            c_tilde,
            z,
            h: repr.h,
        })
    }
}

/// Evaluates the VRF on `x` and returns the output plus a publicly verifiable proof.
///
/// # Errors
///
/// Returns [`EyvaraError::RejectionSamplingFailed`] if all `MAX_ATTEMPTS`
/// rejection-sampling iterations fail.
pub fn eyvara_eval<R>(
    params: &Params,
    sk: &SecretKey,
    x: &[u8],
    rng: &mut R,
) -> Result<(EyvaraOutput, EyvaraProof), EyvaraError>
where
    R: CryptoRng + RngCore,
{
    let a_ntt = expand_a(sk.rho(), params.k());

    // Rejection sampling usually succeeds quickly; EYVARA_128 is expected to
    // need roughly four attempts or fewer in normal runs.
    for _ in 0..MAX_ATTEMPTS {
        // y masks the secret contribution in z, so wipe it after each attempt.
        let y = Zeroizing::new(sample_uniform_gamma1_vec(rng, params.k(), params.gamma_1()));

        let w = poly_matrix_mul_ntt(&a_ntt, &y);
        let w1 = high_bits_vec(&w, params.gamma_2());
        let c_tilde = hash_to_challenge_seed(&w1, sk.t(), x);
        let c = sample_in_ball(&c_tilde, params.tau());

        let cs = Zeroizing::new(
            sk.s()
                .iter()
                .map(|si| poly_scalar_mul(&c, si))
                .collect::<PolyVec>(),
        );
        let z = poly_vec_add(&y, &cs)?;

        if infinity_norm_vec(&z) >= params.rejection_bound() {
            continue;
        }

        let ct: PolyVec = sk.t().iter().map(|ti| poly_scalar_mul(&c, ti)).collect();
        let r = poly_vec_sub(&poly_matrix_mul_ntt(&a_ntt, &z), &ct)?;

        let low_r = low_bits_vec(&r, params.gamma_2());
        if infinity_norm_vec(&low_r) >= params.gamma_2() - params.beta() {
            continue;
        }

        let neg_ce: PolyVec = sk
            .e()
            .iter()
            .map(|ei| {
                let mut cei = poly_scalar_mul(&c, ei);
                for coeff in &mut cei {
                    *coeff = -*coeff;
                }
                cei
            })
            .collect();
        let (h, hint_w) = make_hint_vec(&neg_ce, &w, params.gamma_2())?;

        if hint_w > params.omega() {
            continue;
        }

        // Output is derived from w1, not s, so the verifier can recompute
        // it independently via UseHint without knowing the secret key.
        let output = EyvaraOutput(hash_vrf_output(&w1, x));
        return Ok((output, EyvaraProof { c_tilde, z, h }));
    }

    Err(EyvaraError::RejectionSamplingFailed)
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
        // Seeded for determinism; real usage requires OsRng.
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
        let result = eyvara_eval(&EYVARA_128, &sk, b"test input", &mut rng);
        assert!(result.is_ok(), "evaluation should succeed");
    }

    #[test]
    fn test_eval_different_inputs_different_outputs() {
        // Seeded for determinism; real usage requires OsRng.
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_, sk) = eyvara_keygen(&EYVARA_128, &mut rng);

        let (beta1, _) = eyvara_eval(&EYVARA_128, &sk, b"input1", &mut rng).unwrap();
        let (beta2, _) = eyvara_eval(&EYVARA_128, &sk, b"input2", &mut rng).unwrap();

        assert_ne!(beta1, beta2, "different evaluations should differ");
    }

    #[test]
    fn test_eval_proof_structure() {
        // Seeded for determinism; real usage requires OsRng.
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_, sk) = eyvara_keygen(&EYVARA_128, &mut rng);

        let (_, proof) = eyvara_eval(&EYVARA_128, &sk, b"test", &mut rng).unwrap();

        assert_eq!(proof.c_tilde.len(), CHALLENGE_SEED_SIZE);
        assert_eq!(proof.z.len(), EYVARA_128.k());
        assert_eq!(proof.h.len(), EYVARA_128.k() * N);
        assert!(infinity_norm_vec(&proof.z) < EYVARA_128.rejection_bound());

        let hw = proof.h.iter().filter(|&&b| b != 0).count();
        assert!(hw <= EYVARA_128.omega());
    }
}

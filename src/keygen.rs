//! Key generation for the Eyvara VRF.
//!
//! Implements key generation from the MLWE assumption. The public key contains
//! the public matrix seed and public vector. The secret key keeps the short
//! vectors private and redacts them in debug output.

use crate::ntt::{ntt_forward, ntt_inverse, ntt_pointwise_mul, reduce_coeff};
use crate::params::{Params, N, SEED_SIZE};
use crate::poly::{expand_a, poly_zero, sample_cbd_vec, Poly, PolyVec};
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Public key for the Eyvara VRF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// Seed for deterministic matrix expansion via ExpandA.
    pub rho: [u8; SEED_SIZE],

    /// Public vector t = As + e mod q, where s and e are short secret vectors.
    pub t: PolyVec,
}

/// Secret key for the Eyvara VRF.
///
/// Secret vectors are private, are not cloneable through the public API, and
/// are redacted in debug output. The key zeroizes its memory when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    seed: [u8; SEED_SIZE],
    rho: [u8; SEED_SIZE],
    s: PolyVec,
    e: PolyVec,
    t: PolyVec,
    #[zeroize(skip)]
    public_key: PublicKey,
}

#[cfg(feature = "serde")]
impl serde::Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("PublicKey", 2)?;
        state.serialize_field("rho", &self.rho.as_slice())?;
        state.serialize_field("t", &crate::poly::polyvec_to_nested_vec(&self.t))?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct PublicKeyRepr {
            rho: Vec<u8>,
            t: Vec<Vec<i64>>,
        }

        let repr = PublicKeyRepr::deserialize(deserializer)?;
        if repr.rho.len() != SEED_SIZE {
            return Err(serde::de::Error::invalid_length(
                repr.rho.len(),
                &"32-byte public matrix seed",
            ));
        }
        let mut rho = [0_u8; SEED_SIZE];
        rho.copy_from_slice(&repr.rho);
        let t = crate::poly::nested_vec_to_polyvec(repr.t).map_err(serde::de::Error::custom)?;
        Ok(Self { rho, t })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("SecretKey", 5)?;
        state.serialize_field("seed", &self.seed.as_slice())?;
        state.serialize_field("rho", &self.rho.as_slice())?;
        state.serialize_field("s", &crate::poly::polyvec_to_nested_vec(&self.s))?;
        state.serialize_field("e", &crate::poly::polyvec_to_nested_vec(&self.e))?;
        state.serialize_field("t", &crate::poly::polyvec_to_nested_vec(&self.t))?;
        state.end()
    }
}

impl SecretKey {
    /// Reconstructs a `SecretKey` from its serialized components.
    ///
    /// All fields must have been produced by a prior call to [`eyvara_keygen`].
    /// No validation of the cryptographic relationship between fields is
    /// performed.
    #[cfg(feature = "serde")]
    pub fn from_parts(
        rho: [u8; SEED_SIZE],
        s: PolyVec,
        e: PolyVec,
        t: PolyVec,
        seed: [u8; SEED_SIZE],
    ) -> Self {
        let public_key = PublicKey { rho, t: t.clone() };
        Self {
            seed,
            rho,
            s,
            e,
            t,
            public_key,
        }
    }

    /// Returns the public matrix seed. Safe to expose.
    pub fn rho(&self) -> &[u8; SEED_SIZE] {
        &self.rho
    }

    /// Returns the public key component corresponding to this secret key.
    ///
    /// This does not expose the secret vectors `s` or `e`.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub(crate) fn s(&self) -> &PolyVec {
        &self.s
    }

    pub(crate) fn e(&self) -> &PolyVec {
        &self.e
    }

    pub(crate) fn t(&self) -> &PolyVec {
        &self.t
    }

    pub(crate) fn seed(&self) -> &[u8; SEED_SIZE] {
        &self.seed
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact secret material from debug output.
        f.debug_struct("SecretKey")
            .field("rho", &self.rho)
            .field("seed", &"[REDACTED]")
            .field("s", &"[REDACTED]")
            .field("e", &"[REDACTED]")
            .field("t", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Generates a public key and non-cloneable secret key using a cryptographic
/// RNG. The caller must supply a [`CryptoRng`] so key material is never derived
/// from predictable randomness in normal use.
pub fn eyvara_keygen<R>(params: &Params, rng: &mut R) -> (PublicKey, SecretKey)
where
    R: CryptoRng + RngCore,
{
    let mut seed = [0u8; SEED_SIZE];
    rng.fill_bytes(&mut seed);

    let mut rho = [0u8; SEED_SIZE];
    rng.fill_bytes(&mut rho);

    let a_ntt = expand_a(&rho, params.k());
    let s = sample_cbd_vec(rng, params.k(), params.eta());
    let e = sample_cbd_vec(rng, params.k(), params.eta());

    let s_ntt: Vec<Poly> = s
        .iter()
        .map(|p| {
            let mut pn = *p;
            ntt_forward(&mut pn);
            pn
        })
        .collect();

    let mut t = vec![poly_zero(); params.k()];
    for i in 0..params.k() {
        let mut acc = poly_zero();
        for j in 0..params.k() {
            let product = ntt_pointwise_mul(&a_ntt[i][j], &s_ntt[j]);
            for idx in 0..N {
                acc[idx] += product[idx];
            }
        }
        ntt_inverse(&mut acc);
        for idx in 0..N {
            acc[idx] = reduce_coeff(acc[idx] + e[i][idx]);
        }
        t[i] = acc;
    }

    let pk = PublicKey { rho, t: t.clone() };
    let sk = SecretKey {
        seed,
        rho,
        s,
        e,
        t,
        public_key: pk.clone(),
    };

    (pk, sk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::EYVARA_128;
    use crate::poly::infinity_norm_vec;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_keygen_produces_valid_keys() {
        // Seeded for determinism; real usage requires OsRng.
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);

        assert_eq!(pk.t.len(), EYVARA_128.k());
        assert!(infinity_norm_vec(sk.s()) <= EYVARA_128.eta());
        assert!(infinity_norm_vec(sk.e()) <= EYVARA_128.eta());
        assert_eq!(pk.t, *sk.t());
        assert_eq!(pk.rho, *sk.rho());
        assert_eq!(&pk, sk.public_key());
    }

    #[test]
    fn test_keygen_different_seeds_different_keys() {
        // Seeded for determinism; real usage requires OsRng.
        let mut rng1 = ChaCha20Rng::seed_from_u64(1);
        // Seeded for determinism; real usage requires OsRng.
        let mut rng2 = ChaCha20Rng::seed_from_u64(2);
        let (pk1, _) = eyvara_keygen(&EYVARA_128, &mut rng1);
        let (pk2, _) = eyvara_keygen(&EYVARA_128, &mut rng2);

        assert_ne!(pk1.rho, pk2.rho);
    }

    #[test]
    fn test_secret_key_debug_redacts_secret_fields() {
        // Seeded for determinism; real usage requires OsRng.
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
        let debug = format!("{sk:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("s: [["));
    }
}

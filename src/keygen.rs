//! Key generation for the Eyvara VRF.
//!
//! Implements Algorithm 1 from the paper: generates a public/secret key pair
//! from the MLWE assumption. The public key (rho, t) defines the verification
//! context, while the secret key contains the short vectors s, e needed for
//! evaluation.

use crate::params::{Params, N, SEED_SIZE};
use crate::poly::{Poly, PolyVec, expand_a, sample_cbd_vec, poly_zero};
use crate::ntt::{ntt_forward, ntt_inverse, ntt_pointwise_mul};
use rand::Rng;
use zeroize::Zeroize;

/// Public key for the Eyvara VRF.
///
/// Contains the seed rho (from which the public matrix A is derived) and
/// the public vector t = As + e mod q. The public key is sufficient for
/// verification of VRF proofs.
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// Seed for deterministic matrix expansion via ExpandA.
    pub rho: [u8; SEED_SIZE],

    /// Public vector t = As + e mod q, where s and e are short secret vectors.
    pub t: PolyVec,
}

/// Secret key for the Eyvara VRF.
///
/// Contains all values needed for efficient VRF evaluation: the seed rho
/// (for matrix expansion), the secret vector s, the error vector e, and
/// the precomputed public vector t.
///
/// Implements Zeroize to ensure secret material is erased from memory
/// when the key is dropped.
#[derive(Debug, Clone)]
pub struct SecretKey {
    /// Seed for deterministic matrix expansion.
    pub rho: [u8; SEED_SIZE],

    /// Secret vector s sampled from CBD(eta)^k.
    pub s: PolyVec,

    /// Error vector e sampled from CBD(eta)^k.
    pub e: PolyVec,

    /// Precomputed public vector t = As + e mod q.
    pub t: PolyVec,
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.rho.zeroize();
        for poly in self.s.iter_mut() {
            for coeff in poly.iter_mut() {
                coeff.zeroize();
            }
        }
        for poly in self.e.iter_mut() {
            for coeff in poly.iter_mut() {
                coeff.zeroize();
            }
        }
        // t is public, but zeroize for defense in depth
        for poly in self.t.iter_mut() {
            for coeff in poly.iter_mut() {
                coeff.zeroize();
            }
        }
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Generate an Eyvara VRF key pair.
///
/// Implements Algorithm 1 from the paper:
/// 1. Sample a random 32-byte seed rho.
/// 2. Expand rho into the public matrix A ∈ R_q^{k×k} via SHAKE-256.
/// 3. Sample secret vector s ∈ S_eta^k from CBD(eta).
/// 4. Sample error vector e ∈ S_eta^k from CBD(eta).
/// 5. Compute t = As + e mod q.
/// 6. Return pk = (rho, t), sk = (rho, s, e, t).
///
/// The matrix A is generated in NTT domain for efficiency; the product As
/// is computed via NTT-domain multiplication.
pub fn eyvara_keygen<R: Rng>(params: &Params, rng: &mut R) -> (PublicKey, SecretKey) {
    // Step 1: Sample random seed
    let mut rho = [0u8; SEED_SIZE];
    rng.fill(&mut rho);

    // Step 2: Expand A from seed (in NTT domain)
    let a_ntt = expand_a(&rho, params.k);

    // Step 3-4: Sample secret and error vectors
    let s = sample_cbd_vec(rng, params.k, params.eta);
    let e = sample_cbd_vec(rng, params.k, params.eta);

    // Step 5: Compute t = As + e mod q
    // Transform s to NTT domain
    let s_ntt: Vec<Poly> = s.iter().map(|p| {
        let mut pn = *p;
        ntt_forward(&mut pn);
        pn
    }).collect();

    let mut t = vec![poly_zero(); params.k];
    for i in 0..params.k {
        let mut acc = poly_zero();
        for j in 0..params.k {
            let product = ntt_pointwise_mul(&a_ntt[i][j], &s_ntt[j]);
            for idx in 0..N {
                acc[idx] += product[idx];
            }
        }
        ntt_inverse(&mut acc);
        // Add error
        for idx in 0..N {
            acc[idx] = crate::ntt::reduce_coeff(acc[idx] + e[i][idx]);
        }
        t[i] = acc;
    }

    let pk = PublicKey {
        rho,
        t: t.clone(),
    };

    let sk = SecretKey {
        rho,
        s,
        e,
        t,
    };

    (pk, sk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::EYVARA_I;
    use crate::poly::infinity_norm_vec;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_keygen_produces_valid_keys() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (pk, sk) = eyvara_keygen(&EYVARA_I, &mut rng);

        // Public key should have k polynomials
        assert_eq!(pk.t.len(), EYVARA_I.k);

        // Secret vectors should have bounded norms
        assert!(infinity_norm_vec(&sk.s) <= EYVARA_I.eta);
        assert!(infinity_norm_vec(&sk.e) <= EYVARA_I.eta);

        // pk.t and sk.t should match
        assert_eq!(pk.t, sk.t);

        // Seeds should match
        assert_eq!(pk.rho, sk.rho);
    }

    #[test]
    fn test_keygen_different_seeds_different_keys() {
        let mut rng1 = ChaCha20Rng::seed_from_u64(1);
        let mut rng2 = ChaCha20Rng::seed_from_u64(2);
        let (pk1, _) = eyvara_keygen(&EYVARA_I, &mut rng1);
        let (pk2, _) = eyvara_keygen(&EYVARA_I, &mut rng2);

        assert_ne!(pk1.rho, pk2.rho);
    }
}

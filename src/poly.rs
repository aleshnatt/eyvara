//! Polynomial arithmetic and sampling operations.
//!
//! Provides the core polynomial operations over `R_q = Z_q[X]/(X^N + 1)` for
//! the Eyvara VRF.

use crate::error::EyvaraError;
use crate::ntt::{ntt_forward, ntt_inverse, ntt_pointwise_mul, reduce_coeff};
use crate::params::{DOMAIN_MATRIX, N, Q, SEED_SIZE};
use rand::RngCore;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use zeroize::Zeroize;

/// A polynomial in `R_q`, represented as an array of N centered coefficients.
pub type Poly = [i64; N];

/// A vector of polynomials, representing an element of `R_q^k`.
pub type PolyVec = Vec<Poly>;

/// Polynomial wrapper that zeroizes coefficients when dropped.
pub struct ZeroizingPoly(pub Poly);

impl Drop for ZeroizingPoly {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(Zeroize::zeroize);
    }
}

/// Create a zero polynomial.
pub fn poly_zero() -> Poly {
    [0i64; N]
}

/// Add two polynomials coefficient-wise: c = a + b mod Q.
pub fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let mut c = [0i64; N];
    for i in 0..N {
        c[i] = reduce_coeff(a[i] + b[i]);
    }
    c
}

/// Subtract two polynomials coefficient-wise: c = a - b mod Q.
pub fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    let mut c = [0i64; N];
    for i in 0..N {
        c[i] = reduce_coeff(a[i] - b[i]);
    }
    c
}

/// Multiply two polynomials using NTT-based multiplication.
pub fn poly_mul(a: &Poly, b: &Poly) -> Poly {
    let mut a_ntt = *a;
    let mut b_ntt = *b;
    ntt_forward(&mut a_ntt);
    ntt_forward(&mut b_ntt);
    let mut c = ntt_pointwise_mul(&a_ntt, &b_ntt);
    ntt_inverse(&mut c);
    c
}

/// Multiply a polynomial by a scalar polynomial.
pub fn poly_scalar_mul(c: &Poly, s: &Poly) -> Poly {
    poly_mul(c, s)
}

/// Negate a polynomial: c = -a mod Q.
pub fn poly_neg(a: &Poly) -> Poly {
    let mut c = [0i64; N];
    for i in 0..N {
        c[i] = reduce_coeff(-a[i]);
    }
    c
}

/// Computes the infinity norm of a polynomial in centered representation.
///
/// # Timing
///
/// This function is NOT constant-time with respect to the polynomial
/// coefficients. For the rejection sampling decision in [`crate::eyvara_eval`],
/// the polynomial being checked (`z`) contains a secret contribution from the
/// secret key. Consequently, this function may leak information about the
/// secret key through timing side channels on platforms where integer division
/// or branching is not constant-time.
///
/// This is a known limitation of the current research prototype. A production
/// deployment must replace this function with a verified constant-time
/// implementation.
pub fn infinity_norm(a: &Poly) -> i64 {
    let mut max = 0i64;
    for &coeff in a {
        let mut c = coeff % Q;
        if c > Q / 2 {
            c -= Q;
        }
        if c < -(Q / 2) {
            c += Q;
        }
        let abs = c.abs();
        if abs > max {
            max = abs;
        }
    }
    max
}

/// Compute the infinity norm using arithmetic masking for data-dependent choices.
///
/// The `%` reductions may still compile to variable-latency division on some
/// CPUs, so this function is not claimed as a production constant-time primitive.
#[allow(clippy::cast_sign_loss)]
pub fn infinity_norm_ct(poly: &Poly, q: i64) -> i64 {
    let mut max_val = 0_i64;
    let half_q = q / 2;

    for &coeff in poly {
        let c = ((coeff % q) + q) % q;
        let gt_half_mask = !((c - half_q - 1) >> 63);
        let centered = c - (q & gt_half_mask);
        let abs = (centered ^ (centered >> 63)) - (centered >> 63);

        let diff = abs - max_val;
        let gt_mask = !((diff - 1) >> 63);
        max_val += diff & gt_mask;
    }

    max_val
}

/// Compute the infinity norm of a polynomial vector.
pub fn infinity_norm_vec(v: &[Poly]) -> i64 {
    v.iter().map(infinity_norm).max().unwrap_or(0)
}

/// Add two polynomial vectors component-wise.
pub fn poly_vec_add(a: &[Poly], b: &[Poly]) -> Result<PolyVec, EyvaraError> {
    if a.len() != b.len() {
        return Err(EyvaraError::MalformedProof);
    }

    Ok(a.iter()
        .zip(b.iter())
        .map(|(ai, bi)| poly_add(ai, bi))
        .collect())
}

/// Subtract two polynomial vectors component-wise.
pub fn poly_vec_sub(a: &[Poly], b: &[Poly]) -> Result<PolyVec, EyvaraError> {
    if a.len() != b.len() {
        return Err(EyvaraError::MalformedProof);
    }

    Ok(a.iter()
        .zip(b.iter())
        .map(|(ai, bi)| poly_sub(ai, bi))
        .collect())
}

/// Multiply a matrix A in NTT domain by a coefficient-form vector v.
pub fn poly_matrix_mul_ntt(a_ntt: &[Vec<Poly>], v: &[Poly]) -> PolyVec {
    let k = a_ntt.len();
    let mut result = vec![poly_zero(); k];

    let v_ntt: Vec<Poly> = v
        .iter()
        .map(|p| {
            let mut pn = *p;
            ntt_forward(&mut pn);
            pn
        })
        .collect();

    for i in 0..k {
        let mut acc = poly_zero();
        for (j, vj) in v_ntt.iter().enumerate() {
            let product = ntt_pointwise_mul(&a_ntt[i][j], vj);
            for idx in 0..N {
                acc[idx] += product[idx];
            }
        }
        ntt_inverse(&mut acc);
        for coeff in &mut acc {
            *coeff = reduce_coeff(*coeff);
        }
        result[i] = acc;
    }
    result
}

/// Expand a seed rho into the public matrix A in NTT domain.
pub fn expand_a(rho: &[u8; SEED_SIZE], k: usize) -> Vec<Vec<Poly>> {
    let mut a = vec![vec![poly_zero(); k]; k];

    for i in 0..k {
        for j in 0..k {
            let mut hasher = Shake256::default();
            hasher.update(DOMAIN_MATRIX);
            hasher.update(rho);
            hasher.update(&[i as u8, j as u8]);
            let mut reader = hasher.finalize_xof();

            let mut poly = poly_zero();
            let mut idx = 0;
            while idx < N {
                let mut buf = [0u8; 3];
                reader.read(&mut buf);
                let val = ((buf[0] as i64) | ((buf[1] as i64) << 8) | ((buf[2] as i64) << 16))
                    & 0x7F_FFFF;
                if val < Q {
                    poly[idx] = val;
                    if poly[idx] > Q / 2 {
                        poly[idx] -= Q;
                    }
                    idx += 1;
                }
            }

            ntt_forward(&mut poly);
            a[i][j] = poly;
        }
    }
    a
}

/// Sample a polynomial with coefficients from the centered binomial distribution.
pub fn sample_cbd<R: RngCore>(rng: &mut R, eta: i64) -> Poly {
    let mut poly = poly_zero();
    let eta_u = eta as u32;

    for coeff in &mut poly {
        let mut a_sum = 0i64;
        let mut b_sum = 0i64;
        for _ in 0..eta_u {
            a_sum += (rng.next_u32() & 1) as i64;
            b_sum += (rng.next_u32() & 1) as i64;
        }
        *coeff = a_sum - b_sum;
    }
    poly
}

/// Sample a polynomial vector with each component from CBD(eta).
pub fn sample_cbd_vec<R: RngCore>(rng: &mut R, k: usize, eta: i64) -> PolyVec {
    (0..k).map(|_| sample_cbd(rng, eta)).collect()
}

/// Sample a polynomial with coefficients uniformly from [-gamma1+1, gamma1].
pub fn sample_uniform_gamma1<R: RngCore>(rng: &mut R, gamma1: i64) -> Poly {
    let mut poly = poly_zero();
    let range = 2 * gamma1;
    let range_u64 = range as u64;
    for coeff in &mut poly {
        let bound = (u64::MAX / range_u64) * range_u64;
        loop {
            let r = rng.next_u64();
            if r < bound {
                *coeff = (r % range_u64) as i64 - gamma1 + 1;
                break;
            }
        }
    }
    poly
}

/// Sample a polynomial vector with each component uniform in [-gamma1+1, gamma1].
pub fn sample_uniform_gamma1_vec<R: RngCore>(rng: &mut R, k: usize, gamma1: i64) -> PolyVec {
    (0..k).map(|_| sample_uniform_gamma1(rng, gamma1)).collect()
}

fn decompose(r: i64, gamma2: i64) -> (i64, i64) {
    let r_pos = ((r % Q) + Q) % Q;

    let mut r0 = r_pos % (2 * gamma2);
    if r0 > gamma2 {
        r0 -= 2 * gamma2;
    }

    if r_pos - r0 == Q - 1 {
        (0, r0 - 1)
    } else {
        ((r_pos - r0) / (2 * gamma2), r0)
    }
}

/// Extract the high-order bits of a coefficient.
pub fn high_bits(r: i64, gamma2: i64) -> i64 {
    decompose(r, gamma2).0
}

/// Extract the low-order bits of a coefficient.
pub fn low_bits(r: i64, gamma2: i64) -> i64 {
    decompose(r, gamma2).1
}

/// Compute HighBits for each coefficient of a polynomial.
pub fn high_bits_poly(a: &Poly, gamma2: i64) -> Poly {
    let mut result = poly_zero();
    for i in 0..N {
        result[i] = high_bits(a[i], gamma2);
    }
    result
}

/// Compute LowBits for each coefficient of a polynomial.
pub fn low_bits_poly(a: &Poly, gamma2: i64) -> Poly {
    let mut result = poly_zero();
    for i in 0..N {
        result[i] = low_bits(a[i], gamma2);
    }
    result
}

/// Compute HighBits for each coefficient of a polynomial vector.
pub fn high_bits_vec(v: &[Poly], gamma2: i64) -> PolyVec {
    v.iter().map(|p| high_bits_poly(p, gamma2)).collect()
}

/// Compute LowBits for each coefficient of a polynomial vector.
pub fn low_bits_vec(v: &[Poly], gamma2: i64) -> PolyVec {
    v.iter().map(|p| low_bits_poly(p, gamma2)).collect()
}

/// Compute the hint bit for a single coefficient pair.
pub fn make_hint_coeff(z: i64, r: i64, gamma2: i64) -> i8 {
    let r1 = high_bits(r, gamma2);
    let v1 = high_bits(((r + z) % Q + Q) % Q, gamma2);
    i8::from(r1 != v1)
}

/// Apply the hint to recover high bits from a coefficient.
pub fn use_hint_coeff(hint: i8, r: i64, gamma2: i64) -> i64 {
    let (r1, r0) = decompose(r, gamma2);

    if hint == 0 {
        return r1;
    }

    let m = (Q - 1) / (2 * gamma2);
    if r0 > 0 {
        (r1 + 1) % m
    } else {
        (r1 - 1 + m) % m
    }
}

/// Compute MakeHint for an entire polynomial pair.
pub fn make_hint_poly(z: &Poly, r: &Poly, gamma2: i64) -> Vec<i8> {
    let mut hints = vec![0i8; N];
    for i in 0..N {
        hints[i] = make_hint_coeff(z[i], r[i], gamma2);
    }
    hints
}

/// Compute UseHint for an entire polynomial with hint vector.
pub fn use_hint_poly(hints: &[i8], r: &Poly, gamma2: i64) -> Result<Poly, EyvaraError> {
    if hints.len() != N {
        return Err(EyvaraError::MalformedProof);
    }

    let mut result = poly_zero();
    for i in 0..N {
        result[i] = use_hint_coeff(hints[i], r[i], gamma2);
    }
    Ok(result)
}

/// Compute MakeHint for polynomial vectors.
pub fn make_hint_vec(z: &[Poly], r: &[Poly], gamma2: i64) -> Result<(Vec<i8>, usize), EyvaraError> {
    if z.len() != r.len() {
        return Err(EyvaraError::MalformedProof);
    }

    let mut hints = Vec::with_capacity(z.len() * N);
    let mut weight = 0usize;
    for (zi, ri) in z.iter().zip(r.iter()) {
        let h = make_hint_poly(zi, ri, gamma2);
        weight += h.iter().filter(|&&bit| bit != 0).count();
        hints.extend_from_slice(&h);
    }
    Ok((hints, weight))
}

/// Compute UseHint for polynomial vectors.
pub fn use_hint_vec(hints: &[i8], r: &[Poly], gamma2: i64) -> Result<PolyVec, EyvaraError> {
    let k = r.len();
    if hints.len() != k * N {
        return Err(EyvaraError::MalformedProof);
    }

    let mut result = vec![poly_zero(); k];
    for i in 0..k {
        let h_slice = &hints[i * N..(i + 1) * N];
        result[i] = use_hint_poly(h_slice, &r[i], gamma2)?;
    }
    Ok(result)
}

/// Count the number of nonzero entries in a hint vector.
pub fn hint_weight(hints: &[i8]) -> usize {
    hints.iter().filter(|&&h| h != 0).count()
}

/// Serialize a polynomial's coefficients to bytes for hashing.
pub fn poly_to_bytes(p: &Poly) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(N * 4);
    for &c in p {
        let c_pos = ((c % Q) + Q) % Q;
        bytes.extend_from_slice(&(c_pos as u32).to_le_bytes());
    }
    bytes
}

/// Serialize a polynomial vector to bytes for hashing.
pub fn poly_vec_to_bytes(v: &[Poly]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(v.len() * N * 4);
    for p in v {
        bytes.extend(poly_to_bytes(p));
    }
    bytes
}

#[cfg(feature = "serde")]
pub(crate) fn polyvec_to_nested_vec(v: &PolyVec) -> Vec<Vec<i64>> {
    v.iter().map(|p| p.to_vec()).collect()
}

#[cfg(feature = "serde")]
pub(crate) fn nested_vec_to_polyvec(v: Vec<Vec<i64>>) -> Result<PolyVec, String> {
    let mut out = Vec::with_capacity(v.len());
    for poly in v {
        if poly.len() != N {
            return Err(format!("polynomial length must be {N}"));
        }
        let mut arr = [0_i64; N];
        arr.copy_from_slice(&poly);
        out.push(arr);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{EYVARA_128, SEED_SIZE};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_poly_add_sub_inverse() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let p1 = sample_uniform_gamma1_vec(&mut rng, 1, 1000)[0];
        let p2 = sample_uniform_gamma1_vec(&mut rng, 1, 1000)[0];

        let sum = poly_add(&p1, &p2);
        let diff = poly_sub(&sum, &p2);

        assert_eq!(p1, diff);
    }

    #[test]
    fn test_high_low_bits_reconstruction() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let p = sample_uniform_gamma1_vec(&mut rng, 1, 1000)[0];
        let gamma2 = EYVARA_128.gamma_2();

        let w1 = high_bits_poly(&p, gamma2);
        let w0 = low_bits_poly(&p, gamma2);

        for &coeff in &w0 {
            assert!(coeff.abs() <= gamma2);
        }

        for i in 0..N {
            let reconstructed = w1[i] * 2 * gamma2 + w0[i];
            let diff = crate::ntt::reduce_coeff(p[i] - reconstructed);
            assert_eq!(diff, 0, "Reconstruction failed at index {i}");
        }
    }

    #[test]
    fn test_make_use_hint_roundtrip_smoke() {
        let gamma2 = EYVARA_128.gamma_2();
        let mut rng = ChaCha20Rng::seed_from_u64(99);

        for _ in 0..100 {
            let r: i64 = (rng.next_u64() % Q as u64) as i64;
            let z: i64 = (rng.next_u64() % (2 * gamma2 as u64)) as i64 - gamma2;
            let hint = make_hint_coeff(z, r, gamma2);
            let _ = use_hint_coeff(hint, ((r + z) % Q + Q) % Q, gamma2);
        }
    }

    #[test]
    fn test_sample_uniform_gamma1_bounds() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let gamma1 = EYVARA_128.gamma_1();
        let p = sample_uniform_gamma1(&mut rng, gamma1);
        for &c in &p {
            assert!(c > -gamma1 && c <= gamma1, "coefficient {c} out of range");
        }
    }

    #[test]
    fn test_expand_a_deterministic() {
        let rho = [0u8; SEED_SIZE];
        let a1 = expand_a(&rho, 2);
        let a2 = expand_a(&rho, 2);
        for i in 0..2 {
            for j in 0..2 {
                assert_eq!(a1[i][j], a2[i][j], "A[{i}][{j}] differs");
            }
        }
    }

    #[test]
    fn test_vector_length_mismatch_returns_error() {
        let a = vec![poly_zero()];
        let b = vec![poly_zero(), poly_zero()];
        assert_eq!(poly_vec_add(&a, &b), Err(EyvaraError::MalformedProof));
        assert_eq!(poly_vec_sub(&a, &b), Err(EyvaraError::MalformedProof));
    }
}

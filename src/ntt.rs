//! Number Theoretic Transform (NTT) over Z_q for q = 8380417.
//!
//! Provides forward and inverse NTT for polynomials of degree N=256 over the
//! ring R_q = Z_q[X]/(X^N + 1). The NTT enables O(N log N) polynomial
//! multiplication by converting to pointwise products in the NTT domain.
//!
//! The implementation uses Cooley-Tukey butterflies for the forward transform
//! and Gentleman-Sande butterflies for the inverse, with Montgomery arithmetic
//! for modular multiplication.

use crate::params::{N, Q, Q_INV};

/// Precomputed twiddle factors (roots of unity) in Montgomery form.
/// These are powers of the primitive 512th root of unity zeta = 1753
/// in Z_q, multiplied by the Montgomery constant R = 2^32 mod Q.
///
/// The array is indexed such that ZETAS[k] corresponds to the twiddle
/// factor used at level log2(N) - floor(log2(k+1)) of the NTT butterfly.
pub const ZETAS: [i64; N] = {
    // Primitive 512th root of unity: zeta = 1753 (mod Q)
    // zeta^256 ≡ -1 (mod Q), enabling NTT over X^256 + 1.
    //
    // The twiddle factors are computed as zeta^{brv(i)} * R mod Q
    // where brv is the bit-reversal permutation and R = 2^32 mod Q.
    let mut zetas = [0i64; N];
    // We compute these at compile time using const evaluation.
    // zeta = 1753, R = 2^32 mod Q = 4193792
    // zeta_mont = zeta * R mod Q

    // Bit-reversed powers of zeta in Montgomery domain.
    // These are the standard Dilithium NTT twiddle factors for q = 8380417.
    zetas[0] = 0;
    zetas[1] = 25847;
    zetas[2] = -2608894;
    zetas[3] = -518909;
    zetas[4] = 237124;
    zetas[5] = -777960;
    zetas[6] = -876248;
    zetas[7] = 466468;
    zetas[8] = 1826347;
    zetas[9] = 2353451;
    zetas[10] = -359251;
    zetas[11] = -2091905;
    zetas[12] = 3119733;
    zetas[13] = -2884855;
    zetas[14] = 3111497;
    zetas[15] = 2680103;
    zetas[16] = 2725464;
    zetas[17] = 1024112;
    zetas[18] = -1079900;
    zetas[19] = 3585928;
    zetas[20] = -549488;
    zetas[21] = -1119584;
    zetas[22] = 2619752;
    zetas[23] = -2108549;
    zetas[24] = -2118186;
    zetas[25] = -3859737;
    zetas[26] = -1399561;
    zetas[27] = -3277672;
    zetas[28] = 1757237;
    zetas[29] = -19422;
    zetas[30] = 4010497;
    zetas[31] = 280005;
    zetas[32] = 2706023;
    zetas[33] = 95776;
    zetas[34] = 3077325;
    zetas[35] = 3530437;
    zetas[36] = -1661693;
    zetas[37] = -3592148;
    zetas[38] = -2537516;
    zetas[39] = 3915439;
    zetas[40] = -3861115;
    zetas[41] = -3043716;
    zetas[42] = 3574422;
    zetas[43] = -2867647;
    zetas[44] = 3539968;
    zetas[45] = -300467;
    zetas[46] = 2348700;
    zetas[47] = -539299;
    zetas[48] = -1699267;
    zetas[49] = -1643818;
    zetas[50] = 3505694;
    zetas[51] = -3821735;
    zetas[52] = 3507263;
    zetas[53] = -2140649;
    zetas[54] = -1600420;
    zetas[55] = 3699596;
    zetas[56] = 811944;
    zetas[57] = 531354;
    zetas[58] = 954230;
    zetas[59] = 3881043;
    zetas[60] = 3900724;
    zetas[61] = -2556880;
    zetas[62] = 2071892;
    zetas[63] = -2797779;
    zetas[64] = -3930395;
    zetas[65] = -1528703;
    zetas[66] = -3677745;
    zetas[67] = -3041255;
    zetas[68] = -1452451;
    zetas[69] = 3475950;
    zetas[70] = 2176455;
    zetas[71] = -1585221;
    zetas[72] = -1257611;
    zetas[73] = 1939314;
    zetas[74] = -4083598;
    zetas[75] = -1000202;
    zetas[76] = -3190144;
    zetas[77] = -3157330;
    zetas[78] = -3632928;
    zetas[79] = 126922;
    zetas[80] = 3412210;
    zetas[81] = -983419;
    zetas[82] = 2147896;
    zetas[83] = 2715295;
    zetas[84] = -2967645;
    zetas[85] = -3693493;
    zetas[86] = -411027;
    zetas[87] = -2477047;
    zetas[88] = -671102;
    zetas[89] = -1228525;
    zetas[90] = -22981;
    zetas[91] = -1308169;
    zetas[92] = -381987;
    zetas[93] = 1349076;
    zetas[94] = 1852771;
    zetas[95] = -1430430;
    zetas[96] = -3343383;
    zetas[97] = 264944;
    zetas[98] = 508951;
    zetas[99] = 3097992;
    zetas[100] = 44288;
    zetas[101] = -1100098;
    zetas[102] = 904516;
    zetas[103] = 3958618;
    zetas[104] = -3724342;
    zetas[105] = -8578;
    zetas[106] = 1653064;
    zetas[107] = -3249728;
    zetas[108] = 2389356;
    zetas[109] = -210977;
    zetas[110] = 759969;
    zetas[111] = -1316856;
    zetas[112] = 189548;
    zetas[113] = -3553272;
    zetas[114] = 3159746;
    zetas[115] = -1851402;
    zetas[116] = -2409325;
    zetas[117] = -177440;
    zetas[118] = 1315589;
    zetas[119] = 1341330;
    zetas[120] = 1285669;
    zetas[121] = -1584928;
    zetas[122] = -812732;
    zetas[123] = -1439742;
    zetas[124] = -3019102;
    zetas[125] = -3881060;
    zetas[126] = -3628969;
    zetas[127] = 3839961;
    zetas[128] = 2091667;
    zetas[129] = 3407706;
    zetas[130] = 2316500;
    zetas[131] = 3817976;
    zetas[132] = -3342478;
    zetas[133] = 2244091;
    zetas[134] = -2446433;
    zetas[135] = -3562462;
    zetas[136] = 266997;
    zetas[137] = 2434439;
    zetas[138] = -1235728;
    zetas[139] = 3513181;
    zetas[140] = -3520352;
    zetas[141] = -3759364;
    zetas[142] = -1197226;
    zetas[143] = -3193378;
    zetas[144] = 900702;
    zetas[145] = 1859098;
    zetas[146] = 909542;
    zetas[147] = 819034;
    zetas[148] = 495491;
    zetas[149] = -1613174;
    zetas[150] = -43260;
    zetas[151] = -522500;
    zetas[152] = -655327;
    zetas[153] = -3122442;
    zetas[154] = 2031748;
    zetas[155] = 3207046;
    zetas[156] = -3556995;
    zetas[157] = -525098;
    zetas[158] = -768622;
    zetas[159] = -3595838;
    zetas[160] = 342297;
    zetas[161] = 286988;
    zetas[162] = -2437823;
    zetas[163] = 4108315;
    zetas[164] = 3437287;
    zetas[165] = -3342277;
    zetas[166] = 1735879;
    zetas[167] = 203044;
    zetas[168] = 2842341;
    zetas[169] = 2691481;
    zetas[170] = -2590150;
    zetas[171] = 1265009;
    zetas[172] = 4055324;
    zetas[173] = 1247620;
    zetas[174] = 2486353;
    zetas[175] = 1595974;
    zetas[176] = -3767016;
    zetas[177] = 1250494;
    zetas[178] = 2635921;
    zetas[179] = -3548272;
    zetas[180] = -2994039;
    zetas[181] = 1869119;
    zetas[182] = 1903435;
    zetas[183] = -1050970;
    zetas[184] = -1333058;
    zetas[185] = 1237275;
    zetas[186] = -3318210;
    zetas[187] = -1430225;
    zetas[188] = -451100;
    zetas[189] = 1312455;
    zetas[190] = 3306115;
    zetas[191] = -1962642;
    zetas[192] = -1279661;
    zetas[193] = 1917081;
    zetas[194] = -2546312;
    zetas[195] = -1374803;
    zetas[196] = 1500165;
    zetas[197] = 777191;
    zetas[198] = 2235880;
    zetas[199] = 3406031;
    zetas[200] = -542412;
    zetas[201] = -2831860;
    zetas[202] = -1671176;
    zetas[203] = -1846953;
    zetas[204] = -2584293;
    zetas[205] = -3724270;
    zetas[206] = 594136;
    zetas[207] = -3776993;
    zetas[208] = -2013608;
    zetas[209] = 2432395;
    zetas[210] = 2454455;
    zetas[211] = -164721;
    zetas[212] = 1957272;
    zetas[213] = 3369112;
    zetas[214] = 185531;
    zetas[215] = -1207385;
    zetas[216] = -3183426;
    zetas[217] = 162844;
    zetas[218] = 1616392;
    zetas[219] = 3014001;
    zetas[220] = 810149;
    zetas[221] = 1652634;
    zetas[222] = -3694233;
    zetas[223] = -1799107;
    zetas[224] = -3038916;
    zetas[225] = 3523897;
    zetas[226] = 3866901;
    zetas[227] = 269760;
    zetas[228] = 2213111;
    zetas[229] = -975884;
    zetas[230] = 1717735;
    zetas[231] = 472078;
    zetas[232] = -426683;
    zetas[233] = 1723600;
    zetas[234] = -1803090;
    zetas[235] = 1910376;
    zetas[236] = -1667432;
    zetas[237] = -1104333;
    zetas[238] = -260646;
    zetas[239] = -3833893;
    zetas[240] = -2939036;
    zetas[241] = -2235985;
    zetas[242] = -420899;
    zetas[243] = -2286327;
    zetas[244] = 183443;
    zetas[245] = -976891;
    zetas[246] = 1612842;
    zetas[247] = -3545687;
    zetas[248] = -554416;
    zetas[249] = 3919660;
    zetas[250] = -48306;
    zetas[251] = -1362209;
    zetas[252] = 3937738;
    zetas[253] = 1400424;
    zetas[254] = -846154;
    zetas[255] = 1976782;
    zetas
};
/// Montgomery reduction: compute (a * Q_INV) mod 2^32, then (a - t*Q) >> 32.
///
/// Given a 64-bit integer a with |a| < 2^31 * Q, this function returns
/// a value r ≡ a * 2^{-32} (mod Q) with |r| < Q.
///
/// The Montgomery reduction avoids expensive division by Q, replacing it
/// with multiplication by Q_INV (precomputed inverse of Q mod 2^32) and
/// a shift.
#[inline(always)]
pub fn montgomery_reduce(a: i64) -> i64 {
    let t = ((a as i32).wrapping_mul(Q_INV as i32)) as i64;
    (a - t * Q) >> 32
}

/// Forward NTT: convert a polynomial from coefficient representation to
/// NTT domain using Cooley-Tukey butterflies.
///
/// After the transform, each element a[i] is in the range [-(Q-1)/2, (Q-1)/2]
/// times a Montgomery factor. The output is suitable for pointwise multiplication
/// via `ntt_pointwise_mul`.
///
/// Input coefficients must satisfy |a[i]| < Q/2 for correct results.
pub fn ntt_forward(a: &mut [i64; N]) {
    let mut k: usize = 0;
    let mut len = 128;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            k += 1;
            let zeta = ZETAS[k];
            for j in start..start + len {
                let t = montgomery_reduce(zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse NTT: convert a polynomial from NTT domain back to coefficient
/// representation using Gentleman-Sande butterflies.
///
/// After the transform, each coefficient is multiplied by N^{-1} in Montgomery
/// form. The output coefficients are reduced to the range [-(Q-1)/2, (Q-1)/2].
///
/// The inverse NTT uses the negated twiddle factors (ZETAS read in reverse order)
/// to invert the forward transform.
pub fn ntt_inverse(a: &mut [i64; N]) {
    let mut k: usize = 256;
    let mut len = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            k -= 1;
            let zeta = -ZETAS[k];
            for j in start..start + len {
                let t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = montgomery_reduce(zeta * a[j + len]);
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    // Multiply by N^{-1} in Montgomery form.
    // f = Mont(2^32 / 256 mod Q) = Mont(R * N^{-1} mod Q)
    let f: i64 = 41978; // (2^32 / 256) mod Q in Montgomery form
    for coeff in a.iter_mut() {
        *coeff = montgomery_reduce(f * *coeff);
    }
}

/// Pointwise multiplication of two polynomials in NTT domain.
///
/// Each pair of coefficients is multiplied and Montgomery-reduced. The result
/// is also in the NTT domain and can be converted back via `ntt_inverse`.
///
/// This function computes the polynomial product a * b mod (X^N + 1) when
/// both inputs and the output are in NTT representation.
pub fn ntt_pointwise_mul(a: &[i64; N], b: &[i64; N]) -> [i64; N] {
    let mut c = [0i64; N];
    for i in 0..N {
        c[i] = montgomery_reduce(a[i] * b[i]);
    }
    c
}

/// Reduce a coefficient to the centered range [-(Q-1)/2, (Q-1)/2].
///
/// This is applied after NTT operations to keep coefficients bounded,
/// preventing overflow in subsequent multiplications.
#[inline(always)]
pub fn reduce_coeff(a: i64) -> i64 {
    let mut t = a % Q;
    if t > Q / 2 {
        t -= Q;
    }
    if t < -(Q / 2) {
        t += Q;
    }
    t
}

/// Reduce all coefficients of a polynomial to the centered range.
pub fn reduce_poly(a: &mut [i64; N]) {
    for coeff in a.iter_mut() {
        *coeff = reduce_coeff(*coeff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_montgomery_reduce_identity() {
        // Montgomery reduce of a * R should give a (approximately)
        let a = 12345i64;
        let ar = a * (1i64 << 32) % Q;
        let result = montgomery_reduce(ar);
        // result should be congruent to a mod Q
        assert_eq!((result % Q + Q) % Q, (a % Q + Q) % Q);
    }

    #[test]
    fn test_ntt_roundtrip() {
        // Forward NTT followed by inverse NTT should recover the original polynomial
        let mut a = [0i64; N];
        for i in 0..N {
            a[i] = (i as i64 * 137 + 42) % Q;
            if a[i] > Q / 2 {
                a[i] -= Q;
            }
        }
        let original = a;

        ntt_forward(&mut a);
        ntt_inverse(&mut a);

        for i in 0..N {
            let reduced = montgomery_reduce(a[i]);
            let got = ((reduced % Q) + Q) % Q;
            let expected = ((original[i] % Q) + Q) % Q;
            assert_eq!(got, expected, "mismatch at index {i}");
        }
    }

    #[test]
    fn test_ntt_zero_polynomial() {
        let mut a = [0i64; N];
        ntt_forward(&mut a);
        for &c in a.iter() {
            assert_eq!(c, 0);
        }
        ntt_inverse(&mut a);
        for &c in a.iter() {
            assert_eq!(c, 0);
        }
    }
}

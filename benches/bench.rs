//! Criterion benchmarks for the Eyvara VRF.
//!
//! Measures key generation, evaluation, verification, and full round-trip
//! performance for the Eyvara-I parameter set.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use eyvara::{eyvara_eval, eyvara_keygen, eyvara_verify, EYVARA_128};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Benchmark key generation for Eyvara-I.
fn bench_keygen(c: &mut Criterion) {
    c.bench_function("eyvara_i_keygen", |b| {
        b.iter_batched(
            || ChaCha20Rng::seed_from_u64(42),
            |mut rng| {
                let _ = eyvara_keygen(&EYVARA_128, &mut rng);
            },
            BatchSize::SmallInput,
        );
    });
}

/// Benchmark VRF evaluation for Eyvara-I.
fn bench_eval(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
    let input = b"benchmark_eval_input";

    c.bench_function("eyvara_i_eval", |b| {
        b.iter_batched(
            || ChaCha20Rng::seed_from_u64(99),
            |mut rng| {
                let _ = eyvara_eval(&EYVARA_128, &sk, input, &mut rng).unwrap();
            },
            BatchSize::SmallInput,
        );
    });
}

/// Benchmark VRF verification for Eyvara-I.
fn bench_verify(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
    let input = b"benchmark_verify_input";
    let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, input, &mut rng).unwrap();

    c.bench_function("eyvara_i_verify", |b| {
        b.iter(|| {
            let _ = eyvara_verify(&EYVARA_128, &pk, input, &beta, &proof).unwrap();
        });
    });
}

/// Benchmark full round trip: keygen + eval + verify for Eyvara-I.
fn bench_full_round_trip(c: &mut Criterion) {
    c.bench_function("eyvara_i_full_round_trip", |b| {
        b.iter_batched(
            || ChaCha20Rng::seed_from_u64(42),
            |mut rng| {
                let (pk, sk) = eyvara_keygen(&EYVARA_128, &mut rng);
                let input = b"round_trip_input";
                let (beta, proof) = eyvara_eval(&EYVARA_128, &sk, input, &mut rng).unwrap();
                let _ = eyvara_verify(&EYVARA_128, &pk, input, &beta, &proof).unwrap();
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    name = eyvara_benches;
    config = Criterion::default().sample_size(100);
    targets = bench_keygen, bench_eval, bench_verify, bench_full_round_trip
);
criterion_main!(eyvara_benches);

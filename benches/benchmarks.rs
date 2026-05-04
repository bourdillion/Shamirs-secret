use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use ark_bls12_381::{Fr, G1Projective};
use ark_ec::PrimeGroup;

use shamir_secret::feldman::Commitment;
use shamir_secret::field::BlsScalar;
use shamir_secret::frost::{PartialSignature, SignerNonce};
use shamir_secret::sharing::Share;

fn bench_split(c: &mut Criterion) {
    let secret = BlsScalar {
        value: Fr::from(42u64),
    };

    let mut group = c.benchmark_group("split");
    for &(t, n) in &[(3, 5), (5, 10), (10, 20)] {
        group.bench_with_input(
            BenchmarkId::new("t_n", format!("{}_{}", t, n)),
            &(t, n),
            |b, &(t, n)| {
                b.iter(|| Share::split(secret, t, n, 0).unwrap());
            },
        );
    }
    group.finish();
}

fn bench_reconstruct(c: &mut Criterion) {
    let secret = BlsScalar {
        value: Fr::from(42u64),
    };

    let mut group = c.benchmark_group("reconstruct");
    for &(t, n) in &[(3, 5), (5, 10), (10, 20)] {
        let shares = Share::split(secret, t, n, 0).unwrap();
        let subset: Vec<_> = shares.into_iter().take(t as usize).collect();

        group.bench_with_input(
            BenchmarkId::new("t_n", format!("{}_{}", t, n)),
            &subset,
            |b, subset| {
                b.iter(|| Share::reconstruct(subset.clone(), 0).unwrap());
            },
        );
    }
    group.finish();
}

fn bench_feldman_commit(c: &mut Criterion) {
    let secret = BlsScalar {
        value: Fr::from(42u64),
    };
    let generator = G1Projective::generator();

    let mut group = c.benchmark_group("feldman_commit");
    for &(t, n) in &[(3, 5), (5, 10), (10, 20)] {
        group.bench_with_input(
            BenchmarkId::new("t_n", format!("{}_{}", t, n)),
            &(t, n),
            |b, &(t, n)| {
                b.iter(|| Commitment::split_with_commitments(secret, t, n, generator).unwrap());
            },
        );
    }
    group.finish();
}

fn bench_feldman_verify(c: &mut Criterion) {
    let secret = BlsScalar {
        value: Fr::from(42u64),
    };
    let generator = G1Projective::generator();
    let (shares, commitment) = Commitment::split_with_commitments(secret, 3, 5, generator).unwrap();

    c.bench_function("feldman_verify", |b| {
        b.iter(|| Commitment::verify(&shares[0], &commitment, generator));
    });
}

fn bench_frost_sign(c: &mut Criterion) {
    let group_private_key = Fr::from(42u64);
    let group_public_key = G1Projective::generator() * group_private_key;
    let secret = BlsScalar {
        value: group_private_key,
    };
    let message = b"benchmark message";

    let mut group = c.benchmark_group("frost_sign");
    for &(t, n) in &[(3, 5), (5, 10)] {
        let (shares, _) =
            Commitment::split_with_commitments(secret, t, n, G1Projective::generator()).unwrap();

        group.bench_with_input(
            BenchmarkId::new("t_n", format!("{}_{}", t, n)),
            &t,
            |b, &t| {
                b.iter_batched(
                    || {
                        let nonces: Vec<SignerNonce> =
                            (1..=t).map(|i| SignerNonce::generate(i)).collect();
                        nonces
                    },
                    |nonces| {
                        for i in 0..t as usize {
                            PartialSignature::sign(
                                &nonces[i],
                                &shares[i].y.value,
                                &nonces,
                                &group_public_key,
                                message,
                            )
                            .unwrap();
                        }
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_frost_aggregate(c: &mut Criterion) {
    let group_private_key = Fr::from(42u64);
    let group_public_key = G1Projective::generator() * group_private_key;
    let secret = BlsScalar {
        value: group_private_key,
    };
    let message = b"benchmark message";

    let mut group = c.benchmark_group("frost_aggregate");
    for &(t, n) in &[(3, 5), (5, 10)] {
        let (shares, _) =
            Commitment::split_with_commitments(secret, t, n, G1Projective::generator()).unwrap();

        group.bench_with_input(
            BenchmarkId::new("t_n", format!("{}_{}", t, n)),
            &t,
            |b, &t| {
                b.iter_batched(
                    || {
                        let nonces: Vec<SignerNonce> =
                            (1..=t).map(|i| SignerNonce::generate(i)).collect();
                        let partial_sigs: Vec<PartialSignature> = (0..t as usize)
                            .map(|i| {
                                PartialSignature::sign(
                                    &nonces[i],
                                    &shares[i].y.value,
                                    &nonces,
                                    &group_public_key,
                                    message,
                                )
                                .unwrap()
                            })
                            .collect();
                        (partial_sigs, nonces)
                    },
                    |(partial_sigs, nonces)| {
                        PartialSignature::aggregate(&partial_sigs, &nonces).unwrap();
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_split,
    bench_reconstruct,
    bench_feldman_commit,
    bench_feldman_verify,
    bench_frost_sign,
    bench_frost_aggregate,
);
criterion_main!(benches);

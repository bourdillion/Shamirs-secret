use ark_bls12_381::{Fr, G1Projective};
use ark_ec::PrimeGroup;
use ark_ff::UniformRand;

struct SignerNonce {
    index: u64,
    secret_nonce: Fr,
    nonce: G1Projective,
}

struct PartialSignature {
    index: u64,
    private_key: Fr,
}

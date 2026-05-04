use crate::field::{BlsScalar, Field};
use crate::polynomial::Polynomial;
use ark_bls12_381::{Fr, G1Projective};
use ark_ec::PrimeGroup;
use ark_ff::UniformRand;

struct DkgSharePackage {
    sender_index: u64,
    receiver_index: u64,
    share: BlsScalar,
}

struct DkgParticipant {
    index: u32,
    threshold: usize,
    polynomial: Polynomial<BlsScalar>,
    commitment: Vec<G1Projective>,
}

struct DkgResult {
    index: u64,
    key_share: BlsScalar,
    group_public_key: G1Projective,
    verification_commitment: Vec<G1Projective>,
}

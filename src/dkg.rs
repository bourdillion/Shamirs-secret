use std::hash::BuildHasher;

use crate::feldman::Commitment;
use crate::field::{BlsScalar, Field};
use crate::polynomial::Polynomial;
use ark_bls12_381::{Fr, G1Projective};
use ark_ec::PrimeGroup;
use ark_ff::{UniformRand, Zero};

#[derive(Clone, Debug)]
struct DkgSharePackage {
    sender_index: u64,
    receiver_index: u64,
    share: BlsScalar,
}

struct DkgParticipant {
    index: u64,
    threshold: usize,
    polynomial: Polynomial<BlsScalar>,
    commitment: Commitment,
}

impl DkgParticipant {
    pub fn new(index: u64, threshold: usize) -> Self {
        let mut rng = rand_core::OsRng;
        let secret = BlsScalar {
            value: Fr::rand(&mut rng),
        };
        let degree = threshold - 1;
        let prime = 0;

        let polynomial = Polynomial::new(secret, degree, prime);

        let commitment = Commitment::commit(&polynomial, G1Projective::generator());

        DkgParticipant {
            index,
            threshold,
            polynomial,
            commitment,
        }
    }

    pub fn generate_shares(&self, num_participants: u64) -> Vec<DkgSharePackage> {
        let mut shares = vec![];

        for j in 1..=num_participants {
            if j != self.index {
                let x = BlsScalar { value: Fr::from(j) };
                let y = self.polynomial.evaluate(x);
                shares.push(DkgSharePackage {
                    sender_index: self.index,
                    receiver_index: j,
                    share: y,
                });
            }
        }

        shares
    }
}

#[derive(Clone, Debug)]
struct DkgResult {
    index: u64,
    key_share: BlsScalar,
    group_public_key: G1Projective,
    verification_commitment: Vec<G1Projective>,
}

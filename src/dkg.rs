use std::hash::BuildHasher;

use crate::feldman::Commitment;
use crate::field::{BlsScalar, Field};
use crate::polynomial::Polynomial;
use ark_bls12_381::{Fr, G1Projective};
use ark_ec::{AdditiveGroup, PrimeGroup};
use ark_ff::{UniformRand, Zero};

#[derive(Clone, Debug)]
pub struct DkgSharePackage {
    sender_index: u64,
    receiver_index: u64,
    pub share: BlsScalar,
}

#[derive(Clone, Debug)]
struct DkgResult {
    index: u64,
    key_share: BlsScalar,
    group_public_key: G1Projective,
    verification_commitment: Vec<G1Projective>,
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

    pub fn compute_result(
        &self,
        received_shares: &[DkgSharePackage],
        all_commitments: &[Commitment],
    ) -> DkgResult {
        let index = self.index;
        //first, evaluate self polynomial
        let x = BlsScalar {
            value: Fr::from(self.index),
        };
        let evaluated_share = self.polynomial.evaluate(x);

        //next, loop through to sum the key_share
        let mut key_share = evaluated_share;
        for received_share in received_shares {
            key_share = key_share.add(received_share.share);
        }

        //loop through to get the sum verification_commit
        let num_coeffs = all_commitments[0].points.len();
        let mut verification_commitment = vec![];

        for i in 0..num_coeffs {
            let mut sum = G1Projective::zero();
            for commitment in all_commitments {
                sum = sum + commitment.points[i];
            }
            verification_commitment.push(sum);
        }

        //the group private key will be verification_commit[0]
        let mut group_public_key = verification_commitment[0];

        DkgResult {
            index,
            key_share,
            group_public_key,
            verification_commitment,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::{PartialSignature, SignerNonce};
    use crate::schnorr::Signature;

    #[test]
    fn test_dkg_full_flow() {
        let threshold = 3;
        let num_participants = 5;

        // 1. Each participant creates their polynomial and commitments
        let participants: Vec<DkgParticipant> = (1..=num_participants)
            .map(|i| DkgParticipant::new(i, threshold))
            .collect();

        // 2. Each participant generates shares for all others
        let all_share_packages: Vec<Vec<DkgSharePackage>> = participants
            .iter()
            .map(|p| p.generate_shares(num_participants as u64))
            .collect();

        // 3. Collect all commitments
        let all_commitments: Vec<&Commitment> =
            participants.iter().map(|p| &p.commitment).collect();

        // 4. Each participant gathers shares sent TO them and computes result
        let mut results = vec![];
        for p in &participants {
            let my_shares: Vec<DkgSharePackage> = all_share_packages
                .iter()
                .flatten()
                .filter(|s| s.receiver_index == p.index)
                .cloned()
                .collect();

            let commitments: Vec<Commitment> =
                participants.iter().map(|p| p.commitment.clone()).collect();

            let result = p.compute_result(&my_shares, &commitments);
            results.push(result);
        }

        // 5. All participants should agree on the same group public key
        let group_pk = results[0].group_public_key;
        for result in &results {
            assert_eq!(result.group_public_key, group_pk);
        }

        // 6. Use 3 of 5 key shares to sign with FROSTs
        let nonce1 = SignerNonce::generate(1);
        let nonce2 = SignerNonce::generate(2);
        let nonce3 = SignerNonce::generate(3);
        let all_nonces = vec![nonce1, nonce2, nonce3];

        let message = b"DKG threshold signature";

        let ps1 = PartialSignature::sign(
            &all_nonces[0],
            &results[0].key_share.value,
            &all_nonces,
            &group_pk,
            message,
        );
        let ps2 = PartialSignature::sign(
            &all_nonces[1],
            &results[1].key_share.value,
            &all_nonces,
            &group_pk,
            message,
        );
        let ps3 = PartialSignature::sign(
            &all_nonces[2],
            &results[2].key_share.value,
            &all_nonces,
            &group_pk,
            message,
        );

        let partial_sigs = vec![ps1, ps2, ps3];
        let signature = PartialSignature::aggregate(&partial_sigs, &all_nonces);

        // 7. Verify the signature against the group public key
        assert!(signature.verify(&group_pk, message));
    }

    #[test]
    fn test_dkg_all_agree_on_public_key() {
        let threshold = 2;
        let num_participants = 3;

        let participants: Vec<DkgParticipant> = (1..=num_participants)
            .map(|i| DkgParticipant::new(i, threshold))
            .collect();

        let all_share_packages: Vec<Vec<DkgSharePackage>> = participants
            .iter()
            .map(|p| p.generate_shares(num_participants as u64))
            .collect();

        let mut results = vec![];
        for p in &participants {
            let my_shares: Vec<DkgSharePackage> = all_share_packages
                .iter()
                .flatten()
                .filter(|s| s.receiver_index == p.index)
                .cloned()
                .collect();

            let commitments: Vec<Commitment> =
                participants.iter().map(|p| p.commitment.clone()).collect();

            let result = p.compute_result(&my_shares, &commitments);
            results.push(result);
        }

        // Every participant must derive the same group public key
        for i in 1..results.len() {
            assert_eq!(results[0].group_public_key, results[i].group_public_key);
        }
    }

    #[test]
    fn test_dkg_different_signer_subset() {
        let threshold = 3;
        let num_participants = 5;

        let participants: Vec<DkgParticipant> = (1..=num_participants)
            .map(|i| DkgParticipant::new(i, threshold))
            .collect();

        let all_share_packages: Vec<Vec<DkgSharePackage>> = participants
            .iter()
            .map(|p| p.generate_shares(num_participants as u64))
            .collect();

        let mut results = vec![];
        for p in &participants {
            let my_shares: Vec<DkgSharePackage> = all_share_packages
                .iter()
                .flatten()
                .filter(|s| s.receiver_index == p.index)
                .cloned()
                .collect();

            let commitments: Vec<Commitment> =
                participants.iter().map(|p| p.commitment.clone()).collect();

            let result = p.compute_result(&my_shares, &commitments);
            results.push(result);
        }

        let group_pk = results[0].group_public_key;

        // Use signers 2, 4, 5 instead of 1, 2, 3
        let nonce2 = SignerNonce::generate(2);
        let nonce4 = SignerNonce::generate(4);
        let nonce5 = SignerNonce::generate(5);
        let all_nonces = vec![nonce2, nonce4, nonce5];

        let message = b"different subset signing";

        let ps2 = PartialSignature::sign(
            &all_nonces[0],
            &results[1].key_share.value,
            &all_nonces,
            &group_pk,
            message,
        );
        let ps4 = PartialSignature::sign(
            &all_nonces[1],
            &results[3].key_share.value,
            &all_nonces,
            &group_pk,
            message,
        );
        let ps5 = PartialSignature::sign(
            &all_nonces[2],
            &results[4].key_share.value,
            &all_nonces,
            &group_pk,
            message,
        );

        let partial_sigs = vec![ps2, ps4, ps5];
        let signature = PartialSignature::aggregate(&partial_sigs, &all_nonces);

        assert!(signature.verify(&group_pk, message));
    }

    #[test]
    fn test_dkg_wrong_message_fails() {
        let threshold = 3;
        let num_participants = 5;

        let participants: Vec<DkgParticipant> = (1..=num_participants)
            .map(|i| DkgParticipant::new(i, threshold))
            .collect();

        let all_share_packages: Vec<Vec<DkgSharePackage>> = participants
            .iter()
            .map(|p| p.generate_shares(num_participants as u64))
            .collect();

        let mut results = vec![];
        for p in &participants {
            let my_shares: Vec<DkgSharePackage> = all_share_packages
                .iter()
                .flatten()
                .filter(|s| s.receiver_index == p.index)
                .cloned()
                .collect();

            let commitments: Vec<Commitment> =
                participants.iter().map(|p| p.commitment.clone()).collect();

            let result = p.compute_result(&my_shares, &commitments);
            results.push(result);
        }

        let group_pk = results[0].group_public_key;

        let nonce1 = SignerNonce::generate(1);
        let nonce2 = SignerNonce::generate(2);
        let nonce3 = SignerNonce::generate(3);
        let all_nonces = vec![nonce1, nonce2, nonce3];

        let ps1 = PartialSignature::sign(
            &all_nonces[0],
            &results[0].key_share.value,
            &all_nonces,
            &group_pk,
            b"real message",
        );
        let ps2 = PartialSignature::sign(
            &all_nonces[1],
            &results[1].key_share.value,
            &all_nonces,
            &group_pk,
            b"real message",
        );
        let ps3 = PartialSignature::sign(
            &all_nonces[2],
            &results[2].key_share.value,
            &all_nonces,
            &group_pk,
            b"real message",
        );

        let partial_sigs = vec![ps1, ps2, ps3];
        let signature = PartialSignature::aggregate(&partial_sigs, &all_nonces);

        assert!(!signature.verify(&group_pk, b"tampered message"));
    }
}

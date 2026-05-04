use crate::error::ShamirError;
use crate::feldman::Commitment;
use crate::field::{BlsScalar, Field};
use crate::polynomial::Polynomial;
use ark_bls12_381::{Fr, G1Projective};
use ark_ec::PrimeGroup;
use ark_ff::{UniformRand, Zero};

/// A share package sent from one DKG participant to another.
#[derive(Clone, Debug)]
pub struct DkgSharePackage {
    pub sender_index: u64,
    pub receiver_index: u64,
    pub share: BlsScalar,
}

/// The final output each participant derives after the DKG protocol completes.
#[derive(Clone, Debug)]
pub struct DkgResult {
    pub index: u64,
    pub key_share: BlsScalar,
    pub group_public_key: G1Projective,
    pub verification_commitment: Vec<G1Projective>,
}

/// A participant in the DKG protocol holding a random polynomial and its Feldman commitment.
pub struct DkgParticipant {
    index: u64,
    pub threshold: usize,
    polynomial: Polynomial<BlsScalar>,
    pub commitment: Commitment,
}

impl DkgParticipant {
    /// Creates a new participant with a random polynomial and corresponding Feldman commitment.
    pub fn new(index: u64, threshold: usize) -> Result<Self, ShamirError> {
        if threshold == 0 {
            return Err(ShamirError::ZeroThresholdNumber);
        }

        let mut rng = rand_core::OsRng;
        let secret = BlsScalar {
            value: Fr::rand(&mut rng),
        };
        let degree = threshold - 1;
        let prime = 0;

        let polynomial = Polynomial::new(secret, degree, prime);
        let commitment = Commitment::commit(&polynomial, G1Projective::generator());

        Ok(DkgParticipant {
            index,
            threshold,
            polynomial,
            commitment,
        })
    }

    /// Evaluates the polynomial at each other participant's index to produce share packages.
    pub fn generate_shares(
        &self,
        num_participants: u64,
    ) -> Result<Vec<DkgSharePackage>, ShamirError> {
        if num_participants == 0 {
            return Err(ShamirError::NoParticipants);
        }

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

        Ok(shares)
    }

    /// Combines own polynomial evaluation with received shares to derive the final key share,
    pub fn compute_result(
        &self,
        received_shares: &[DkgSharePackage],
        all_commitments: &[Commitment],
    ) -> Result<DkgResult, ShamirError> {
        for received_share in received_shares {
            let sender_idx = received_share.sender_index as usize - 1;
            let commitment = &all_commitments[sender_idx];

            let share = crate::sharing::Share {
                x: BlsScalar {
                    value: Fr::from(received_share.receiver_index),
                },
                y: received_share.share,
            };

            if !Commitment::verify(&share, commitment, G1Projective::generator()) {
                return Err(ShamirError::InvalidShare);
            }
        }

        let x = BlsScalar {
            value: Fr::from(self.index),
        };
        let evaluated_share = self.polynomial.evaluate(x);

        let mut key_share = evaluated_share;
        for received_share in received_shares {
            key_share = key_share.add(received_share.share);
        }

        let num_coeffs = all_commitments[0].points.len();
        let mut verification_commitment = vec![];

        for i in 0..num_coeffs {
            let mut sum = G1Projective::zero();
            for commitment in all_commitments {
                sum = sum + commitment.points[i];
            }
            verification_commitment.push(sum);
        }

        let group_public_key = verification_commitment[0];

        Ok(DkgResult {
            index: self.index,
            key_share,
            group_public_key,
            verification_commitment,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::{PartialSignature, SignerNonce};

    fn run_dkg(threshold: usize, num_participants: u64) -> (G1Projective, Vec<DkgResult>) {
        let participants: Vec<DkgParticipant> = (1..=num_participants)
            .map(|i| DkgParticipant::new(i, threshold).unwrap())
            .collect();

        let all_share_packages: Vec<Vec<DkgSharePackage>> = participants
            .iter()
            .map(|p| p.generate_shares(num_participants).unwrap())
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

            let result = p.compute_result(&my_shares, &commitments).unwrap();
            results.push(result);
        }

        let group_pk = results[0].group_public_key;
        (group_pk, results)
    }

    #[test]
    fn test_dkg_full_flow() {
        let (group_pk, results) = run_dkg(3, 5);

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
        )
        .unwrap();
        let ps2 = PartialSignature::sign(
            &all_nonces[1],
            &results[1].key_share.value,
            &all_nonces,
            &group_pk,
            message,
        )
        .unwrap();
        let ps3 = PartialSignature::sign(
            &all_nonces[2],
            &results[2].key_share.value,
            &all_nonces,
            &group_pk,
            message,
        )
        .unwrap();

        let signature = PartialSignature::aggregate(&[ps1, ps2, ps3], &all_nonces).unwrap();
        assert!(signature.verify(&group_pk, message));
    }

    #[test]
    fn test_dkg_all_agree_on_public_key() {
        let (_, results) = run_dkg(2, 3);
        for i in 1..results.len() {
            assert_eq!(results[0].group_public_key, results[i].group_public_key);
        }
    }

    #[test]
    fn test_dkg_different_signer_subset() {
        let (group_pk, results) = run_dkg(3, 5);

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
        )
        .unwrap();
        let ps4 = PartialSignature::sign(
            &all_nonces[1],
            &results[3].key_share.value,
            &all_nonces,
            &group_pk,
            message,
        )
        .unwrap();
        let ps5 = PartialSignature::sign(
            &all_nonces[2],
            &results[4].key_share.value,
            &all_nonces,
            &group_pk,
            message,
        )
        .unwrap();

        let signature = PartialSignature::aggregate(&[ps2, ps4, ps5], &all_nonces).unwrap();
        assert!(signature.verify(&group_pk, message));
    }

    #[test]
    fn test_dkg_wrong_message_fails() {
        let (group_pk, results) = run_dkg(3, 5);

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
        )
        .unwrap();
        let ps2 = PartialSignature::sign(
            &all_nonces[1],
            &results[1].key_share.value,
            &all_nonces,
            &group_pk,
            b"real message",
        )
        .unwrap();
        let ps3 = PartialSignature::sign(
            &all_nonces[2],
            &results[2].key_share.value,
            &all_nonces,
            &group_pk,
            b"real message",
        )
        .unwrap();

        let signature = PartialSignature::aggregate(&[ps1, ps2, ps3], &all_nonces).unwrap();
        assert!(!signature.verify(&group_pk, b"tampered message"));
    }

    #[test]
    fn test_dkg_zero_threshold_errors() {
        let result = DkgParticipant::new(1, 0);
        assert!(matches!(result, Err(ShamirError::ZeroThresholdNumber)));
    }

    #[test]
    fn test_dkg_zero_participants_errors() {
        let p = DkgParticipant::new(1, 2).unwrap();
        let result = p.generate_shares(0);
        assert!(matches!(result, Err(ShamirError::NoParticipants)));
    }
}

use crate::error::ShamirError;
use crate::field::{BlsScalar, Field};
use crate::polynomial::Polynomial;
use crate::sharing::Share;
use ark_bls12_381::{Fr, G1Projective};
use ark_ec::{CurveGroup, PrimeGroup};

#[derive(Clone)]
pub struct Commitment {
    pub points: Vec<G1Projective>,
}

impl Commitment {
    pub fn commit(poly: &Polynomial<BlsScalar>, generator: G1Projective) -> Commitment {
        let mut result = Vec::new();

        for coefficient in poly.get_coefficients() {
            let temp = generator * coefficient.value;
            result.push(temp);
        }

        Commitment { points: result }
    }

    pub fn verify(
        share: &Share<BlsScalar>,
        commitment: &Commitment,
        generator: G1Projective,
    ) -> bool {
        let left_result = generator * share.y.value;

        let mut right_result = commitment.points[0];
        let mut x_power = share.x.value;

        for c in &commitment.points[1..] {
            right_result = right_result + (*c * x_power);
            x_power = x_power * share.x.value;
        }

        left_result == right_result
    }

    pub fn split_with_commitments(
        secret: BlsScalar,
        threshold: u64,
        num_shares: u64,
        generator: G1Projective,
    ) -> Result<(Vec<Share<BlsScalar>>, Commitment), ShamirError> {
        if threshold == 0 {
            return Err(ShamirError::ZeroThresholdNumber);
        }

        if num_shares == 0 {
            return Err(ShamirError::ZeroShareNumber);
        }

        if threshold > num_shares {
            return Err(ShamirError::InvalidShareNumber);
        }

        let degree = threshold - 1;

        let mut counter = BlsScalar::one(0);
        let one = BlsScalar::one(0);
        let mut result = vec![];
        let polynome = Polynomial::new(secret, degree as usize, 0);

        for _ in 0..num_shares {
            let temp_result = polynome.evaluate(counter);
            let perm_result = Share {
                x: counter,
                y: temp_result,
            };
            result.push(perm_result);
            counter = counter.add(one);
        }

        let commitment = Commitment::commit(&polynome, generator);
        Ok((result, commitment))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;

    #[test]
    #[test]
    fn test_feldman_verify_valid_shares() {
        let secret = BlsScalar {
            value: Fr::from(42),
        };
        let poly = Polynomial::new(secret, 2, 0);
        let generator = G1Projective::generator();

        let commitment = Commitment::commit(&poly, generator);

        // Generate shares from the SAME polynomial we committed to
        for i in 1..=5 {
            let x = BlsScalar {
                value: Fr::from(i as u64),
            };
            let y = poly.evaluate(x);
            let share = Share { x, y };
            assert!(Commitment::verify(&share, &commitment, generator));
        }
    }

    #[test]
    fn test_feldman_reject_fake_share() {
        let secret = BlsScalar {
            value: Fr::from(42),
        };
        let poly = Polynomial::new(secret, 2, 0);
        let generator = G1Projective::generator();

        let commitment = Commitment::commit(&poly, generator);

        // Create a fake share with a made-up y value
        let fake_share = Share {
            x: BlsScalar { value: Fr::from(1) },
            y: BlsScalar {
                value: Fr::from(999),
            },
        };

        assert!(!Commitment::verify(&fake_share, &commitment, generator));
    }

    #[test]
    fn test_split_with_commitments_all_verify() {
        let secret = BlsScalar {
            value: Fr::from(42),
        };
        let generator = G1Projective::generator();

        let (shares, commitment) =
            Commitment::split_with_commitments(secret, 3, 5, generator).unwrap();

        for share in &shares {
            assert!(Commitment::verify(share, &commitment, generator));
        }
    }

    #[test]
    fn test_split_with_commitments_reconstruct() {
        let secret = BlsScalar {
            value: Fr::from(42),
        };
        let generator = G1Projective::generator();

        let (shares, _commitment) =
            Commitment::split_with_commitments(secret, 3, 5, generator).unwrap();

        let subset: Vec<Share<BlsScalar>> = shares.into_iter().take(3).collect();
        let recovered = Share::reconstruct(subset, 0).unwrap();
        assert_eq!(recovered.value, Fr::from(42));
    }

    #[test]
    fn test_split_with_commitments_fake_share_fails() {
        let secret = BlsScalar {
            value: Fr::from(42),
        };
        let generator = G1Projective::generator();

        let (_shares, commitment) =
            Commitment::split_with_commitments(secret, 3, 5, generator).unwrap();

        let fake = Share {
            x: BlsScalar { value: Fr::from(1) },
            y: BlsScalar {
                value: Fr::from(999),
            },
        };

        assert!(!Commitment::verify(&fake, &commitment, generator));
    }
}

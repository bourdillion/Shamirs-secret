use serde::{Deserialize, Serialize};

use crate::error::ShamirError;
use crate::field::{Field, is_prime};
use crate::polynomial::Polynomial;

/// Share is a point (x, y) on the polynomial curve, given to a participant.
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct Share<F: Field + Copy + Clone + PartialEq> {
    pub x: F,
    pub y: F,
}

impl<F: Field + Copy + Clone + PartialEq> Share<F> {
    /// Splits a secret into shares using a random polynomial.
    /// threshold = minimum shares needed to reconstruct.
    pub fn split(
        secret: F,
        threshold: u64,
        number_of_shares: u64,
        prime: u64,
    ) -> Result<Vec<Share<F>>, ShamirError> {
        if threshold == 0 {
            return Err(ShamirError::ZeroThresholdNumber);
        }

        if number_of_shares == 0 {
            return Err(ShamirError::ZeroShareNumber);
        }

        if threshold > number_of_shares {
            return Err(ShamirError::InvalidShareNumber);
        }

        if prime != 0 && !is_prime(prime) {
            return Err(ShamirError::NonPrimeModulus);
        }

        let degree = threshold - 1;

        let mut counter = F::one(prime);
        let one = F::one(prime);
        let mut result = vec![];
        let polynome = Polynomial::new(secret, degree as usize, prime);

        // Evaluate polynomial at x = 1, 2, 3, ...no. of shares to produce shares
        for _ in 0..number_of_shares {
            let temp_result = polynome.evaluate(counter);
            let perm_result = Share {
                x: counter,
                y: temp_result,
            };
            result.push(perm_result);
            counter = counter.add(one);
        }

        Ok(result)
    }

    /// Recovers the secret from shares using Lagrange interpolation at x = 0.
    pub fn reconstruct(shares: Vec<Share<F>>, prime: u64) -> Result<F, ShamirError> {
        //sanity checks
        if shares.is_empty() {
            return Err(ShamirError::ZeroShareNumber);
        }

        if prime != 0 && !is_prime(prime) {
            return Err(ShamirError::NonPrimeModulus);
        }

        // Check for duplicate x values
        for i in 0..shares.len() {
            for j in (i + 1)..shares.len() {
                if shares[i].x == shares[j].x {
                    return Err(ShamirError::DuplicateShareValue);
                }
            }
        }

        let mut secret = F::zero(prime);

        // Compute the basis from lagrange, product of (0 - x_j) / (x_i - x_j) for all j != i
        for share_i in &shares {
            let mut basis = F::one(prime);

            for share_j in &shares {
                if share_j.x != share_i.x {
                    let num = F::zero(prime).subtract(share_j.x);
                    let denom = share_i.x.subtract(share_j.x);
                    let result_temp = num.division(denom).unwrap();
                    basis = basis.multiply(result_temp);
                }
            }

            // Each share's contribution is equals to y_i * basis_i
            let contribution = share_i.y.multiply(basis);
            secret = secret.add(contribution);
        }
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::SimpleField;

    fn make(value: u64) -> SimpleField {
        SimpleField { value, prime: 17 }
    }

    #[test]
    fn test_full_round_trip() {
        let shares = Share::split(make(7), 3, 5, 17).unwrap();
        let subset: Vec<Share<SimpleField>> = shares.into_iter().take(3).collect();
        let secret = Share::reconstruct(subset, 17).unwrap();
        assert_eq!(secret.value, 7);
    }

    #[test]
    fn test_round_trip_different_subset() {
        let shares = Share::split(make(7), 3, 5, 17).unwrap();
        let subset: Vec<Share<SimpleField>> = vec![shares[1], shares[3], shares[4]];
        let secret = Share::reconstruct(subset, 17).unwrap();
        assert_eq!(secret.value, 7);
    }

    #[test]
    fn test_round_trip_exact_threshold() {
        let shares = Share::split(make(10), 2, 3, 17).unwrap();
        let subset: Vec<Share<SimpleField>> = shares.into_iter().take(2).collect();
        let secret = Share::reconstruct(subset, 17).unwrap();
        assert_eq!(secret.value, 10);
    }

    #[test]
    fn test_round_trip_all_shares() {
        let shares = Share::split(make(7), 3, 5, 17).unwrap();
        let secret = Share::reconstruct(shares, 17).unwrap();
        assert_eq!(secret.value, 7);
    }

    #[test]
    fn test_round_trip_secret_zero() {
        let shares = Share::split(make(0), 3, 5, 17).unwrap();
        let subset: Vec<Share<SimpleField>> = shares.into_iter().take(3).collect();
        let secret = Share::reconstruct(subset, 17).unwrap();
        assert_eq!(secret.value, 0);
    }

    #[test]
    fn test_round_trip_different_secret() {
        let shares = Share::split(make(13), 3, 5, 17).unwrap();
        let subset: Vec<Share<SimpleField>> = shares.into_iter().take(3).collect();
        let secret = Share::reconstruct(subset, 17).unwrap();
        assert_eq!(secret.value, 13);
    }

    #[test]
    fn test_round_trip_larger_prime() {
        fn make_29(value: u64) -> SimpleField {
            SimpleField { value, prime: 29 }
        }
        let shares = Share::split(make_29(19), 3, 5, 29).unwrap();
        let subset: Vec<Share<SimpleField>> = shares.into_iter().take(3).collect();
        let secret = Share::reconstruct(subset, 29).unwrap();
        assert_eq!(secret.value, 19);
    }

    #[test]
    fn test_below_threshold_fails() {
        let mut wrong_count = 0;
        for _ in 0..10 {
            let shares = Share::split(make(7), 3, 5, 17).unwrap();
            let subset: Vec<Share<SimpleField>> = shares.into_iter().take(2).collect();
            let secret = Share::reconstruct(subset, 17).unwrap();
            if secret.value != 7 {
                wrong_count += 1;
            }
        }
        assert!(wrong_count > 5);
    }

    #[test]
    fn test_shares_are_unique() {
        let shares = Share::split(make(7), 3, 5, 17).unwrap();
        for i in 0..shares.len() {
            for j in (i + 1)..shares.len() {
                assert_ne!(shares[i].x.value, shares[j].x.value);
            }
        }
    }

    // Error case tests

    #[test]
    fn test_zero_threshold_errors() {
        let result = Share::split(make(7), 0, 5, 17);
        assert!(result.is_err());
    }

    #[test]
    fn test_threshold_greater_than_shares_errors() {
        let result = Share::split(make(7), 5, 3, 17);
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_shares_errors() {
        let result = Share::split(make(7), 0, 0, 17);
        assert!(result.is_err());
    }

    #[test]
    fn test_reconstruct_empty_shares_errors() {
        let result = Share::<SimpleField>::reconstruct(vec![], 17);
        assert!(result.is_err());
    }

    #[test]
    fn test_reconstruct_duplicate_x_errors() {
        let share_a = Share {
            x: make(1),
            y: make(9),
        };
        let share_b = Share {
            x: make(1),
            y: make(7),
        };
        let result = Share::reconstruct(vec![share_a, share_b], 17);
        assert!(result.is_err());
    }

    #[test]
    fn test_share_serialization() {
        let share = Share {
            x: make(3),
            y: make(9),
        };
        let json = serde_json::to_string(&share).unwrap();
        let recovered: Share<SimpleField> = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.x.value, 3);
        assert_eq!(recovered.y.value, 9);
    }
}

use crate::field::Field;
use crate::polynomial::Polynomial;

/// A point (x, y) on the polynomial curve, given to a participant.
#[derive(Copy, Clone)]
struct Share<F: Field + Copy + Clone + PartialEq> {
    x: F,
    y: F,
}

impl<F: Field + Copy + Clone + PartialEq> Share<F> {
    /// Splits a secret into shares using a random polynomial.
    /// threshold = minimum shares needed to reconstruct.
    fn split(secret: F, threshold: u64, number_of_shares: u64, prime: u64) -> Vec<Share<F>> {
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

        result
    }

    /// Recovers the secret from shares using Lagrange interpolation at x = 0.
    fn reconstruct(shares: Vec<Share<F>>, prime: u64) -> F {
        let mut secret = F::zero(prime);

        // Compute the basis from langrange, product of (0 - x_j) / (x_i - x_j) for all j != i
        for share_i in &shares {
            let mut basis = F::one(prime);

            for share_j in &shares {
                if share_j.x != share_i.x {
                    let num = F::zero(prime).subtract(share_j.x);
                    let denom = share_i.x.subtract(share_j.x);
                    let result_temp = num.division(denom);
                    basis = basis.multiply(result_temp);
                }
            }

            // Each share's contribution is equals to y_i * basis_i
            let contribution = share_i.y.multiply(basis);
            secret = secret.add(contribution);
        }
        secret
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
        let shares = Share::split(make(7), 3, 5, 17);
        let subset: Vec<Share<SimpleField>> = shares.into_iter().take(3).collect();
        let secret = Share::reconstruct(subset, 17);
        assert_eq!(secret.value, 7);
    }

    #[test]
    fn test_round_trip_different_subset() {
        let shares = Share::split(make(7), 3, 5, 17);
        let subset: Vec<Share<SimpleField>> = vec![shares[1], shares[3], shares[4]];
        let secret = Share::reconstruct(subset, 17);
        assert_eq!(secret.value, 7);
    }

    #[test]
    fn test_round_trip_exact_threshold() {
        let shares = Share::split(make(10), 2, 3, 17);
        let subset: Vec<Share<SimpleField>> = shares.into_iter().take(2).collect();
        let secret = Share::reconstruct(subset, 17);
        assert_eq!(secret.value, 10);
    }

    #[test]
    fn test_round_trip_all_shares() {
        let shares = Share::split(make(7), 3, 5, 17);
        let secret = Share::reconstruct(shares, 17);
        assert_eq!(secret.value, 7);
    }

    #[test]
    fn test_round_trip_secret_zero() {
        let shares = Share::split(make(0), 3, 5, 17);
        let subset: Vec<Share<SimpleField>> = shares.into_iter().take(3).collect();
        let secret = Share::reconstruct(subset, 17);
        assert_eq!(secret.value, 0);
    }

    #[test]
    fn test_round_trip_different_secret() {
        let shares = Share::split(make(13), 3, 5, 17);
        let subset: Vec<Share<SimpleField>> = shares.into_iter().take(3).collect();
        let secret = Share::reconstruct(subset, 17);
        assert_eq!(secret.value, 13);
    }

    #[test]
    fn test_round_trip_larger_prime() {
        fn make_29(value: u64) -> SimpleField {
            SimpleField { value, prime: 29 }
        }
        let shares = Share::split(make_29(19), 3, 5, 29);
        let subset: Vec<Share<SimpleField>> = shares.into_iter().take(3).collect();
        let secret = Share::reconstruct(subset, 29);
        assert_eq!(secret.value, 19);
    }

    #[test]
    fn test_below_threshold_fails() {
        let mut wrong_count = 0;
        for _ in 0..10 {
            let shares = Share::split(make(7), 3, 5, 17);
            let subset: Vec<Share<SimpleField>> = shares.into_iter().take(2).collect();
            let secret = Share::reconstruct(subset, 17);
            if secret.value != 7 {
                wrong_count += 1;
            }
        }
        assert!(wrong_count > 5);
    }

    #[test]
    fn test_shares_are_unique() {
        let shares = Share::split(make(7), 3, 5, 17);
        for i in 0..shares.len() {
            for j in (i + 1)..shares.len() {
                assert_ne!(shares[i].x.value, shares[j].x.value);
            }
        }
    }
}

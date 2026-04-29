use crate::field::{Field, SimpleField};
use crate::polynomial::Polynomial;
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
        // Take only the first 3 shares (the threshold)
        let subset: Vec<Share<SimpleField>> = shares.into_iter().take(3).collect();
        let secret = Share::reconstruct(subset, 17);
        assert_eq!(secret.value, 7);
    }
}

use crate::error::ShamirError;
use ark_bls12_381::Fr;
use ark_ff::{Field as ArkField, UniformRand};
use rand::RngExt;
use serde::{Deserialize, Serialize};

/// Core finite field trait for modular arithmetic.
pub trait Field: Sized {
    /// Adds two field elements, returning the result mod p.
    fn add(self, x: Self) -> Self;

    /// Subtracts x from self, returning the result mod p.
    fn subtract(self, x: Self) -> Self;

    /// Multiplies two field elements, returning the result mod p.
    fn multiply(self, x: Self) -> Self;

    /// Computes the multiplicative inverse using Fermat's little theorem.
    fn mul_inverse(self) -> Result<Self, ShamirError>;

    /// Divides self by x via multiplication with x's inverse.
    fn division(self, x: Self) -> Result<Self, ShamirError> {
        let x_inverse = x.mul_inverse()?;
        Ok(self.multiply(x_inverse))
    }

    /// Returns the prime modulus of this field.
    /// For BLS12-381 scalars, returns 0 since the prime doesn't fit in u64.
    fn prime(&self) -> u64;

    /// Returns the additive identity (0) for a field with the given prime.
    fn zero(x: u64) -> Self;

    /// Returns the multiplicative identity (1) for a field with the given prime.
    fn one(x: u64) -> Self;

    /// Returns a random element in the field.
    fn random(x: u64) -> Self;
}

/// A simple finite field element using u64 arithmetic mod a small prime. Useful for testing with small fields
#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimpleField {
    pub value: u64,
    pub prime: u64,
}

impl Field for SimpleField {
    fn add(self, x: Self) -> Self {
        SimpleField {
            value: (self.value + x.value) % self.prime,
            prime: self.prime,
        }
    }

    fn subtract(self, x: Self) -> Self {
        SimpleField {
            value: (self.value + self.prime - x.value) % self.prime,
            prime: self.prime,
        }
    }

    fn multiply(self, x: Self) -> Self {
        SimpleField {
            value: (self.value * x.value) % self.prime,
            prime: self.prime,
        }
    }

    fn mul_inverse(self) -> Result<Self, ShamirError> {
        if self.value == 0 {
            return Err(ShamirError::ZeroInverse);
        }
        // From Fermat's little theorem: a^(p-2) ≡ a^(-1) (mod p)
        let exp = self.prime - 2;
        let inverse = SimpleField::exp_inverse(self.value, exp, self.prime);
        Ok(SimpleField {
            value: inverse,
            prime: self.prime,
        })
    }

    fn prime(&self) -> u64 {
        self.prime
    }

    fn one(prime: u64) -> Self {
        SimpleField { value: 1, prime }
    }

    fn random(x: u64) -> Self {
        let mut rnd_gen = rand::rng();
        let max = x - 1;
        let rnd = rnd_gen.random_range(0..=max);
        SimpleField {
            value: rnd,
            prime: x,
        }
    }

    fn zero(prime: u64) -> Self {
        SimpleField { value: 0, prime }
    }
}

impl SimpleField {
    /// Modular exponentiation via repeated squaring method.
    fn exp_inverse(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
        let mut result: u64 = 1;
        base %= modulus;

        while exp > 0 {
            if exp % 2 == 1 {
                result = (result * base) % modulus;
            }
            exp >>= 1;
            base = (base * base) % modulus;
        }

        result
    }
}

/// Helper fn to check if n is a prime number using trial division.
/// It tests divisibility up to √n with the 6k +/- 1 optimization.
pub fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n < 4 {
        return true;
    }
    if n % 2 == 0 || n % 3 == 0 {
        return false;
    }
    let mut i = 5;
    while i * i <= n {
        if n % i == 0 || n % (i + 2) == 0 {
            return false;
        }
        i += 6;
    }
    true
}

impl std::ops::Add for SimpleField {
    type Output = Self;
    fn add(self, rhs: SimpleField) -> SimpleField {
        Field::add(self, rhs)
    }
}

impl std::ops::Sub for SimpleField {
    type Output = Self;
    fn sub(self, rhs: SimpleField) -> SimpleField {
        Field::subtract(self, rhs)
    }
}

impl std::ops::Mul for SimpleField {
    type Output = Self;
    fn mul(self, rhs: SimpleField) -> SimpleField {
        Field::multiply(self, rhs)
    }
}

impl std::ops::Div for SimpleField {
    type Output = Self;
    fn div(self, rhs: SimpleField) -> SimpleField {
        Field::division(self, rhs).expect("division by zero")
    }
}

/// BLS12-381 scalar field element wrapping ark-bls12-381's Fr.
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct BlsScalar {
    pub value: Fr,
}

impl Field for BlsScalar {
    fn add(self, x: Self) -> Self {
        BlsScalar {
            value: self.value + x.value,
        }
    }

    fn subtract(self, x: Self) -> Self {
        BlsScalar {
            value: self.value - x.value,
        }
    }

    fn multiply(self, x: Self) -> Self {
        BlsScalar {
            value: self.value * x.value,
        }
    }

    fn division(self, x: Self) -> Result<Self, ShamirError> {
        if x.value == Fr::from(0u64) {
            return Err(ShamirError::ZeroInverse);
        }
        Ok(BlsScalar {
            value: self.value / x.value,
        })
    }

    fn zero(_prime: u64) -> Self {
        BlsScalar { value: Fr::from(0) }
    }

    fn one(_prime: u64) -> Self {
        BlsScalar { value: Fr::from(1) }
    }

    fn mul_inverse(self) -> Result<Self, ShamirError> {
        match self.value.inverse() {
            Some(inv) => Ok(BlsScalar { value: inv }),
            None => Err(ShamirError::ZeroInverse),
        }
    }

    fn random(_prime: u64) -> Self {
        let mut rng = rand_core::OsRng;
        BlsScalar {
            value: Fr::rand(&mut rng),
        }
    }

    fn prime(&self) -> u64 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn make(value: u64) -> SimpleField {
        SimpleField { value, prime: 17 }
    }

    #[test]
    fn test_add() {
        let result = make(5).add(make(3));
        assert_eq!(result.value, 8);
    }

    #[test]
    fn test_subtract_aoverb() {
        let result = make(5).subtract(make(3));
        assert_eq!(result.value, 2);
    }

    #[test]
    fn test_subtract_bovera() {
        let result = make(3).subtract(make(5));
        assert_eq!(result.value, 15);
    }

    #[test]
    fn test_multiply() {
        let result = make(5).multiply(make(3));
        assert_eq!(result.value, 15);
    }

    #[test]
    fn test_divide() {
        let result = make(5).division(make(3)).unwrap();
        assert_eq!(result.value, 13);
    }

    #[test]
    fn test_inverse_of_zero_errors() {
        let result = make(0).mul_inverse();
        assert!(matches!(result, Err(ShamirError::ZeroInverse)));
    }

    #[test]
    fn test_division_by_zero_errors() {
        let result = make(5).division(make(0));
        assert!(matches!(result, Err(ShamirError::ZeroInverse)));
    }

    #[test]
    fn test_bls_inverse_of_zero_errors() {
        let zero = BlsScalar { value: Fr::from(0) };
        let result = zero.mul_inverse();
        assert!(matches!(result, Err(ShamirError::ZeroInverse)));
    }

    #[test]
    fn test_bls_round_trip() {
        use crate::sharing::Share;

        let secret = BlsScalar {
            value: Fr::from(42),
        };
        let shares = Share::split(secret, 3, 5, 0).unwrap();
        let subset: Vec<_> = shares.into_iter().take(3).collect();
        let recovered = Share::reconstruct(subset, 0).unwrap();
        assert_eq!(recovered.value, Fr::from(42));
    }

    #[test]
    fn test_bls_different_subset() {
        use crate::sharing::Share;

        let secret = BlsScalar {
            value: Fr::from(42),
        };
        let shares = Share::split(secret, 3, 5, 0).unwrap();
        let subset = vec![shares[0], shares[2], shares[4]];
        let recovered = Share::reconstruct(subset, 0).unwrap();
        assert_eq!(recovered.value, Fr::from(42));
    }

    #[test]
    fn test_bls_large_secret() {
        use crate::sharing::Share;

        let secret = BlsScalar {
            value: Fr::from(123456789u64),
        };
        let shares = Share::split(secret, 3, 5, 0).unwrap();
        let subset: Vec<_> = shares.into_iter().take(3).collect();
        let recovered = Share::reconstruct(subset, 0).unwrap();
        assert_eq!(recovered.value, Fr::from(123456789u64));
    }

    proptest! {
        #[test]
        fn add_then_subtract_is_identity(a in 0u64..17, b in 0u64..17) {
            let result = make(a).add(make(b)).subtract(make(b));
            assert_eq!(result.value, a);
        }

        #[test]
        fn multiply_then_divide_is_identity(a in 0u64..17, b in 1u64..17) {
            let result = make(a).multiply(make(b)).division(make(b)).unwrap();
            assert_eq!(result.value, a);
        }

        #[test]
        fn inverse_times_self_is_one(a in 1u64..17) {
            let result = make(a).multiply(make(a).mul_inverse().unwrap());
            assert_eq!(result.value, 1);
        }

        #[test]
        fn addition_is_commutative(a in 0u64..17, b in 0u64..17) {
            let r1 = make(a).add(make(b));
            let r2 = make(b).add(make(a));
            assert_eq!(r1.value, r2.value);
        }

        #[test]
        fn multiplication_is_commutative(a in 0u64..17, b in 0u64..17) {
            let r1 = make(a).multiply(make(b));
            let r2 = make(b).multiply(make(a));
            assert_eq!(r1.value, r2.value);
        }

        #[test]
        fn result_stays_in_field(a in 0u64..17, b in 0u64..17) {
            assert!(make(a).add(make(b)).value < 17);
            assert!(make(a).subtract(make(b)).value < 17);
            assert!(make(a).multiply(make(b)).value < 17);
        }
    }
}

use crate::field::Field;

/// This struct represents a polynomial over a finite field.
pub struct Polynomial<F: Field + Copy + Clone> {
    pub coefficients: Vec<F>,
}

impl<F: Field + Copy + Clone> Polynomial<F> {
    /// Creates a random polynomial with the secret as the constant term.
    /// degree is equals to threshold - 1, so t shares can reconstruct the secret.
    pub fn new(secret: F, degree: usize, prime: u64) -> Self {
        //start with the secret at index 0.
        let mut result = vec![secret];
        //loop through random coefficient and add to the vector
        for _ in 0..degree {
            let rand = F::random(prime);
            result.push(rand);
        }
        Polynomial {
            coefficients: result,
        }
    }

    ///using horner's principle to evaluate polynomials
    pub fn evaluate(&self, x: F) -> F
    where
        F: Field + Copy + Clone,
    {
        //Start from zero field
        let mut result = F::zero(x.prime());
        //reverse the vec, so we can start from inside to end outside just as horner rult
        let rev_coeficients = self.coefficients.iter().rev();

        //Evaluate for each coefficient.
        for coefficient in rev_coeficients {
            result = result.multiply(x).add(*coefficient)
        }

        result
    }

    pub fn get_coefficients(&self) -> &Vec<F> {
        &self.coefficients
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::field::SimpleField;

    fn make(value: u64) -> SimpleField {
        SimpleField { value, prime: 17 }
    }

    #[test]
    fn test_new_secret_is_first() {
        let poly = Polynomial::new(make(7), 2, 17);
        assert_eq!(poly.coefficients[0].value, 7);
    }

    #[test]
    fn test_new_correct_length() {
        let poly = Polynomial::new(make(7), 2, 17);
        assert_eq!(poly.coefficients.len(), 3);
    }

    #[test]
    fn test_new_all_values_in_field() {
        let poly = Polynomial::new(make(7), 4, 17);
        for coeff in &poly.coefficients {
            assert!(coeff.value < 17);
        }
    }

    #[test]
    fn test_evaluate() {
        let y1 = make(7);
        let y2 = make(3);
        let y3 = make(16);
        let polnoms = Polynomial {
            coefficients: vec![y1, y2, y3],
        };
        let x = make(1);
        let result = polnoms.evaluate(x);

        println!("value is {}", result.value);
        assert_eq!(result.value, 9);
    }

    #[test]
    fn test_evaluate_at_3() {
        let polnoms = Polynomial {
            coefficients: vec![make(7), make(3), make(16)],
        };
        let result = polnoms.evaluate(make(3));
        assert_eq!(result.value, 7);
    }

    #[test]
    fn test_evaluate_at_4() {
        let polnoms = Polynomial {
            coefficients: vec![make(7), make(3), make(16)],
        };
        let result = polnoms.evaluate(make(4));
        assert_eq!(result.value, 3);
    }

    #[test]
    fn test_new_then_evaluate_secret_at_zero() {
        let poly = Polynomial::new(make(7), 2, 17);
        let result = poly.evaluate(make(0));
        assert_eq!(result.value, 7);
    }

    #[test]
    fn test_new_then_evaluate_stays_in_field() {
        let poly = Polynomial::new(make(7), 3, 17);
        for x in 1..=5 {
            let result = poly.evaluate(make(x));
            assert!(result.value < 17);
        }
    }

    #[test]
    fn test_new_then_evaluate_different_x_values() {
        let poly = Polynomial::new(make(7), 2, 17);
        let y1 = poly.evaluate(make(1));
        let y2 = poly.evaluate(make(2));
        let y3 = poly.evaluate(make(3));
        // All results should be valid field elements
        assert!(y1.value < 17);
        assert!(y2.value < 17);
        assert!(y3.value < 17);
    }
}

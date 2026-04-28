use crate::field::Field;

struct Polynomial<F: Field + Copy + Clone> {
    coefficients: Vec<F>,
}

impl<F: Field + Copy + Clone> Polynomial<F> {
    //using horner's principle to evaluate polynomials
    fn evaluate(&self, x: F) -> F
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
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::field::SimpleField;

    fn make(value: u64) -> SimpleField {
        SimpleField { value, prime: 17 }
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
}

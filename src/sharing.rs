use crate::field::{Field, SimpleField};
use crate::polynomial::Polynomial;
struct Share<F: Field + Copy + Clone> {
    x: F,
    y: F,
}

impl<F: Field + Copy + Clone> Share<F> {
    fn split(secret: F, threshold: u64, number_of_shares: u64, prime: u64) -> Vec<Share<F>> {
        let degree = threshold - 1;

        let mut counter = F::one(prime);
        let one = F::one(prime);
        let mut result = vec![];
        let polynome = Polynomial::new(secret, degree as usize, prime);

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
}

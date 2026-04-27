use rand::RngExt;

pub trait Field: Sized {
    fn add(self, x: Self) -> Self;

    fn subtract(self, x: Self) -> Self;

    fn multiply(self, x: Self) -> Self;

    fn mul_inverse(self) -> Self;

    fn division(self, x: Self) -> Self {
        let x_inverse = x.mul_inverse();
        self.multiply(x_inverse)
    }

    fn zero(x: u64) -> Self;

    fn one(x: u64) -> Self;

    fn random(x: u64) -> Self;
}

struct SimpleField {
    value: u64,
    prime: u64,
}

impl Field for SimpleField {
    fn add(self, x: Self) -> Self {
        let value_added = (self.value + x.value) % self.prime;
        let ans = SimpleField {
            value: value_added,
            prime: self.prime,
        };
        ans
    }

    fn subtract(self, x: Self) -> Self {
        let value_sub = (self.value + self.prime - x.value) % self.prime;

        SimpleField {
            value: value_sub,
            prime: self.prime,
        }
    }

    fn mul_inverse(self) -> Self {
        SimpleField { value: 1, prime: 1 }
    }

    fn multiply(self, x: Self) -> Self {
        let value_mul: u64 = (self.value * x.value) % self.prime;
        SimpleField {
            value: value_mul,
            prime: self.prime,
        }
    }

    fn one(prime: u64) -> Self {
        SimpleField {
            value: 1,
            prime: prime,
        }
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
        SimpleField {
            value: 0,
            prime: prime,
        }
    }
}

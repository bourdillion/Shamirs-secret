pub trait Field: Sized {
    fn add(self, x: Self) -> Self;

    fn subtract(self, x: Self) -> Self;

    fn multiply(self, x: Self) -> Self;

    fn mul_inverse(self) -> Self;

    fn division(self, x: Self) -> Self {
        let x_inverse = x.mul_inverse();
        self.multiply(x_inverse)
    }

    fn zero() -> Self;

    fn one() -> Self;

    fn random(x: u64) -> Self;
}

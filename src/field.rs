pub trait Field {
    fn add(self, x: Self) -> Self;

    fn subtract(self, x: Self) -> Self;

    fn multiply(self, x: Self) -> Self;

    fn mul_inverse(self) -> Self;

    fn division(&self, x: Self) -> Self;

    fn zero() -> Self;

    fn one() -> Self;

    fn random(self) -> Self;
}

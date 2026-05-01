use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShamirError {
    #[error("Threshold cannot be zero")]
    ZeroThresholdNumber,

    #[error("Threshold cannot be greater than shares number")]
    InvalidShareNumber,

    #[error("Shares cannot be zero")]
    ZeroShareNumber,

    #[error("Duplicate value in shares will break reconstruction")]
    DuplicateShareValue,

    #[error("Modulus must be a prime number")]
    NonPrimeModulus,
}

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

    #[error("No nonces provided")]
    EmptyNonces,

    #[error("No partial signatures provided")]
    EmptyPartialSignatures,

    #[error("Signer index not found in nonces")]
    SignerIndexNotFound,

    #[error("Received share failed verification")]
    InvalidShare,

    #[error("No participants provided")]
    NoParticipants,

    #[error("Duplicate signer index")]
    DuplicateSignerIndex,

    #[error("Cannot compute inverse of zero")]
    ZeroInverse,
}

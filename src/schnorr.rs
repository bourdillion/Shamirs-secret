use ark_bls12_381::{Fr, G1Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{PrimeField, UniformRand};
use sha2::{Digest, Sha256};

/// A Schnorr keypair over BLS12-381 G1.
struct KeyPair {
    private_key: Fr,
    public_key: G1Projective,
}

impl KeyPair {
    /// Generates a random keypair. x ← random, X = x * G.
    fn generate() -> KeyPair {
        let mut rng = rand_core::OsRng;
        let private_key = Fr::rand(&mut rng);
        let public_key = G1Projective::generator() * private_key;

        KeyPair {
            private_key,
            public_key,
        }
    }

    /// Produces a Schnorr signature, k = random number, R = k*G, c = H(R, X, msg), s = k + c*x.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let mut rng = rand_core::OsRng;
        let k = Fr::rand(&mut rng);
        let g = G1Projective::generator();
        let r = g * k;

        let challenge = compute_challenge(&r, &self.public_key, message);

        let signature = k + challenge * self.private_key;
        Signature {
            nonce: r,
            response: signature,
        }
    }
}

/// A Schnorr signature (R, s). Also used as the final output of FROST aggregation.
pub struct Signature {
    pub nonce: G1Projective,
    pub response: Fr,
}

impl Signature {
    /// Verifies by checking s*G == R + c*X.
    pub fn verify(&self, public_key: &G1Projective, message: &[u8]) -> bool {
        let g = G1Projective::generator();
        let c = compute_challenge(&self.nonce, public_key, message);

        g * self.response == self.nonce + *public_key * c
    }
}

/// Fiat-Shamir challenge: c = H(R || X || msg) mapped to Fr.
pub fn compute_challenge(r: &G1Projective, public_key: &G1Projective, message: &[u8]) -> Fr {
    let mut hasher = Sha256::new();

    let r_affine = r.into_affine();
    let pk_affine = public_key.into_affine();

    hasher.update(format!("{:?}", r_affine).as_bytes());
    hasher.update(format!("{:?}", pk_affine).as_bytes());
    hasher.update(message);

    let hash_bytes = hasher.finalize();
    Fr::from_le_bytes_mod_order(&hash_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let keypair = KeyPair::generate();
        let signature = keypair.sign(b"hello world");
        assert!(signature.verify(&keypair.public_key, b"hello world"));
    }

    #[test]
    fn test_wrong_message_fails() {
        let keypair = KeyPair::generate();
        let signature = keypair.sign(b"hello world");
        assert!(!signature.verify(&keypair.public_key, b"goodbye world"));
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let signature = keypair1.sign(b"hello world");
        assert!(!signature.verify(&keypair2.public_key, b"hello world"));
    }
}

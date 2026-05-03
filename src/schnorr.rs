use ark_bls12_381::{Fr, G1Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{PrimeField, UniformRand};
use sha2::{Digest, Sha256};

struct KeyPair {
    private_key: Fr,
    public_key: G1Projective,
}

impl KeyPair {
    fn generate() -> KeyPair {
        let mut rng = rand_core::OsRng;
        let private_key = Fr::rand(&mut rng);

        let public_key = G1Projective::generator() * private_key;

        KeyPair {
            private_key,
            public_key,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        //Build up the nonce commitment R, from R = K * G
        let mut rng = rand_core::OsRng;
        let k = Fr::rand(&mut rng);
        let g = G1Projective::generator();
        let r = g * k;

        //compute challenge
        let challenge = compute_challenge(&r, &self.public_key, message);

        //sign, basically nonce + challenge * private_key
        let signature = k + challenge * self.private_key;
        Signature {
            nonce: r,
            response: signature,
        }
    }
}

pub struct Signature {
    nonce: G1Projective,
    response: Fr,
}

impl Signature {
    fn verify(&self, public_key: &G1Projective, message: &[u8]) -> bool {
        //verifying is done by g * s == r + x * c
        let s = self.response;
        let g = G1Projective::generator();
        let r = self.nonce;
        let c = compute_challenge(&r, public_key, message);
        let x = public_key;

        g * s == r + *x * c
    }
}

pub fn compute_challenge(r: &G1Projective, public_key: &G1Projective, message: &[u8]) -> Fr {
    let mut hasher = Sha256::new();

    // ark uses affine form for serialization, so convert point to bytes for hashing
    let r_affine = r.into_affine();
    let pk_affine = public_key.into_affine();

    // Feed everything into the hash
    hasher.update(format!("{:?}", r_affine).as_bytes());
    hasher.update(format!("{:?}", pk_affine).as_bytes());
    hasher.update(message);

    //convert to Fr
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

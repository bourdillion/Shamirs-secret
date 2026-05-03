use ark_bls12_381::{Fr, G1Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{PrimeField, UniformRand};
use rand::RngExt;
use sha2::{Digest, Sha256};

struct KeyPair {
    private_key: Fr,
    public_key: G1Projective,
}

struct Signature {
    nonce: G1Projective,
    response: Fr,
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

    fn compute_challenge(r: &G1Projective, public_key: &G1Projective, message: &[u8]) -> Fr {
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
}

use crate::schnorr::compute_challenge;
use ark_bls12_381::{Fr, G1Projective};
use ark_ec::PrimeGroup;
use ark_ff::UniformRand;

struct SignerNonce {
    index: u64,
    secret_nonce: Fr,
    nonce: G1Projective,
}

impl SignerNonce {
    fn generate(index: u64) -> SignerNonce {
        let mut rng = rand_core::OsRng;
        let secret_nonce = Fr::rand(&mut rng);

        let nonce = G1Projective::generator() * secret_nonce;

        SignerNonce {
            index,
            secret_nonce,
            nonce,
        }
    }
}

struct PartialSignature {
    index: u64,
    response: Fr,
}

impl PartialSignature {
    pub fn sign(
        nonce: &SignerNonce,
        key_share: &Fr,
        all_nonces: &[SignerNonce],
        group_public_key: &G1Projective,
        message: &[u8],
    ) {
        //first get the sum of all public nonces
        let r = all_nonces[0].nonce;
        for nonce in &all_nonces[1..] {
            r + nonce.nonce;
        }

        //next, compute a challenge with the helper function for this nonce sum
        let c = compute_challenge(&r, group_public_key, message);
    }
}

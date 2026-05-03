use crate::schnorr::compute_challenge;
use ark_bls12_381::{Fr, G1Projective};
use ark_ec::PrimeGroup;
use ark_ff::{One, UniformRand, Zero};

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
    ) -> Self {
        // 1. Sum all public nonces into one R
        let mut r = all_nonces[0].nonce;
        for n in &all_nonces[1..] {
            r = r + n.nonce;
        }

        // 2. Compute challenge
        let c = compute_challenge(&r, group_public_key, message);

        // 3. Compute Lagrange coefficient for this signer
        let mut lambda = Fr::from(1u64);
        for other in all_nonces {
            if other.index != nonce.index {
                let num = Fr::from(0u64) - Fr::from(other.index);
                let den = Fr::from(nonce.index) - Fr::from(other.index);
                lambda = lambda * num / den;
            }
        }

        // 4. Compute partial signature: s_i = k_i + c * lambda * key_share
        let s_i = nonce.secret_nonce + c * lambda * key_share;

        PartialSignature {
            index: nonce.index,
            response: s_i,
        }
    }
}

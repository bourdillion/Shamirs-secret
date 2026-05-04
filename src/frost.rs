use crate::{
    error::ShamirError,
    schnorr::{Signature, compute_challenge},
};
use ark_bls12_381::{Fr, G1Projective};
use ark_ec::PrimeGroup;
use ark_ff::UniformRand;

/// A signer's nonce for one round of FROST signing.
pub struct SignerNonce {
    index: u64,
    secret_nonce: Fr,
    /// Public commitment R = k * G, that is broadcast to all signers.
    nonce: G1Projective,
}

impl SignerNonce {
    pub fn generate(index: u64) -> SignerNonce {
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

/// partial signature produced by one FROST signer.
pub struct PartialSignature {
    pub index: u64,
    response: Fr,
}

impl PartialSignature {
    /// Computes a partial FROST signature using the signer's key share.
    pub fn sign(
        nonce: &SignerNonce,
        key_share: &Fr,
        all_nonces: &[SignerNonce],
        group_public_key: &G1Projective,
        message: &[u8],
    ) -> Result<Self, ShamirError> {
        //sanity checks
        if all_nonces.is_empty() {
            return Err(ShamirError::EmptyNonces);
        }

        if !all_nonces.iter().any(|n| n.index == nonce.index) {
            return Err(ShamirError::SignerIndexNotFound);
        }

        for i in 0..all_nonces.len() {
            for j in (i + 1)..all_nonces.len() {
                if all_nonces[i].index == all_nonces[j].index {
                    return Err(ShamirError::DuplicateSignerIndex);
                }
            }
        }

        // Sum all public nonces into one R
        let mut r = all_nonces[0].nonce;
        for n in &all_nonces[1..] {
            r = r + n.nonce;
        }

        //Compute challenge
        let c = compute_challenge(&r, group_public_key, message);

        // Compute Lagrange coefficient for this signer
        let mut lambda = Fr::from(1u64);
        for other in all_nonces {
            if other.index != nonce.index {
                let num = Fr::from(0u64) - Fr::from(other.index);
                let den = Fr::from(nonce.index) - Fr::from(other.index);
                lambda = lambda * num / den;
            }
        }

        // Compute partial signature: s_i = k_i + c * lambda * key_share
        let s_i = nonce.secret_nonce + c * lambda * key_share;

        Ok(PartialSignature {
            index: nonce.index,
            response: s_i,
        })
    }

    /// Combines partial signatures into a final Schnorr signature.
    pub fn aggregate(
        partial_sigs: &[PartialSignature],
        all_nonces: &[SignerNonce],
    ) -> Result<Signature, ShamirError> {
        //sanity checks
        if partial_sigs.is_empty() {
            return Err(ShamirError::EmptyPartialSignatures);
        }

        if all_nonces.is_empty() {
            return Err(ShamirError::EmptyNonces);
        }
        // Sum all public nonces into one R
        let mut r = all_nonces[0].nonce;
        for n in &all_nonces[1..] {
            r = r + n.nonce;
        }

        // Sum all partial responses as well
        let mut s = partial_sigs[0].response;
        for ps in &partial_sigs[1..] {
            s = s + ps.response;
        }

        Ok(Signature {
            nonce: r,
            response: s,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feldman::Commitment;
    use crate::field::BlsScalar;

    #[test]
    fn test_frost_full_flow() {
        let group_private_key = Fr::from(42u64);
        let group_public_key = G1Projective::generator() * group_private_key;

        let secret = BlsScalar {
            value: group_private_key,
        };
        let (shares, _commitment) =
            Commitment::split_with_commitments(secret, 3, 5, G1Projective::generator()).unwrap();

        let nonce1 = SignerNonce::generate(1);
        let nonce2 = SignerNonce::generate(2);
        let nonce3 = SignerNonce::generate(3);
        let all_nonces = vec![nonce1, nonce2, nonce3];

        let message = b"send 1 ETH to Bob";

        //    Share indices match nonce indices: share[0] has x=1, share[1] has x=2, etc.
        let ps1 = PartialSignature::sign(
            &all_nonces[0],
            &shares[0].y.value,
            &all_nonces,
            &group_public_key,
            message,
        )
        .unwrap();
        let ps2 = PartialSignature::sign(
            &all_nonces[1],
            &shares[1].y.value,
            &all_nonces,
            &group_public_key,
            message,
        )
        .unwrap();
        let ps3 = PartialSignature::sign(
            &all_nonces[2],
            &shares[2].y.value,
            &all_nonces,
            &group_public_key,
            message,
        )
        .unwrap();

        let partial_sigs = vec![ps1, ps2, ps3];
        let signature = PartialSignature::aggregate(&partial_sigs, &all_nonces).unwrap();

        assert!(signature.verify(&group_public_key, message));
    }

    #[test]
    fn test_frost_wrong_message_fails() {
        let group_private_key = Fr::from(42u64);
        let group_public_key = G1Projective::generator() * group_private_key;

        let secret = BlsScalar {
            value: group_private_key,
        };
        let (shares, _commitment) =
            Commitment::split_with_commitments(secret, 3, 5, G1Projective::generator()).unwrap();

        let nonce1 = SignerNonce::generate(1);
        let nonce2 = SignerNonce::generate(2);
        let nonce3 = SignerNonce::generate(3);
        let all_nonces = vec![nonce1, nonce2, nonce3];

        let ps1 = PartialSignature::sign(
            &all_nonces[0],
            &shares[0].y.value,
            &all_nonces,
            &group_public_key,
            b"send 1 ETH",
        )
        .unwrap();
        let ps2 = PartialSignature::sign(
            &all_nonces[1],
            &shares[1].y.value,
            &all_nonces,
            &group_public_key,
            b"send 1 ETH",
        )
        .unwrap();
        let ps3 = PartialSignature::sign(
            &all_nonces[2],
            &shares[2].y.value,
            &all_nonces,
            &group_public_key,
            b"send 1 ETH",
        )
        .unwrap();

        let partial_sigs = vec![ps1, ps2, ps3];
        let signature = PartialSignature::aggregate(&partial_sigs, &all_nonces).unwrap();

        // Verify against a DIFFERENT message should fail
        assert!(!signature.verify(&group_public_key, b"send 100 ETH"));
    }

    #[test]
    fn test_frost_different_signers() {
        let group_private_key = Fr::from(99u64);
        let group_public_key = G1Projective::generator() * group_private_key;

        let secret = BlsScalar {
            value: group_private_key,
        };
        let (shares, _commitment) =
            Commitment::split_with_commitments(secret, 3, 5, G1Projective::generator()).unwrap();

        // Use signers 2, 4, 5 instead of 1, 2, 3
        let nonce2 = SignerNonce::generate(2);
        let nonce4 = SignerNonce::generate(4);
        let nonce5 = SignerNonce::generate(5);
        let all_nonces = vec![nonce2, nonce4, nonce5];

        let message = b"approve block 12345";

        let ps2 = PartialSignature::sign(
            &all_nonces[0],
            &shares[1].y.value,
            &all_nonces,
            &group_public_key,
            message,
        )
        .unwrap();
        let ps4 = PartialSignature::sign(
            &all_nonces[1],
            &shares[3].y.value,
            &all_nonces,
            &group_public_key,
            message,
        )
        .unwrap();
        let ps5 = PartialSignature::sign(
            &all_nonces[2],
            &shares[4].y.value,
            &all_nonces,
            &group_public_key,
            message,
        )
        .unwrap();

        let partial_sigs = vec![ps2, ps4, ps5];
        let signature = PartialSignature::aggregate(&partial_sigs, &all_nonces).unwrap();

        assert!(signature.verify(&group_public_key, message));
    }

    #[test]
    fn test_sign_empty_nonces_errors() {
        let nonce = SignerNonce::generate(1);
        let key = Fr::from(42u64);
        let pk = G1Projective::generator() * key;
        let result = PartialSignature::sign(&nonce, &key, &[], &pk, b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_aggregate_empty_sigs_errors() {
        let nonces = vec![SignerNonce::generate(1)];
        let result = PartialSignature::aggregate(&[], &nonces);
        assert!(result.is_err());
    }
}

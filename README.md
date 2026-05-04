# Shamirs Secret
It is a verifiable secret sharing, distributed key generation, and threshold Schnorr signatures (FROST) over BLS12-381, built for blockchain protocols from first principles in Rust.

## who is this library for?
1. Blockchain or Distributed system validators, who need threshold BLS signatures to split a validator key across multiple nodes.
2. Cross chain bridge signers, who need a committee of signers rather than a single multisig.
3. MPC wallet providers who wants to split customer private keys across multiple servers so that a compromise of one server doesn't leak funds.
4. Dao and governances tooling builders who wants a treasury that is controlled by a threshold signature rather than a multisig.
5. L2s rollup sequencer that are moving from single sequencers to committees, this library let them have a single signature posted to L1 rather than an aggregated multisig.
6. Anyone building a tool that a group of parties needs to collectively control a single key without any one party holding it alone.


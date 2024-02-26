<div align="center">
  <a href="https://near.org"><img alt="NEAR Protocol" src="docs/assets/near-logo.svg" width=600></a>
  <h3> <a href="https://near.org">NEAR</a> is a low-cost, usable, and scalable layer-one blockchain that offers cheap data availability layer.</h3>
  <br />
</div>

# NEAR light client

[![Tests](https://github.com/near/near-light-client/actions/workflows/on_pull_request.yml/badge.svg)](https://github.com/near/near-light-client/actions/workflows/on_pull_request.yml)
[![Deploy](https://github.com/near/near-light-client/actions/workflows/on_main.yml/badge.svg)](https://github.com/near/near-light-client/actions/workflows/on_main.yml)

A fully featured, injectable, dependable implementation of the NEAR light client protocol[^1].

## Motivation

There are many light clients in circulation for NEAR, with a variety of protocols and features to varying degrees of security and maintenance.
In this repository, we hope to collaborate our efforts such that we can build a robust client and amalgamate our efforts to improve the light client and also innovate with with it.

This is inspired by the great `helios`[^2] light client, where there were once many light client implementations for Ethereum until it was released. 
This has now become an integral unification of efforts in innovating helios as well as a trustworthy system for people to build with.

Functional requirements:
- **injectable**: For the client to be injectable, it must be ready to be injected in various environments. Building a ZK light client using plonky3? Lambdaworks? Arcworks? Use a different EDDSA library? What about building a contract, where the code paths don't use a library? All of these 
various systems require varying libraries, each of which provides some base cryptography however they are implemented in various dependencies.
Interoperability with dependencies is very hard to maintain and eventually falls by the wayside.
With the light client being injectable, they can inject cryptographic semantics and the light client logic should be the same, with the only difference being what environment the application uses.
- **robust**: With an open source, contributor-friendly effort, stringent semantic versioning and audits, we can be sure that the light client will be robust and maintainable.
- **dependable**: The Protocol itself should not be dependent on many dependencies which would detract from its usability. Ideally, the light client should be `#[no_std]`, and it should be environment-agnostic.
If an environment is simply too difficult to maintain Interoperability with, such as `Solidity <> Rust`, we should try to build a modular set of building blocks to aid this.

## Structure

At present, there are currently two implementations of the light client. The `std` and the `zk` version. With varying approaches to get running with these.

### Off-chain  

This is the first light client that was used to build on the logic of the protocol, it has the greatest environment assumptions and a bunch of dependencies.

In `bin`, there is the off-chain light client, which syncs with the final head of the chain, applies the sync protocol and stores the block producers and the next header. 
This is the most basic way to run the light client, you can configure the `${ENVIRONMENT}.toml` to set your trusted checkpoints, state and the host exposed and this will work out of the box, syncing with the state and catching up if needed.

#### State

It also stores some information in the state db, this contains a few tries in `sled`, namely block producers, headers and any cachable information used for verification.
The state for this is largely unoptimised and definitely can be improved, particularly around the technology selected.

#### Interface

It exposes an HTTP interface for querying state and providing proofs. It should expose a JSON-RPC implementation to be more compatible with users already aware of NEAR RPC nodes.

### ZK

https://alpha.succinct.xyz/near/near-light-client

We have just merged the initial implementation of a ZK light client protocol, this can be seen in `nearx`. It leverages Succinct's[^3] prover network and plonky2x SDK as a proving system.
Thich will allow us to pay for proof generation from the proof market.

It is a fully featured light client protocol, providing sync and transaction verification. It exploits STARK acceleration for the STARK-friendly functionality and parallel proving for the Merkle verification.
We aim to also fold verification and syncing with proof recursion so the light client can act lazily, syncing when needed, vs syncing eagerly. 

#### Circuits

Below are the current circuits for the ZK light client.

The circuits will be improved going forward, as they serve only a "one-shot" command style for syncing/verification and no autonomous proving.

Since the ZK client integrates with a Solidity Contract on chain and the circuit must have a statically aligned size, we have to minimise as much calldata as possible, opting to witness verification in the circuit rather than store information.
One example of this is the `Block Producers`, if we were to store this information unoptimised, we would have to store all hashable fields, growable to their max size `(account_id(64 bytes), public_key(64), stake(16))`, also grown to eth storage slots.
So thats: (64 + 64 + 32(eth storage slots are minimum 32)) = 160 bytes per validator per epoch. At the time of writing, that is 100 validators per epoch, making the resulting bytes just for validators 16000. 

##### Sync

Syncs to the next `head`, either the last header of the next epoch or the next header in the current epoch.

Public inputs:
- `trusted_header_hash`: This is the last header that was synced or the checkpoint header. We use this to query the header info and witness the header is valid, as well as to ensure the header was once synced.

Public Outputs:
- `next_header_hash`: The header hash of the next header that has been synced in the protocol.

Proof generation time:

Improvements:
- Fast forward: The light client should sync arbitrarily many headers at a time. We can gather all the information and then sync in parallel, using boundary checks to ensure the joining of the parallel parts.
- Autonomous sync
- Lazy, aggregate proofs. The operational cost of sync light clients is intensely high. Quite often they do not need to be synced until a transaction needs to be verified. Since proving time is quite fast, we can introduce lazy syncing to the protocol.

In some cases, the light client would need to be synced eagerly. However, at most times the light client should be synced lazily and only when needed to mitigate operational costs.

##### Verify

Verifies a batch of transactions/receipts, this wraps the Merkle proof verification of multiple transactions in a parallelised circuit. 
This allows us to witness the verification of arbitrary amounts of transactions and only pay for verification on Ethereum once, with the relay of the results for the transactions/receipts calldata being the most fees.
We are introducing an additional circuit to allow us to skip the relay of this information.

Public inputs:
- `trusted_header_hash`: The last header that was synced. We can use this to also determine if we need to sync in this verification. And to query the header information.
- `transaction_or_receipt_ids`: The transactions or receipts to be verified.

Public Outputs:
- `transaction_or_receipt_results`: The IDs and the result of their verification 

### Crates

Here we have the building blocks used by the protocol, std binary and the ZK implementation. This is the main building blocks that we use for the implementations. There is a great deal of overlap in their functionality:
- calling rpc nodes
- hashing
- signature verification
- encoding
- the protocol itself

## Metrics

All metrics are currently based on a consumer machine with the following specifications:

- OS: NixOS 24.05.20240205.4b1aab2 (Uakari) x86_64
- CPU: AMD Ryzen 9 7950X (32) @ 4.500GHz 
- RAM: 32GB @ 4800MHz DDR5

Circuits:
- Sync: ~38seconds
- Verify_2x1: ~25s
- Verify_128x4: ~12mins, linearly with batch size. No parallelisation. Roughly 22 seconds per batch.

To run the tests yourself:
- `cargo nextest archive -r -p near-light-clientx --archive-file=nextest-archive.tar.zst --locked`
- `RUST_LOG=debug cargo nextest run --no-capture --run-ignored ignored-only --archive-file nextest-archive.tar.zst -- sync_e2e verify_e2e_2x1 verify_e2e_128x4`


[^1]: NEAR light client specification: [Near light client](https://nomicon.io/ChainSpec/LightClient)
[^2]: Helios, ethereum light client: https://github.com/a16z/helios
[^3]: Succinct's [plonky2 SDK](https://github.com/succinctlabs/succinctx) and [prover network](https://alpha.succinct.xyz/). 

## Contributions

After laying out some of the functional requirements and some overall understanding, we'd love to invite many light client maintainers to contribute to the project. 
If you have any questions, feel free to raise an issue. We are also working on ironing out the process so that it is as smooth as possible with appropriate guidelines.


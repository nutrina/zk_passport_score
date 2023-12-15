# zk_passport_score
Compute a score for a Gitcoin Passport in a ZK fashion

# Links
- https://noir-lang.org/
  - verifying secp256k1 signature: https://noir-lang.org/dev/standard_library/cryptographic_primitives/ecdsa_sig_verification/
- https://github.com/sambarnes/noir-by-example
- https://github.com/noir-lang/awesome-noir

# Calculating Score in Noir

Public inputs:
- an array of stamp hashes

Private inputs (the VC):
- array of VCs
    - given that validating the VCs in noir is difficult, we can instead pass in:
        - array of dids (did coresponding to each stamp)
        - array of providers
        - signature (secp256k1) computed by the issuer to prove validity of the tuple (did, provider, hash)
- signature (secp256k1) to prove ownership of the DIDs
    - not required in first iteration of POC


Circuit configuration / setup:
- provider weights

Verify that the user qualifies

**Step 1**
- validate all the dids
  - we need a proof that the user owns this did, hence a signature created with the eTH address of the did is required
  - but we should also use some sort of nonce

**Step 2**
- iterate over the list of providers
  - start with weights & providers (the weights for providers can be hardcoded / or consider weight 1 by default for every provider)  
- validate the VC (or the secp256k1 for the tuple (did, provider, hash) )
  - check that this signature was created by the issuer (IAM)
- sum up weights
- allow each provider only once


# TODO
- [ ] create first iteration of circuit (basic, not all verification needed in circuit)
- [ ] create UI for proof generation
- [ ] create UI for proof verification generation
- [ ] implement end-to-end flow
- [ ] implement validations in circuit
- [ ] implement nullfier / deduplication



# Other
See also: https://github.com/jonas089/zk-proofs-noir-ecdsa/blob/master/signature_circuit/src/main.nr

Check signature in Noir:
```rust
use dep::std;

fn main(message_hash: [u8;32], pub_key_x: [u8;32], pub_key_y: [u8;32], signature: [u8;64]) {
    // hash the message again (this happens when we generate a deterministic signature)
    // the reason we do this is to ensure persistent input message length (always 32 bytes)
    // let message_hash_2 = std::hash::sha256(message_hash);

    let valid_signature = std::ecdsa_secp256k1::verify_signature(pub_key_x, pub_key_y, signature, message_hash);
    assert(valid_signature);
}

#[test]
fn test_main() {
    main(
        [
        226, 117, 76, 93, 5, 148, 130, 91, 187, 174, 247, 117, 241, 124, 25, 180, 71, 215, 93, 108, 236, 254, 196, 205, 65, 179, 64, 34, 241, 171, 199, 5
    ],
        [
        123, 131, 173, 106, 251, 18, 9, 243, 200, 46, 190, 176, 140, 12, 95, 169, 191, 103, 36, 84, 133, 6, 242, 251, 79, 153, 30, 34, 135, 167, 112, 144
    ],
        [
        23, 115, 22, 202, 130, 176, 189, 247, 12, 217, 222, 225, 69, 195, 0, 44, 13, 161, 217, 38, 38, 68, 152, 117, 151, 42, 39, 128, 123, 115, 180, 46
    ],
        [
        84, 45, 76, 125, 117, 220, 113, 219, 166, 127, 32, 244, 88, 146, 37, 148, 132, 128, 246, 167, 50, 85, 125, 104, 76, 94, 228, 190, 49, 237, 106, 46, 51, 60, 5, 108, 229, 245, 167, 3, 56, 59, 216, 13, 205, 101, 64, 104, 176, 196, 71, 76, 15, 83, 248, 206, 114, 242, 51, 207, 31, 52, 82, 88
    ]
    );
}

```
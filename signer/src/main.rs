use anyhow::Result;
use ecdsa::{
    signature::{self, rand_core::OsRng, Signer, Verifier},
    EncodedPoint, Signature, SigningKey, VerifyingKey,
};
use k256::{
    ecdsa::{signature::Signer as DigestSigner, Signature as EcdsaSignature},
    Secp256k1,
};
use sha2::{Digest, Sha256};

fn hash_message_partition(part: &[u8]) -> Vec<u8> {
    // Hash the data using SHA-256 to get a 32-byte hash
    let mut hasher = Sha256::new();
    hasher.update(part);
    let message_hash = hasher.finalize();

    // Ensure the hash is 32 bytes
    assert_eq!(message_hash.len(), 32, "Hashed data is not 32 bytes");

    message_hash.to_vec()
}

fn hash_and_sign_message(
    hash: &[u8],
    provider: &[u8],
    signing_key: &SigningKey<Secp256k1>,
    verify_key: &VerifyingKey<Secp256k1>,
    index: u8,
) {
    // Concatenate the hash and provider
    let message = [hash, provider].concat();

    // Hash the data using SHA-256 to get a 32-byte hash
    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_hash = hasher.finalize();

    // Ensure the hash is 32 bytes
    assert_eq!(message_hash.len(), 32, "Hashed data is not 32 bytes");

    // Sign the data directly (without manually hashing it)
    // Explicitly specifying the type of the signature
    let signed_msg: EcdsaSignature = signing_key.sign(&message_hash);

    // Serialize the signature into a byte array
    let signature = signed_msg.to_vec();

    // Verify the signature
    let is_valid = verify_key.verify(&message_hash, &signed_msg);

    match is_valid {
        Ok(_) => println!("Signature is valid!"),
        Err(e) => {
            dbg!(e);
        }
    }

    // Convert the verifying key to an EncodedPoint
    let encoded_point: EncodedPoint<Secp256k1> = verify_key.to_encoded_point(false); // false for uncompressed

    // Convert to uncompressed format as a byte array
    let uncompressed_bytes = encoded_point.as_bytes();

    let pub_key_x = &uncompressed_bytes[1..33];
    let pub_key_y = &uncompressed_bytes[33..65];

    println!("let pub_key_x = {:?};", pub_key_x);
    println!("let pub_key_y = {:?};", pub_key_y);
    println!("let signature_{} = {:?};", index, signature);
    println!("let message_hash_{} = {:?};", index, message_hash);
    println!(
        "let stamp_hash_bytes{} = {:?};",
        index,
        hash_message_partition(hash)
    );
}

fn main() -> Result<()> {
    // Generate a new ECDSA key pair
    let signing_key = SigningKey::random(&mut OsRng);

    // Obtain the verifying key (public key)
    let verify_key: VerifyingKey<Secp256k1> = VerifyingKey::from(&signing_key);

    // Data to be signed
    let hash = b"GqmK8ClmCF6E9DaQYe3ei3KGlwyJOWDPNthLX4NRftQ";
    let provider = b"google";

    hash_and_sign_message(hash, provider, &signing_key, &verify_key, 0);

    // Data to be signed
    let hash_1 = b"5NMZWaxFcB3PW1OPOeKvX61UOpeggdxcM8N77TVX5qc=";
    let provider_1 = b"facebook";

    hash_and_sign_message(hash_1, provider_1, &signing_key, &verify_key, 1);

    Ok(())
}

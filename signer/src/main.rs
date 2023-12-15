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

fn hash_and_sign_message(
    message: &[u8],
    signing_key: &SigningKey<Secp256k1>,
    verify_key: &VerifyingKey<Secp256k1>,
) {
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
    let signature_bytes = signed_msg.to_vec();
    println!("Signature: {:?}", signature_bytes);

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

    let x_key_coordinates = &uncompressed_bytes[1..33];
    let y_key_coordinates = &uncompressed_bytes[33..65];

    dbg!(
        x_key_coordinates,
        y_key_coordinates,
        signature_bytes,
        message_hash
    );
}

fn main() -> Result<()> {
    // Generate a new ECDSA key pair
    let signing_key = SigningKey::random(&mut OsRng);

    // Obtain the verifying key (public key)
    let verify_key: VerifyingKey<Secp256k1> = VerifyingKey::from(&signing_key);

    // Data to be signed
    let message = b"GqmK8ClmCF6E9DaQYe3ei3KGlwyJOWDPNthLX4NRftQ=googlegooglegooglegooglegoogle";

    hash_and_sign_message(message, &signing_key, &verify_key);

    Ok(())
}

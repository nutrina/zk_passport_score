use anyhow::Result;
use base64::{decode as decode_base64, encode as encode_base64};
use ecdsa::{
    signature::{self, rand_core::OsRng, Signer, Verifier},
    EncodedPoint, Signature, SigningKey, VerifyingKey,
};
use hex::decode;
use k256::{
    ecdsa::{signature::Signer as DigestSigner, Signature as EcdsaSignature},
    Secp256k1,
};
use sha2::{Digest, Sha256};

fn decode_stamp_hash(hash: &str) -> Result<(Vec<u8>)> {
    // 'GqmK8ClmCF6E9DaQYe3ei3KGlwyJOWDPNthLX4NRftQ='
    let bytes = decode_base64(hash)?;

    println!("Decoded bytes: {:?}", bytes.len());

    Ok(bytes)
}

fn hash_and_sign_message(
    stamp_hash: Vec<u8>,
    provider: Vec<u8>,
    signing_key: &SigningKey<Secp256k1>,
    verify_key: &VerifyingKey<Secp256k1>,
    index: u8,
) {
    // Concatenate the hash and provider
    let message = [stamp_hash.clone(), provider.clone()].concat();
    // dbg!(message.clone());

    // Hash the data using SHA-256 to get a 32-byte hash
    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_hash = hasher.finalize();

    dbg!(message_hash.clone());

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
    println!("let stamp_hash_bytes_{} = {:?};", index, stamp_hash);
    println!("let provider_{} = {:?};", index, provider);
}

fn main() -> Result<()> {
    // Generate a new ECDSA key pair
    let signing_key = SigningKey::random(&mut OsRng);

    // Obtain the verifying key (public key)
    let verify_key: VerifyingKey<Secp256k1> = VerifyingKey::from(&signing_key);

    let facebook_provider =
        decode("6f028453ddea055c2bfd6baeffa906ae6954e0bb90083e4b76c86058e9e2c08a")?;

    // Data to be signed
    let decoded_hash_0 = decode_stamp_hash("GqmK8ClmCF6E9DaQYe3ei3KGlwyJOWDPNthLX4NRftQ=")?;

    hash_and_sign_message(
        decoded_hash_0,
        facebook_provider,
        &signing_key,
        &verify_key,
        0,
    );

    // Data to be signed
    // let google_provider: Vec<u8> =
    // decode("f610f88085f5955bccb50431e1315a28335522d87be5000ff334274cc9985741")?;
    // let hash_1 = b"5NMZWaxFcB3PW1OPOeKvX61UOpeggdxcM8N77TVX5qc=";
    // let decoded_hash_1 = decode_stamp_hash("5NMZWaxFcB3PW1OPOeKvX61UOpeggdxcM8N77TVX5qc=")?;

    // hash_and_sign_message(
    //     decoded_hash_1,
    //     google_provider,
    //     &signing_key,
    //     &verify_key,
    //     1,
    // );

    Ok(())
}

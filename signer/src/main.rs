use anyhow::Result;
use ecdsa::{
    signature::{self, rand_core::OsRng, Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use k256::ecdsa::{signature::Signer as DigestSigner, Signature as EcdsaSignature};
use sha2::Sha256;

fn main() -> Result<()> {
    // Generate a new ECDSA key pair
    let signing_key = SigningKey::random(&mut OsRng);

    // Obtain the verifying key (public key)
    let verify_key = VerifyingKey::from(&signing_key);

    // Data to be signed
    let data = b"Example data to sign";

    // Sign the data directly (without manually hashing it)
    // Explicitly specifying the type of the signature
    let signed_msg: EcdsaSignature = signing_key.sign(data);

    // Serialize the signature into a byte array
    let signature_bytes = signed_msg.to_vec();
    println!("Signature: {:?}", signature_bytes);

    // Verify the signature
    let is_valid = verify_key.verify(data, &signed_msg);

    match is_valid {
        Ok(_) => println!("Signature is valid!"),
        Err(e) => {
            dbg!(e);
        }
    }

    Ok(())
}

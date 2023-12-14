use dep::std;
use dep::std::println;
use dep::ecrecover;


fn verify_signature(message_hash : [u8;32], pub_key_x : [u8;32], pub_key_y : [u8;32], signature : [u8;64]) {
    // hash the message again (this happens when we generate a deterministic signature)
    // the reason we do this is to ensure persistent input message length (always 32 bytes)
    let message_hash_2 = std::hash::sha256(message_hash);

    let valid_signature = std::ecdsa_secp256k1::verify_signature(pub_key_x, pub_key_y, signature, message_hash_2);
    assert(valid_signature);
}

#[test]
fn test_verify_signature() {
    let message_hash = [245, 223, 58, 50, 74, 76, 120, 255, 154, 66, 228, 77, 1, 67, 64, 61, 149, 67, 119, 15, 48, 228, 152, 123, 172, 4, 232, 97, 108, 104, 20, 218];
    let signature = [166, 5, 102, 196, 4, 203, 205, 221, 56, 19, 228, 3, 222, 136, 61, 36, 112, 92, 79, 87, 206, 201, 77, 255, 128, 33, 243, 19, 6, 203, 117, 68, 64, 145, 153, 152, 123, 48, 10, 242, 213, 114, 82, 234, 207, 147, 47, 163, 107, 163, 86, 100, 139, 143, 24, 187, 239, 255, 38, 96, 57, 176, 217, 97];
    let pub_key_x = [65, 34, 212, 75, 36, 198, 55, 190, 216, 124, 123, 16, 155, 212, 157, 97, 134, 53, 129, 94, 77, 244, 77, 51, 6, 129, 50, 68, 74, 235, 37, 210];
    let pub_key_y = [211, 232, 46, 182, 4, 74, 247, 123, 164, 157, 138, 102, 69, 90, 221, 123, 163, 149, 197, 48, 99, 43, 123, 165, 161, 23, 43, 120, 28, 250, 107, 209];
    verify_signature(message_hash, pub_key_x, pub_key_y, signature);
}


fn verify_stamp(stamp_hash: pub [u8;17], provider: [u8;8], trusted_signer: Field, message_hash : [u8;32], pub_key_x : [u8;32], pub_key_y : [u8;32], signature : [u8;64]) {
    // https://github.com/colinnielsen/ecrecover-noir/tree/main
    let message_hash_2 = std::hash::sha256(message_hash);

    let recovered_signer = ecrecover::ecrecover(pub_key_x, pub_key_y, signature, message_hash_2);

    // Recreate the signed message's bytes from the public stamp_hash and private provider
    let mut combined_message_bytes = [0; 26];
    let seperator_byte = 58 as u8;
    for i in 0..26 {
        if i == 17 as u8 {
            combined_message_bytes[i] = seperator_byte;
        } else {
            if i <= 16 as u8 {
                combined_message_bytes[i] = stamp_hash[i];
            } else {
                combined_message_bytes[i] = provider[i - 18];
            }
        } 
    }

    assert(recovered_signer == trusted_signer);

    let hashed_combined_msg = std::hash::sha256(combined_message_bytes);

    assert(hashed_combined_msg == message_hash); 
}

#[test]
fn test_verify_stamp() {
    let message_hash = [31, 80, 240, 80, 20, 19, 64, 21, 205, 124, 17, 222, 20, 119, 218, 142, 17, 251, 40, 26, 251, 49, 161, 136, 252, 7, 59, 85, 216, 241, 37, 11];
    let signature = [35, 205, 11, 92, 164, 90, 212, 79, 124, 187, 3, 50, 242, 117, 243, 48, 192, 179, 40, 133, 90, 236, 154, 31, 168, 54, 67, 113, 220, 148, 42, 72, 63, 65, 187, 188, 167, 203, 236, 13, 42, 192, 151, 44, 66, 4, 170, 142, 70, 112, 178, 120, 31, 104, 33, 251, 26, 194, 142, 43, 138, 30, 124, 134];
    let pub_key_x = [65, 34, 212, 75, 36, 198, 55, 190, 216, 124, 123, 16, 155, 212, 157, 97, 134, 53, 129, 94, 77, 244, 77, 51, 6, 129, 50, 68, 74, 235, 37, 210];
    let pub_key_y = [211, 232, 46, 182, 4, 74, 247, 123, 164, 157, 138, 102, 69, 90, 221, 123, 163, 149, 197, 48, 99, 43, 123, 165, 161, 23, 43, 120, 28, 250, 107, 209];
    let stamp_hash_bytes = [118, 48, 46, 48, 46, 48, 58, 115, 97, 109, 112, 108, 101, 104, 97, 115, 104];
    let provider_bytes = [102, 97, 99, 101, 98, 111, 111, 107];
    verify_stamp(stamp_hash_bytes, provider_bytes, 0xc7f222aadac8eef0039f5a8f01b9188e7a715a81, message_hash, pub_key_x, pub_key_y, signature);
}


fn main(stamp_hashs: pub [[u8;17]; 2], providers: [[u8;8]; 2], message_hashes : [[u8;32]; 2], signatures : [[u8;64]; 2], pub_key_x : [u8;32], pub_key_y : [u8;32], trusted_signer: Field,) {
    println("Hello, world!");
    for i in 0..2 {
        verify_stamp(stamp_hashs[i], providers[i], trusted_signer, message_hashes[i], pub_key_x, pub_key_y, signatures[i]);
    }
}


#[test]
fn test_main() {
    let message_hash = [31, 80, 240, 80, 20, 19, 64, 21, 205, 124, 17, 222, 20, 119, 218, 142, 17, 251, 40, 26, 251, 49, 161, 136, 252, 7, 59, 85, 216, 241, 37, 11];
    let signature = [35, 205, 11, 92, 164, 90, 212, 79, 124, 187, 3, 50, 242, 117, 243, 48, 192, 179, 40, 133, 90, 236, 154, 31, 168, 54, 67, 113, 220, 148, 42, 72, 63, 65, 187, 188, 167, 203, 236, 13, 42, 192, 151, 44, 66, 4, 170, 142, 70, 112, 178, 120, 31, 104, 33, 251, 26, 194, 142, 43, 138, 30, 124, 134];
    let pub_key_x = [65, 34, 212, 75, 36, 198, 55, 190, 216, 124, 123, 16, 155, 212, 157, 97, 134, 53, 129, 94, 77, 244, 77, 51, 6, 129, 50, 68, 74, 235, 37, 210];
    let pub_key_y = [211, 232, 46, 182, 4, 74, 247, 123, 164, 157, 138, 102, 69, 90, 221, 123, 163, 149, 197, 48, 99, 43, 123, 165, 161, 23, 43, 120, 28, 250, 107, 209];
    let stamp_hash_bytes = [118, 48, 46, 48, 46, 48, 58, 115, 97, 109, 112, 108, 101, 104, 97, 115, 104];
    let provider_bytes = [102, 97, 99, 101, 98, 111, 111, 107];


    
    main([stamp_hash_bytes, stamp_hash_bytes], [provider_bytes, provider_bytes], [message_hash, message_hash], [signature, signature], pub_key_x, pub_key_y, 0xc7f222aadac8eef0039f5a8f01b9188e7a715a81);
}

#[test]
fn test_main1() {
    // let message_hash = [31, 80, 240, 80, 20, 19, 64, 21, 205, 124, 17, 222, 20, 119, 218, 142, 17, 251, 40, 26, 251, 49, 161, 136, 252, 7, 59, 85, 216, 241, 37, 11];
    // let signature = [35, 205, 11, 92, 164, 90, 212, 79, 124, 187, 3, 50, 242, 117, 243, 48, 192, 179, 40, 133, 90, 236, 154, 31, 168, 54, 67, 113, 220, 148, 42, 72, 63, 65, 187, 188, 167, 203, 236, 13, 42, 192, 151, 44, 66, 4, 170, 142, 70, 112, 178, 120, 31, 104, 33, 251, 26, 194, 142, 43, 138, 30, 124, 134];
    
    // let stamp_hash_bytes = [118, 48, 46, 48, 46, 48, 58, 115, 97, 109, 112, 108, 101, 104, 97, 115, 104];
    // let provider_bytes = [102, 97, 99, 101, 98, 111, 111, 107];

    let stamp_hash_bytes_google = [118, 48, 46, 48, 46, 49, 58, 115, 97, 109, 112, 108, 101, 104, 97, 115, 104];
    let provider_bytes_google = [97, 97, 103, 111, 111, 103, 108, 101];
    let message_hash_google = [150, 169, 28, 211, 210, 227, 220, 97, 108, 48, 245, 79, 172, 237, 86, 45, 253, 5, 172, 227, 204, 197, 66, 105, 118, 148, 197, 115, 160, 48, 127, 220];
    let signature_google = [197, 13, 139, 99, 144, 60, 140, 168, 177, 166, 107, 99, 240, 149, 90, 191, 51, 60, 31, 205, 86, 168, 90, 77, 11, 41, 59, 167, 50, 180, 196, 163, 70, 103, 148, 96, 127, 109, 244, 75, 28, 124, 107, 129, 203, 55, 85, 249, 236, 65, 237, 240, 26, 54, 114, 188, 246, 181, 22, 241, 250, 181, 161, 230];
    let pub_key_x_google = [65, 34, 212, 75, 36, 198, 55, 190, 216, 124, 123, 16, 155, 212, 157, 97, 134, 53, 129, 94, 77, 244, 77, 51, 6, 129, 50, 68, 74, 235, 37, 210];
    let pub_key_y_google = [211, 232, 46, 182, 4, 74, 247, 123, 164, 157, 138, 102, 69, 90, 221, 123, 163, 149, 197, 48, 99, 43, 123, 165, 161, 23, 43, 120, 28, 250, 107, 209];
    let stamp_hash_bytes_facebook = [118, 48, 46, 48, 46, 48, 58, 115, 97, 109, 112, 108, 101, 104, 97, 115, 104];
    let provider_bytes_facebook = [102, 97, 99, 101, 98, 111, 111, 107];
    let message_hash_facebook = [31, 80, 240, 80, 20, 19, 64, 21, 205, 124, 17, 222, 20, 119, 218, 142, 17, 251, 40, 26, 251, 49, 161, 136, 252, 7, 59, 85, 216, 241, 37, 11];
    let signature_facebook = [35, 205, 11, 92, 164, 90, 212, 79, 124, 187, 3, 50, 242, 117, 243, 48, 192, 179, 40, 133, 90, 236, 154, 31, 168, 54, 67, 113, 220, 148, 42, 72, 63, 65, 187, 188, 167, 203, 236, 13, 42, 192, 151, 44, 66, 4, 170, 142, 70, 112, 178, 120, 31, 104, 33, 251, 26, 194, 142, 43, 138, 30, 124, 134];
    let pub_key_x = [65, 34, 212, 75, 36, 198, 55, 190, 216, 124, 123, 16, 155, 212, 157, 97, 134, 53, 129, 94, 77, 244, 77, 51, 6, 129, 50, 68, 74, 235, 37, 210];
    let pub_key_y = [211, 232, 46, 182, 4, 74, 247, 123, 164, 157, 138, 102, 69, 90, 221, 123, 163, 149, 197, 48, 99, 43, 123, 165, 161, 23, 43, 120, 28, 250, 107, 209];


    main([stamp_hash_bytes_facebook, stamp_hash_bytes_google], [provider_bytes_facebook, provider_bytes_google], [message_hash_facebook, message_hash_google], [signature_facebook, signature_google], pub_key_x, pub_key_y, 0xc7f222aadac8eef0039f5a8f01b9188e7a715a81);
}











// fn verify_hashed_stamp(message_hash: pub Field, message_and_key_hash: Field, private_key: ) {
    
// }



// #[test]
// fn test_verify_stamp() {
//     let message_bytes = [
//      71, 111, 111, 103, 108, 101,  58, 118,  48,  46,  48,  46,
//      48,  58,  71, 113, 109,  75,  56,  67, 108, 109,  67,  70,
//      54,  69,  57,  68,  97,  81,  89, 101,  51, 101, 105,  51,
//      75,  71, 108, 119, 121,  74,  79,  87,  68,  80,  78, 116,
//     104,  76,  88,  52,  78,  82, 102, 116,  81,  61,  58, 115,
//     101,  99, 114, 101, 116
//   ];

//   let message_and_key_bytes = [71,111,111,103,108,101,58,118,48,46,48,46,48,58,71,113,109,75,56,67,108,109,67,70,54,69,57,68,97,81,89,101,51,101,105,51,75,71,108,119,121,74,79,87,68,80,78,116,104,76,88,52,78,82,102,116,81,61,58,115,101,99,114,101,116,48,120,97,99,48,57,55,52,98,101,99,51,57,97,49,55,101,51,54,98,97,52,97,54,98,52,100,50,51,56,102,102,57,52,52,98,97,99,98,52,55,56,99,98,101,100,53,101,102,99,97,101,55,56,52,100,55,98,102,52,102,50,102,102,56,48];

//   let message_hash = std::hash::pedersen_hash(messageBytes);

//   let message_and_key_hash = std::hash::pedersen_hash(message_and_key_bytes);



// //   let message


//   verify_hashed_stamp(message_hash, message_and_key_hash, private_key);
// }


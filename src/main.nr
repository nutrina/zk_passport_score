use dep::std;
use dep::std::println;
use dep::ecrecover;

fn verify_signature(message_hash: [u8; 32], pub_key_x: [u8; 32], pub_key_y: [u8; 32], signature: [u8; 64]) {
    // hash the message again (this happens when we generate a deterministic signature)
    // the reason we do this is to ensure persistent input message length (always 32 bytes)
    let message_hash_2 = std::hash::sha256(message_hash);

    let valid_signature = std::ecdsa_secp256k1::verify_signature(pub_key_x, pub_key_y, signature, message_hash_2);
    assert(valid_signature);
}

#[test]
fn test_verify_signature() {
    let pub_key_x = [
        71, 213, 130, 192, 205, 208, 183, 223, 212, 101, 180, 134, 201, 179, 114, 25, 82, 118, 127, 131, 160, 207, 64, 53, 80, 95, 192, 164, 112, 16, 132, 12
    ];
    let pub_key_y = [
        4, 254, 246, 107, 127, 155, 47, 97, 200, 155, 125, 100, 88, 95, 25, 30, 193, 107, 3, 77, 164, 9, 20, 169, 40, 186, 228, 0, 106, 77, 117, 86
    ];
    let signature_0 = [
        138, 255, 123, 139, 57, 142, 136, 242, 92, 198, 197, 244, 175, 103, 195, 93, 109, 41, 119, 25, 11, 252, 59, 18, 212, 207, 43, 232, 120, 197, 94, 134, 22, 183, 18, 102, 165, 225, 112, 207, 208, 125, 34, 193, 147, 93, 223, 15, 13, 200, 45, 118, 54, 4, 13, 227, 208, 32, 172, 162, 5, 200, 221, 100
    ];
    let message_hash_0 = [
        163, 182, 42, 173, 255, 236, 215, 236, 172, 125, 65, 112, 111, 175, 29, 65, 73, 14, 117, 61, 230, 176, 58, 250, 91, 20, 180, 116, 122, 215, 132, 84
    ];
    verify_signature(message_hash_0, pub_key_x, pub_key_y, signature_0);
}

fn verify_stamp(
    stamp_hash: pub [u8; 32],
    provider: [u8; 32],
    trusted_signer: Field,
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64]
) {
    // Recreate the signed message's bytes from the public stamp_hash and private provider
    let mut combined_message_bytes = [0; 64];
    for i in 0..64 {
        if i <= 31 as u8 {
            combined_message_bytes[i] = stamp_hash[i];
        } else {
            combined_message_bytes[i] = provider[i - 32];
        }
    }

    // let hashed_combined_msg = std::hash::sha256(combined_message_bytes);

    // https://github.com/colinnielsen/ecrecover-noir/tree/main
    let message_hash_2 = std::hash::sha256(combined_message_bytes);
    println("message_hash_2: ");
    println(message_hash_2);
    println("combined_message_bytes: ");
    println(combined_message_bytes);

    let recovered_signer = ecrecover::ecrecover(pub_key_x, pub_key_y, signature, message_hash_2);

    assert(recovered_signer == trusted_signer);
}

// #[test]
// fn test_verify_stamp() {
//     // let message_hash = [
//     //     31, 80, 240, 80, 20, 19, 64, 21, 205, 124, 17, 222, 20, 119, 218, 142, 17, 251, 40, 26, 251, 49, 161, 136, 252, 7, 59, 85, 216, 241, 37, 11
//     // ];
//     let signature = [
//         35, 205, 11, 92, 164, 90, 212, 79, 124, 187, 3, 50, 242, 117, 243, 48, 192, 179, 40, 133, 90, 236, 154, 31, 168, 54, 67, 113, 220, 148, 42, 72, 63, 65, 187, 188, 167, 203, 236, 13, 42, 192, 151, 44, 66, 4, 170, 142, 70, 112, 178, 120, 31, 104, 33, 251, 26, 194, 142, 43, 138, 30, 124, 134
//     ];
//     let pub_key_x = [
//         65, 34, 212, 75, 36, 198, 55, 190, 216, 124, 123, 16, 155, 212, 157, 97, 134, 53, 129, 94, 77, 244, 77, 51, 6, 129, 50, 68, 74, 235, 37, 210
//     ];
//     let pub_key_y = [
//         211, 232, 46, 182, 4, 74, 247, 123, 164, 157, 138, 102, 69, 90, 221, 123, 163, 149, 197, 48, 99, 43, 123, 165, 161, 23, 43, 120, 28, 250, 107, 209
//     ];
//     let stamp_hash_bytes = [118, 48, 46, 48, 46, 48, 58, 115, 97, 109, 112, 108, 101, 104, 97, 115, 104];
//     let provider_bytes = [102, 97, 99, 101, 98, 111, 111, 107];
//     verify_stamp(
//         stamp_hash_bytes,
//         provider_bytes,
//         0xc7f222aadac8eef0039f5a8f01b9188e7a715a81,
//         pub_key_x,
//         pub_key_y,
//         signature
//     );
// }

fn main(
    stamp_hashs: pub [[u8; 32]; 2],
    providers: [[u8; 32]; 2],
    signatures: [[u8; 64]; 2],
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    trusted_signer: Field
) {
    // Configure the list of supported providers (provider names are byte arrays) - Possibly replace with oed
    // The list is split in 2 parts, the first list will contain the first 128 bits of a hash the second one the rest
    // And the list is expected to be sorted by the numeric value of the hash. Inputs are expected to be passed in in the same order.

    // Order: Facebook, Google

    let valid_providers1:[[u8;32]; 2] = [
        [
            111, 2, 132, 83, 221, 234, 5, 92, 43, 253, 107, 174, 255, 169, 6, 174, 105, 84, 224, 187, 144, 8, 62, 75, 118, 200, 96, 88, 233, 226, 192, 138
        ], [
            246, 16, 248, 128, 133, 245, 149, 91, 204, 181, 4, 49, 225, 49, 90, 40, 51, 85, 34, 216, 123, 229, 0, 15, 243, 52, 39, 76, 201, 152, 87, 65
        ]
    ];
    // The list of weights fr each supported provider
    let weights:[u32; 2] = [10, 20];
    let mut score = 0;

    for i in 1..2 {
        verify_stamp(
            stamp_hashs[i],
            providers[i],
            trusted_signer,
            pub_key_x,
            pub_key_y,
            signatures[i]
        );

        assert(providers[i] == valid_providers1[i]);

        // Not the best check, but it should safe enough since we sign the message/hash off chain/circuit?
        assert(
            stamp_hashs[i] != [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        // If conditions are all met increment points
        score += weights[i];
    }

    println("score: ");
    println(score);

    assert(score >= 20);
}

// #[test(should_fail)]
// fn test_main() {
//     let signature = [
//         35, 205, 11, 92, 164, 90, 212, 79, 124, 187, 3, 50, 242, 117, 243, 48, 192, 179, 40, 133, 90, 236, 154, 31, 168, 54, 67, 113, 220, 148, 42, 72, 63, 65, 187, 188, 167, 203, 236, 13, 42, 192, 151, 44, 66, 4, 170, 142, 70, 112, 178, 120, 31, 104, 33, 251, 26, 194, 142, 43, 138, 30, 124, 134
//     ];
//     let pub_key_x = [
//         65, 34, 212, 75, 36, 198, 55, 190, 216, 124, 123, 16, 155, 212, 157, 97, 134, 53, 129, 94, 77, 244, 77, 51, 6, 129, 50, 68, 74, 235, 37, 210
//     ];
//     let pub_key_y = [
//         211, 232, 46, 182, 4, 74, 247, 123, 164, 157, 138, 102, 69, 90, 221, 123, 163, 149, 197, 48, 99, 43, 123, 165, 161, 23, 43, 120, 28, 250, 107, 209
//     ];
//     let stamp_hash_bytes = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
//     let provider_bytes = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];

//     main(
//         [stamp_hash_bytes, stamp_hash_bytes],
//         [provider_bytes, provider_bytes],
//         [signature, signature],
//         pub_key_x,
//         pub_key_y,
//         0xc7f222aadac8eef0039f5a8f01b9188e7a715a81
//     );
// }

#[test]
fn test_main1_multiple_stamps() {
    // let message_hash = [31, 80, 240, 80, 20, 19, 64, 21, 205, 124, 17, 222, 20, 119, 218, 142, 17, 251, 40, 26, 251, 49, 161, 136, 252, 7, 59, 85, 216, 241, 37, 11];
    // let signature = [35, 205, 11, 92, 164, 90, 212, 79, 124, 187, 3, 50, 242, 117, 243, 48, 192, 179, 40, 133, 90, 236, 154, 31, 168, 54, 67, 113, 220, 148, 42, 72, 63, 65, 187, 188, 167, 203, 236, 13, 42, 192, 151, 44, 66, 4, 170, 142, 70, 112, 178, 120, 31, 104, 33, 251, 26, 194, 142, 43, 138, 30, 124, 134];

    // let stamp_hash_bytes = [118, 48, 46, 48, 46, 48, 58, 115, 97, 109, 112, 108, 101, 104, 97, 115, 104];
    // let provider_bytes = [102, 97, 99, 101, 98, 111, 111, 107];

    let signature_facebook = [
        120, 5, 36, 184, 59, 26, 111, 218, 6, 197, 197, 60, 17, 127, 144, 236, 182, 8, 18, 137, 94, 48, 141, 114, 31, 70, 225, 12, 151, 177, 227, 61, 205, 207, 216, 93, 87, 190, 153, 215, 91, 13, 69, 196, 221, 49, 73, 243, 62, 117, 150, 45, 114, 13, 214, 115, 226, 186, 226, 4, 38, 32, 218, 42
    ];
    let signature_google = [
        144, 236, 131, 111, 201, 68, 117, 205, 211, 176, 241, 198, 105, 115, 64, 221, 42, 99, 14, 47, 227, 164, 111, 124, 61, 31, 255, 234, 204, 134, 251, 84, 129, 129, 74, 40, 20, 149, 28, 78, 185, 199, 94, 154, 200, 119, 237, 136, 156, 70, 143, 17, 5, 189, 237, 247, 137, 104, 161, 16, 118, 167, 158, 92
    ];
    let pub_key_x = [
        65, 34, 212, 75, 36, 198, 55, 190, 216, 124, 123, 16, 155, 212, 157, 97, 134, 53, 129, 94, 77, 244, 77, 51, 6, 129, 50, 68, 74, 235, 37, 210
    ];
    let pub_key_y = [
        211, 232, 46, 182, 4, 74, 247, 123, 164, 157, 138, 102, 69, 90, 221, 123, 163, 149, 197, 48, 99, 43, 123, 165, 161, 23, 43, 120, 28, 250, 107, 209
    ];

    let stamp_hash_bytes_facebook = [
        26, 169, 138, 240, 41, 102, 8, 94, 132, 244, 54, 144, 97, 237, 222, 139, 114, 134, 151, 12, 137, 57, 96, 207, 54, 216, 75, 95, 131, 81, 126, 212
    ];
    let stamp_hash_bytes_google = [
        26, 169, 138, 240, 41, 102, 8, 94, 132, 244, 54, 144, 97, 237, 222, 139, 114, 134, 151, 12, 137, 57, 96, 207, 54, 216, 75, 95, 131, 81, 126, 212
    ];

    let provider_bytes_facebook  = [
        111, 2, 132, 83, 221, 234, 5, 92, 43, 253, 107, 174, 255, 169, 6, 174, 105, 84, 224, 187, 144, 8, 62, 75, 118, 200, 96, 88, 233, 226, 192, 138
    ];
    let provider_bytes_google  = [
        246, 16, 248, 128, 133, 245, 149, 91, 204, 181, 4, 49, 225, 49, 90, 40, 51, 85, 34, 216, 123, 229, 0, 15, 243, 52, 39, 76, 201, 152, 87, 65
    ];

    main(
        [stamp_hash_bytes_facebook, stamp_hash_bytes_google],
        [provider_bytes_facebook, provider_bytes_google],
        [signature_facebook, signature_google],
        pub_key_x,
        pub_key_y,
        0xc7f222aadac8eef0039f5a8f01b9188e7a715a81
    );
}

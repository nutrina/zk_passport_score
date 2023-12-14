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
    let message_hash = [
        63, 183, 222, 65, 155, 61, 195, 51, 21, 152, 186, 252, 17, 242, 45, 91, 214, 174, 148, 204, 120, 35, 2, 8, 143, 72, 10, 232, 121, 251, 67, 9
    ];
    let signature = [
        35, 205, 11, 92, 164, 90, 212, 79, 124, 187, 3, 50, 242, 117, 243, 48, 192, 179, 40, 133, 90, 236, 154, 31, 168, 54, 67, 113, 220, 148, 42, 72, 63, 65, 187, 188, 167, 203, 236, 13, 42, 192, 151, 44, 66, 4, 170, 142, 70, 112, 178, 120, 31, 104, 33, 251, 26, 194, 142, 43, 138, 30, 124, 134
    ];
    let pub_key_x = [
        65, 34, 212, 75, 36, 198, 55, 190, 216, 124, 123, 16, 155, 212, 157, 97, 134, 53, 129, 94, 77, 244, 77, 51, 6, 129, 50, 68, 74, 235, 37, 210
    ];
    let pub_key_y = [
        211, 232, 46, 182, 4, 74, 247, 123, 164, 157, 138, 102, 69, 90, 221, 123, 163, 149, 197, 48, 99, 43, 123, 165, 161, 23, 43, 120, 28, 250, 107, 209
    ];
    verify_signature(message_hash, pub_key_x, pub_key_y, signature);
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

// TODO: implement this
// Improved implementation with split parameters
// use dep::std;

// // We support a maximum of 10 stamps ...
// fn main(providers1: [Field;10], providers2: [Field;10], hashes1: pub [Field;10], hashes2: pub [Field;10]) {
//     // Configure the list of supported providers (provider names are expected to be hashed)
//     // The list is split in 2 parts, the first list will contain the first 128 bits of a hash the second one the rest
//     // And the list is expected to be sorted by the numeric value of the hash. Inputs are expected to be passed in in the same order.
//     let valid_providers1:[Field; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
//     let valid_providers2:[Field; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
//     // The list of weights fr each supported provider
//     let weights:[u32; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
//     let mut score = 0;

//     for i in 0..10 {
//         // We expect the list of providers to match our pre-defined list of providers
//         // The lists should be sorted in the same way, ascending by the numeric value of the hash        
//         assert(providers1[i] == valid_providers1[i]);
//         assert(providers2[i] == valid_providers2[i]);

//         // If a hash was provided we should check the hash and cound the weight for that provider
//         let h1_not_zero: bool = hashes1[i] != 0;
//         let h2_not_zero: bool = hashes2[i] != 0;
//         let any_hash: bool = h1_not_zero | h2_not_zero;

//         if any_hash  {
//             score += weights[i];
//         }
//     }
//     assert(score >= 20);
// }

// #[test]
// fn test_main() {
//     main([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
//     // Uncomment to make test fail
//     // main(1, 1);
// }
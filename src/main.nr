use dep::std;

// We support a maximum of 10 stamps ...
fn main(
    providers1: [Field;10],
    providers2: [Field;10],
    hashes1: pub [Field;10],
    hashes2: pub [Field;10]
) {
    // Configure the list of supported providers (provider names are expected to be hashed)
    // The list is split in 2 parts, the first list will contain the first 128 bits of a hash the second one the rest
    // And the list is expected to be sorted by the numeric value of the hash. Inputs are expected to be passed in in the same order.
    let valid_providers1:[Field; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let valid_providers2:[Field; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    // The list of weights fr each supported provider
    let weights:[u32; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let mut score = 0;

    for i in 0..10 {
        // We expect the list of providers to match our pre-defined list of providers
        // The lists should be sorted in the same way, ascending by the numeric value of the hash        
        assert(providers1[i] == valid_providers1[i]);
        assert(providers2[i] == valid_providers2[i]);

        // If a hash was provided we should check the hash and cound the weight for that provider
        let h1_not_zero: bool = hashes1[i] != 0;
        let h2_not_zero: bool = hashes2[i] != 0;
        let any_hash: bool = h1_not_zero | h2_not_zero;

        if any_hash {
            score += weights[i];
        }
    }
    assert(score >= 20);
}

#[test]
fn test_main() {
    main(
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    );
    // Uncomment to make test fail
    // main(1, 1);
}

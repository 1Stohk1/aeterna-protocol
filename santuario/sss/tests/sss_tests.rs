use santuario_sss::{
    gf_mul, gf_div, split_secret, combine_shares, SssError
};

#[test]
fn test_gf256_arithmetic() {
    // 0 multiplied by anything is 0
    assert_eq!(gf_mul(0, 10), 0);
    assert_eq!(gf_mul(25, 0), 0);

    // Multiplication and division are inverses
    for a in 1..=255 {
        for b in 1..=255 {
            let prod = gf_mul(a, b);
            let div_a = gf_div(prod, b);
            assert_eq!(div_a, a, "gf_div(gf_mul({a}, {b}), {b}) should be {a}, got {div_a}");
        }
    }
}

#[test]
fn test_sss_correct_recovery_exact_quorum() {
    let secret = b"AETERNA-Prometheus-Secret-Key-2026";
    let threshold = 3;
    let num_shares = 5;

    // Split secret into 5 shares with threshold 3
    let shares = split_secret(secret, threshold, num_shares).unwrap();
    assert_eq!(shares.len(), 5);
    for share in &shares {
        assert_eq!(share.1.len(), secret.len());
    }

    // Try combining every possible combination of 3 shares
    for i in 0..num_shares {
        for j in (i + 1)..num_shares {
            for k in (j + 1)..num_shares {
                let subset = vec![
                    shares[i as usize].clone(),
                    shares[j as usize].clone(),
                    shares[k as usize].clone(),
                ];
                let recovered = combine_shares(&subset).unwrap();
                assert_eq!(recovered, secret, "Failed recovery with shares {i}, {j}, {k}");
            }
        }
    }
}

#[test]
fn test_sss_correct_recovery_over_quorum() {
    let secret = b"BIP39-Mnemonic-Seed-Phrase-Vault-Recovery-Test";
    let threshold = 4;
    let num_shares = 7;

    let shares = split_secret(secret, threshold, num_shares).unwrap();

    // Use 5 shares (which is > threshold 4)
    let subset = vec![
        shares[0].clone(),
        shares[2].clone(),
        shares[3].clone(),
        shares[5].clone(),
        shares[6].clone(),
    ];
    let recovered = combine_shares(&subset).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn test_sss_failed_recovery_under_quorum() {
    let secret = b"BIP39-Mnemonic-Seed-Phrase-Vault-Recovery-Test";
    let threshold = 4;
    let num_shares = 7;

    let shares = split_secret(secret, threshold, num_shares).unwrap();

    // Try using 3 shares (which is < threshold 4)
    let subset = vec![
        shares[0].clone(),
        shares[1].clone(),
        shares[2].clone(),
    ];
    let recovered = combine_shares(&subset).unwrap();
    assert_ne!(recovered, secret, "Sub-threshold shares must not recover the correct secret!");
}

#[test]
fn test_sss_invalid_split_params() {
    let secret = b"test";

    // Threshold = 0
    let res = split_secret(secret, 0, 5);
    assert_eq!(res.unwrap_err(), SssError::ThresholdZero);

    // Threshold > num_shares
    let res = split_secret(secret, 4, 3);
    assert_eq!(res.unwrap_err(), SssError::InvalidParameters { threshold: 4, num_shares: 3 });

    // Empty secret
    let res = split_secret(&[], 2, 3);
    assert_eq!(res.unwrap_err(), SssError::EmptySecret);
}

#[test]
fn test_sss_invalid_combine_params() {
    // Empty shares
    let res = combine_shares(&[]);
    assert_eq!(res.unwrap_err(), SssError::EmptyShares);

    // Mismatched lengths
    let shares = vec![
        (1, vec![1, 2, 3]),
        (2, vec![4, 5]),
    ];
    let res = combine_shares(&shares);
    assert_eq!(res.unwrap_err(), SssError::MismatchedLengths);

    // Duplicate share index
    let shares = vec![
        (1, vec![1, 2, 3]),
        (1, vec![4, 5, 6]),
    ];
    let res = combine_shares(&shares);
    assert_eq!(res.unwrap_err(), SssError::DuplicateShareIndex { index: 1 });

    // Zero share index
    let shares = vec![
        (0, vec![1, 2, 3]),
        (2, vec![4, 5, 6]),
    ];
    let res = combine_shares(&shares);
    assert_eq!(res.unwrap_err(), SssError::ZeroShareIndex);
}

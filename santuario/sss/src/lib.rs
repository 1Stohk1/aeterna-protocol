use std::sync::OnceLock;
use rand::RngCore;
use thiserror::Error;

static GF_TABLES: OnceLock<([u8; 256], [u8; 256])> = OnceLock::new();

/// Recupera le tabelle precalcolate Esponenziale e Logaritmo per GF(256) usando il generatore primitivo g=3.
fn get_tables() -> &'static ([u8; 256], [u8; 256]) {
    GF_TABLES.get_or_init(|| {
        let mut exp = [0u8; 256];
        let mut log = [0u8; 256];
        
        let mut val = 1u8;
        for i in 0..255 {
            exp[i] = val;
            log[val as usize] = i as u8;
            
            // Moltiplicazione per 3 in GF(256): 3 * val = (2 * val) ^ val
            let mut next = val << 1;
            if (val & 0x80) != 0 {
                next ^= 0x1B; // AES polynomial reduction
            }
            val = next ^ val;
        }
        
        exp[255] = exp[0]; // exp[255] = exp[0] = 1 (wrapping ciclico)
        log[0] = 0;        // 0 non ha logaritmo, convenzionalmente a 0
        
        (exp, log)
    })
}

/// Moltiplica due elementi in GF(256) usando tabelle di logaritmi
pub fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (exp, log) = get_tables();
    let sum_log = log[a as usize] as usize + log[b as usize] as usize;
    exp[sum_log % 255]
}

/// Divide due elementi in GF(256) usando tabelle di logaritmi
pub fn gf_div(a: u8, b: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    assert!(b != 0, "Division by zero in GF(256)");
    let (exp, log) = get_tables();
    let diff_log = (log[a as usize] as isize - log[b as usize] as isize + 255) % 255;
    exp[diff_log as usize]
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SssError {
    #[error("threshold (K) must be >= 1 and <= num_shares (N), got K={threshold}, N={num_shares}")]
    InvalidParameters { threshold: u8, num_shares: u8 },
    #[error("threshold (K) must be >= 1, got 0")]
    ThresholdZero,
    #[error("secret cannot be empty")]
    EmptySecret,
    #[error("mismatched share lengths")]
    MismatchedLengths,
    #[error("duplicate share index: {index}")]
    DuplicateShareIndex { index: u8 },
    #[error("invalid share index 0")]
    ZeroShareIndex,
    #[error("empty share list provided")]
    EmptyShares,
}

/// Suddivide un segreto in N quote con soglia K.
/// Restituisce un vettore di tuple contenenti (indice_quota, bytes_quota).
pub fn split_secret(
    secret: &[u8],
    threshold: u8,
    num_shares: u8,
) -> Result<Vec<(u8, Vec<u8>)>, SssError> {
    if threshold == 0 {
        return Err(SssError::ThresholdZero);
    }
    if threshold > num_shares {
        return Err(SssError::InvalidParameters { threshold, num_shares });
    }
    if secret.is_empty() {
        return Err(SssError::EmptySecret);
    }

    let mut rng = rand::thread_rng();
    let mut shares = Vec::new();
    
    for x in 1..=num_shares {
        shares.push((x, vec![0u8; secret.len()]));
    }

    for (byte_idx, &s_byte) in secret.iter().enumerate() {
        // Genera i coefficienti del polinomio di grado K-1
        let mut coef = vec![0u8; threshold as usize];
        coef[0] = s_byte; // P(0) = segreto
        for i in 1..(threshold as usize) {
            let mut buf = [0u8; 1];
            rng.fill_bytes(&mut buf);
            coef[i] = buf[0];
        }

        // Calcola il valore del polinomio per ciascuna quota x in 1..=N
        for share_idx in 0..(num_shares as usize) {
            let x = (share_idx + 1) as u8;
            
            let mut y = coef[0];
            let mut x_pow = 1u8;
            for i in 1..(threshold as usize) {
                x_pow = gf_mul(x_pow, x);
                let term = gf_mul(coef[i], x_pow);
                y ^= term; // addizione in GF(256) = XOR
            }
            shares[share_idx].1[byte_idx] = y;
        }
    }

    Ok(shares)
}

/// Ricostruisce il segreto originale a partire da una collezione di quote.
/// Richiede almeno K quote distinte per un corretto ripristino.
pub fn combine_shares(shares: &[(u8, Vec<u8>)]) -> Result<Vec<u8>, SssError> {
    if shares.is_empty() {
        return Err(SssError::EmptyShares);
    }

    let num_provided = shares.len();
    let secret_len = shares[0].1.len();
    
    for (_, s) in shares {
        if s.len() != secret_len {
            return Err(SssError::MismatchedLengths);
        }
    }

    let mut seen_indices = std::collections::HashSet::new();
    for &(x, _) in shares {
        if x == 0 {
            return Err(SssError::ZeroShareIndex);
        }
        if !seen_indices.insert(x) {
            return Err(SssError::DuplicateShareIndex { index: x });
        }
    }

    let mut secret = vec![0u8; secret_len];

    for byte_idx in 0..secret_len {
        let mut secret_byte = 0u8;

        // Interpolazione lagrangiana a x = 0
        for j in 0..num_provided {
            let x_j = shares[j].0;
            let y_j = shares[j].1[byte_idx];

            let mut l_j_0 = 1u8;
            for m in 0..num_provided {
                if m == j {
                    continue;
                }
                let x_m = shares[m].0;
                
                let num = x_m;
                let den = x_j ^ x_m;
                
                let term = gf_div(num, den);
                l_j_0 = gf_mul(l_j_0, term);
            }

            secret_byte ^= gf_mul(y_j, l_j_0);
        }

        secret[byte_idx] = secret_byte;
    }

    Ok(secret)
}

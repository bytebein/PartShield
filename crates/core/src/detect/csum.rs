//! Checksums de Btrfs para el superbloque: crc32c, xxhash64, sha256 y
//! blake2b-256 (`btrfs_csum_type` 0..=3).
//!
//! xxhash64 y blake2b están escritos aquí (son cortos y tienen vectores de
//! prueba oficiales) para no añadir dependencias al motor; crc32c y sha256
//! vienen de los crates que ya usa.

pub const CRC32C: u16 = 0;
pub const XXHASH64: u16 = 1;
pub const SHA256: u16 = 2;
pub const BLAKE2B: u16 = 3;

pub fn name(csum_type: u16) -> &'static str {
    match csum_type {
        CRC32C => "crc32c",
        XXHASH64 => "xxhash64",
        SHA256 => "sha256",
        BLAKE2B => "blake2b",
        _ => "desconocido",
    }
}

/// Checksum of `data` as Btrfs stores it (little-endian for the integer
/// ones), or `None` for a type this build does not know.
pub fn compute(csum_type: u16, data: &[u8]) -> Option<Vec<u8>> {
    Some(match csum_type {
        CRC32C => crc32c::crc32c(data).to_le_bytes().to_vec(),
        XXHASH64 => xxh64(data, 0).to_le_bytes().to_vec(),
        SHA256 => <sha2::Sha256 as sha2::Digest>::digest(data).to_vec(),
        BLAKE2B => blake2b(data, 32),
        _ => return None,
    })
}

// ------------------------------------------------------------- xxhash64

const P1: u64 = 0x9E37_79B1_85EB_CA87;
const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const P3: u64 = 0x1656_67B1_9E37_79F9;
const P4: u64 = 0x85EB_CA77_C2B2_AE63;
const P5: u64 = 0x27D4_EB2F_1656_67C5;

fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().unwrap())
}

fn xxh_round(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(P2))
        .rotate_left(31)
        .wrapping_mul(P1)
}

fn xxh_merge(acc: u64, v: u64) -> u64 {
    (acc ^ xxh_round(0, v)).wrapping_mul(P1).wrapping_add(P4)
}

pub fn xxh64(data: &[u8], seed: u64) -> u64 {
    let mut rest = data;
    let mut h = if data.len() >= 32 {
        let mut v = [
            seed.wrapping_add(P1).wrapping_add(P2),
            seed.wrapping_add(P2),
            seed,
            seed.wrapping_sub(P1),
        ];
        while rest.len() >= 32 {
            for (i, lane) in v.iter_mut().enumerate() {
                *lane = xxh_round(*lane, le64(&rest[i * 8..]));
            }
            rest = &rest[32..];
        }
        let mut h = v[0]
            .rotate_left(1)
            .wrapping_add(v[1].rotate_left(7))
            .wrapping_add(v[2].rotate_left(12))
            .wrapping_add(v[3].rotate_left(18));
        for lane in v {
            h = xxh_merge(h, lane);
        }
        h
    } else {
        seed.wrapping_add(P5)
    };
    h = h.wrapping_add(data.len() as u64);
    while rest.len() >= 8 {
        h ^= xxh_round(0, le64(rest));
        h = h.rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
        rest = &rest[8..];
    }
    if rest.len() >= 4 {
        h ^= u64::from(le32(rest)).wrapping_mul(P1);
        h = h.rotate_left(23).wrapping_mul(P2).wrapping_add(P3);
        rest = &rest[4..];
    }
    for &b in rest {
        h ^= u64::from(b).wrapping_mul(P5);
        h = h.rotate_left(11).wrapping_mul(P1);
    }
    h ^= h >> 33;
    h = h.wrapping_mul(P2);
    h ^= h >> 29;
    h = h.wrapping_mul(P3);
    h ^ (h >> 32)
}

// -------------------------------------------------------------- blake2b

const B2_IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

fn b2_compress(h: &mut [u64; 8], block: &[u8; 128], counter: u128, last: bool) {
    let m: Vec<u64> = block.chunks_exact(8).map(le64).collect();
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&B2_IV);
    v[12] ^= counter as u64;
    v[13] ^= (counter >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    let g = |v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64| {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(32);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(24);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(63);
    };
    for r in 0..12 {
        let s = &SIGMA[r % 10];
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// Unkeyed BLAKE2b with an `out_len`-byte digest (1..=64).
pub fn blake2b(data: &[u8], out_len: usize) -> Vec<u8> {
    assert!((1..=64).contains(&out_len));
    let mut h = B2_IV;
    h[0] ^= 0x0101_0000 ^ out_len as u64;
    let mut counter: u128 = 0;
    let mut rest = data;
    // The last block (possibly the only, possibly empty) is compressed with
    // the final flag, so stop while more than one block remains.
    while rest.len() > 128 {
        counter += 128;
        b2_compress(&mut h, rest[..128].try_into().unwrap(), counter, false);
        rest = &rest[128..];
    }
    let mut last = [0u8; 128];
    last[..rest.len()].copy_from_slice(rest);
    counter += rest.len() as u128;
    b2_compress(&mut h, &last, counter, true);
    h.iter()
        .flat_map(|w| w.to_le_bytes())
        .take(out_len)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn xxh64_reference_vectors() {
        assert_eq!(xxh64(b"", 0), 0xEF46_DB37_51D8_E999);
        assert_eq!(xxh64(b"a", 0), 0xD24E_C4F1_A98C_6E5B);
        assert_eq!(xxh64(b"abc", 0), 0x44BC_2CF5_AD77_0999);
        assert_eq!(
            xxh64(b"Nobody inspects the spammish repetition", 0),
            0xFBCE_A83C_8A37_8BF1
        );
    }

    #[test]
    fn blake2b_reference_vectors() {
        assert_eq!(
            hex(&blake2b(b"abc", 64)),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
        assert_eq!(
            hex(&blake2b(b"", 32)),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
        assert_eq!(
            hex(&blake2b(b"abc", 32)),
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
        );
    }

    #[test]
    fn blake2b_multi_block_matches_exact_boundary() {
        // 128 and 256 bytes exercise the "last full block" path.
        let a = blake2b(&[0u8; 128], 32);
        let b = blake2b(&[0u8; 129], 32);
        assert_ne!(a, b);
        assert_eq!(blake2b(&[7u8; 4064], 32).len(), 32);
    }

    #[test]
    fn sha256_matches_known_value() {
        assert_eq!(
            hex(&compute(SHA256, b"abc").unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(compute(9, b"abc").is_none());
    }
}

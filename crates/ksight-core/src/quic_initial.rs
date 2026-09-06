//! QUIC v1 `Initial` packet decryption without hooks (RFC 9001).
//!
//! Initial keys are derived from the public version salt plus the destination
//! connection ID, so the first client datagram can be opened in user space
//! with no uprobe and no in-process change. Header protection is stripped,
//! `AEAD_AES_128_GCM` is opened, CRYPTO frames are reassembled per connection,
//! and the TLS `ClientHello` SNI/ALPN are recovered. Handshake and 1-RTT
//! packets stay ciphertext; only version 1 is derived.

use std::collections::{BTreeMap, HashMap, VecDeque};

use crate::handshake::parse_client_hello_body;

/// RFC 9001 §5.2 Initial salt for QUIC v1.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// Largest reassembled CRYPTO stream kept per connection.
const CRYPTO_STREAM_CAP: usize = 16 * 1024;
/// Maximum CRYPTO segments buffered per connection before giving up.
const MAX_SEGMENTS: usize = 64;
/// Default per-capture connection entries; insert-order eviction.
const DEFAULT_CONNECTIONS: usize = 1024;

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

// ---------------------------------------------------------------- SHA-256

const K256: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    length: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            buffer: [0; 64],
            buffered: 0,
            length: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        if self.buffered > 0 {
            let take = (64 - self.buffered).min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffered = data.len();
        }
    }

    fn finish(mut self) -> [u8; 32] {
        let bits = self.length.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buffered != 56 {
            self.update(&[0]);
        }
        let mut block = self.buffer;
        block[56..64].copy_from_slice(&bits.to_be_bytes());
        self.compress(&block);
        let mut out = [0u8; 32];
        for (word, chunk) in self.state.iter().zip(out.chunks_mut(4)) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    #[allow(clippy::many_single_char_names)]
    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            *word = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(data);
    hash.finish()
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&sha256(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    let mut ipad = [0x36u8; 64];
    for (pad_byte, key_byte) in ipad.iter_mut().zip(block.iter()) {
        *pad_byte ^= key_byte;
    }
    inner.update(&ipad);
    inner.update(message);
    let mut outer = Sha256::new();
    let mut opad = [0x5cu8; 64];
    for (pad_byte, key_byte) in opad.iter_mut().zip(block.iter()) {
        *pad_byte ^= key_byte;
    }
    outer.update(&opad);
    outer.update(&inner.finish());
    outer.finish()
}

// ---------------------------------------------------------------- HKDF

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

fn hkdf_expand(prk: &[u8; 32], info: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut previous: Vec<u8> = Vec::new();
    for counter in 1u8.. {
        if out.len() >= out_len {
            break;
        }
        let mut message = previous.clone();
        message.extend_from_slice(info);
        message.push(counter);
        previous = hmac_sha256(prk, &message).to_vec();
        out.extend_from_slice(&previous);
    }
    out.truncate(out_len);
    out
}

/// RFC 8446 §7.1 `HKDF-Expand-Label` with the `tls13 ` prefix.
pub(crate) fn hkdf_expand_label(secret: &[u8; 32], label: &[u8], out_len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1);
    info.extend_from_slice(&(u16::try_from(out_len).unwrap_or(0)).to_be_bytes());
    info.push(u8::try_from(6 + label.len()).unwrap_or(0));
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    hkdf_expand(secret, &info, out_len)
}

// ---------------------------------------------------------------- AES-128

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

pub(crate) struct Aes128 {
    round_keys: Vec<[u8; 16]>,
    rounds: usize,
}

impl Aes128 {
    fn new(key: &[u8; 16]) -> Self {
        Self::with_key_bytes(key)
    }

    /// AES-128 or AES-256 from raw key bytes (TLS 1.3 suites pick both).
    pub(crate) fn with_key_bytes(key: &[u8]) -> Self {
        let words_of_key = (key.len() / 4).max(4);
        let rounds = match words_of_key {
            4 => 10,
            6 => 12,
            _ => 14,
        };
        let total_words = 4 * (rounds + 1);
        let mut round_keys = vec![[0u8; 16]; rounds + 1];
        round_keys[0].copy_from_slice(&key[..16]);
        let mut words = vec![0u32; total_words];
        for (i, word) in words.iter_mut().enumerate().take(words_of_key) {
            *word = u32::from_be_bytes([
                key[i * 4],
                key.get(i * 4 + 1).copied().unwrap_or(0),
                key.get(i * 4 + 2).copied().unwrap_or(0),
                key.get(i * 4 + 3).copied().unwrap_or(0),
            ]);
        }
        let rcon = |round: usize| -> u32 {
            let mut value = 1u8;
            for _ in 1..round {
                value = Self::xtimes(value);
            }
            u32::from(value) << 24
        };
        for i in words_of_key..total_words {
            let mut temp = words[i - 1];
            if i % words_of_key == 0 {
                temp = temp.rotate_left(8);
                temp = u32::from_be_bytes([
                    SBOX[usize::from(((temp >> 24) & 0xff) as u8)],
                    SBOX[usize::from(((temp >> 16) & 0xff) as u8)],
                    SBOX[usize::from(((temp >> 8) & 0xff) as u8)],
                    SBOX[usize::from((temp & 0xff) as u8)],
                ]);
                temp ^= rcon(i / words_of_key);
            } else if words_of_key == 8 && i % 8 == 4 {
                for shift in [24, 16, 8, 0] {
                    let byte = usize::try_from((temp >> shift) & 0xff).unwrap_or(0);
                    temp &= !(0xff << shift);
                    temp |= u32::from(SBOX[byte]) << shift;
                }
            }
            words[i] = words[i - words_of_key] ^ temp;
        }
        for (round, round_key) in round_keys.iter_mut().enumerate() {
            for (column, word) in round_key.chunks_mut(4).enumerate() {
                word.copy_from_slice(&words[round * 4 + column].to_be_bytes());
            }
        }
        Self { round_keys, rounds }
    }

    fn sub_bytes(state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = SBOX[usize::from(*byte)];
        }
    }

    fn shift_rows(state: &mut [u8; 16]) {
        let original = *state;
        for row in 1..4usize {
            for column in 0..4usize {
                state[row + column * 4] = original[row + ((column + row) % 4) * 4];
            }
        }
    }

    fn xtimes(value: u8) -> u8 {
        let doubled = value << 1;
        let carry = value >> 7;
        doubled ^ (carry * 0x1b)
    }

    fn mix_columns(state: &mut [u8; 16]) {
        for column in 0..4usize {
            let base = column * 4;
            let column_bytes = [
                state[base],
                state[base + 1],
                state[base + 2],
                state[base + 3],
            ];
            for row in 0..4usize {
                let doubled = Self::xtimes(column_bytes[row]);
                let tripled =
                    Self::xtimes(column_bytes[(row + 1) % 4]) ^ column_bytes[(row + 1) % 4];
                state[base + row] =
                    doubled ^ tripled ^ column_bytes[(row + 2) % 4] ^ column_bytes[(row + 3) % 4];
            }
        }
    }

    fn add_round_key(state: &mut [u8; 16], key: &[u8; 16]) {
        for (state_byte, key_byte) in state.iter_mut().zip(key.iter()) {
            *state_byte ^= key_byte;
        }
    }

    pub(crate) fn encrypt_block(&self, block: &mut [u8; 16]) {
        Self::add_round_key(block, &self.round_keys[0]);
        for round in 1..=self.rounds {
            Self::sub_bytes(block);
            Self::shift_rows(block);
            if round < self.rounds {
                Self::mix_columns(block);
            }
            Self::add_round_key(block, &self.round_keys[round]);
        }
    }
}

// ---------------------------------------------------------------- GCM

fn gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;
    for byte in x {
        for bit in (0..8).rev() {
            if (byte >> bit) & 1 == 1 {
                for (z_byte, v_byte) in z.iter_mut().zip(v.iter()) {
                    *z_byte ^= v_byte;
                }
            }
            let lsb = v[15] & 1;
            for index in (1..16).rev() {
                v[index] = (v[index] >> 1) | (v[index - 1] << 7);
            }
            v[0] >>= 1;
            if lsb == 1 {
                v[0] ^= 0xe1;
            }
        }
    }
    z
}

fn ghash_block(h: &[u8; 16], y: &mut [u8; 16], block: &[u8; 16]) {
    for (y_byte, block_byte) in y.iter_mut().zip(block.iter()) {
        *y_byte ^= block_byte;
    }
    *y = gf128_mul(y, h);
}

fn ghash_bytes(h: &[u8; 16], data: &[u8], y: &mut [u8; 16]) {
    let mut chunks = data.chunks_exact(16);
    for chunk in &mut chunks {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        ghash_block(h, y, &block);
    }
    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        let mut block = [0u8; 16];
        block[..remainder.len()].copy_from_slice(remainder);
        ghash_block(h, y, &block);
    }
}

/// `AEAD_AES_128_GCM` open per RFC 5116/RFC 8439. Returns `None` on tag mismatch.
fn aes128_gcm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Option<Vec<u8>> {
    if ciphertext_with_tag.len() < 16 {
        return None;
    }
    let (ciphertext, tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);
    let aes = Aes128::new(key);
    let mut h = [0u8; 16];
    aes.encrypt_block(&mut h);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;
    let mut y = [0u8; 16];
    ghash_bytes(&h, aad, &mut y);
    ghash_bytes(&h, ciphertext, &mut y);
    let mut length_block = [0u8; 16];
    length_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    length_block[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    ghash_block(&h, &mut y, &length_block);
    let mut expected_tag = j0;
    aes.encrypt_block(&mut expected_tag);
    for (tag_byte, y_byte) in expected_tag.iter_mut().zip(y.iter()) {
        *tag_byte ^= y_byte;
    }
    let mut difference = 0u8;
    for (expected, given) in expected_tag.iter().zip(tag.iter()) {
        difference |= expected ^ given;
    }
    if difference != 0 {
        return None;
    }
    let mut counter = j0;
    let mut out = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(16) {
        for byte in counter.iter_mut().rev() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
        let mut keystream = counter;
        aes.encrypt_block(&mut keystream);
        for (cipher_byte, key_byte) in chunk.iter().zip(keystream.iter()) {
            out.push(cipher_byte ^ key_byte);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------- QUIC parsing

/// QUIC variable-length integer (RFC 9000 §16): value and consumed bytes.
fn read_varint(payload: &[u8], offset: usize) -> Option<(u64, usize)> {
    let first = *payload.get(offset)?;
    let length = match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let end = offset.checked_add(length)?;
    let bytes = payload.get(offset..end)?;
    let mut value = u64::from(first & 0x3f);
    for byte in bytes.iter().skip(1) {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, length))
}

/// One decrypted `Initial` packet: connection ID plus its CRYPTO stream segments.
pub struct DecryptedInitial {
    /// Destination connection ID bytes.
    pub dcid: Vec<u8>,
    /// Reconstructed packet number.
    pub packet_number: u64,
    /// `(offset, bytes)` CRYPTO stream segments carried by this packet.
    pub crypto: Vec<(u64, Vec<u8>)>,
}

/// Keys for one direction of an `Initial` connection.
struct InitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

fn initial_keys(dcid: &[u8], direction_label: &[u8]) -> Option<InitialKeys> {
    let initial_secret = hkdf_extract(&INITIAL_SALT_V1, dcid);
    let secret: [u8; 32] = hkdf_expand_label(&initial_secret, direction_label, 32)
        .try_into()
        .ok()?;
    let key: [u8; 16] = hkdf_expand_label(&secret, b"quic key", 16)
        .try_into()
        .ok()?;
    let iv: [u8; 12] = hkdf_expand_label(&secret, b"quic iv", 12).try_into().ok()?;
    let hp: [u8; 16] = hkdf_expand_label(&secret, b"quic hp", 16).try_into().ok()?;
    Some(InitialKeys { key, iv, hp })
}

fn decode_packet_number(truncated: u64, pn_bytes: usize, expected: u64) -> u64 {
    let window = 1u64 << (8 * pn_bytes);
    let mask = window - 1;
    let candidate = (expected & !mask) | truncated;
    [
        candidate,
        candidate.wrapping_add(window),
        candidate.wrapping_sub(window),
    ]
    .into_iter()
    .min_by_key(|value| value.abs_diff(expected))
    .unwrap_or(candidate)
}

/// Decrypt one v1 `Initial` datagram. Server `Initial` packets open with the
/// `server in` secret; this derives the client direction only, so those fail
/// the tag check and are reported as `None`.
pub fn decrypt_initial(datagram: &[u8]) -> Option<DecryptedInitial> {
    if datagram.len() < 40 || (datagram[0] & 0xc0) != 0xc0 {
        return None;
    }
    let version = u32::from_be_bytes([datagram[1], datagram[2], datagram[3], datagram[4]]);
    if version != 1 || ((datagram[0] >> 4) & 0x03) != 0 {
        return None;
    }
    let mut offset = 5usize;
    let dcid_len = usize::from(*datagram.get(offset)?);
    if dcid_len > 20 {
        return None;
    }
    offset += 1;
    let dcid = datagram.get(offset..offset + dcid_len)?.to_vec();
    offset += dcid_len;
    let scid_len = usize::from(*datagram.get(offset)?);
    if scid_len > 20 {
        return None;
    }
    offset += 1 + scid_len;
    let (token_len, bytes) = read_varint(datagram, offset)?;
    offset = offset
        .checked_add(bytes)?
        .checked_add(usize::try_from(token_len).ok()?)?;
    let (payload_len, bytes) = read_varint(datagram, offset)?;
    offset += bytes;
    let payload_len = usize::try_from(payload_len).ok()?;
    if payload_len < 20 || datagram.len() < offset + payload_len {
        return None;
    }
    let pn_offset = offset;
    let keys = initial_keys(&dcid, b"client in")?;
    let mut sample_block = [0u8; 16];
    sample_block.copy_from_slice(datagram.get(pn_offset + 4..pn_offset + 20)?);
    let aes = Aes128::new(&keys.hp);
    aes.encrypt_block(&mut sample_block);
    let first = datagram[0] ^ (sample_block[0] & 0x0f);
    let pn_len = usize::from(first & 0x03) + 1;
    let mut truncated = 0u64;
    let mut pn_bytes = [0u8; 4];
    for index in 0..pn_len {
        pn_bytes[index] = datagram[pn_offset + index] ^ sample_block[1 + index];
        truncated = (truncated << 8) | u64::from(pn_bytes[index]);
    }
    let packet_number = decode_packet_number(truncated, pn_len, 0);
    let mut header = Vec::with_capacity(pn_offset + pn_len);
    header.extend_from_slice(&datagram[..pn_offset]);
    header[0] = first;
    header.extend_from_slice(&pn_bytes[..pn_len]);
    let mut nonce = keys.iv;
    let encoded = packet_number.to_be_bytes();
    for index in 0..8 {
        nonce[4 + index] ^= encoded[index];
    }
    let body = datagram
        .get(pn_offset + pn_len..pn_offset + payload_len)?
        .to_vec();
    eprintln!("[qdbg] pn_offset={} pn_len={} first={:02x} payload_len={} header_len={} body_len={} key={} iv={}", pn_offset, pn_len, first, payload_len, header.len(), body.len(), to_hex(&keys.key), to_hex(&keys.iv));
    let plaintext = aes128_gcm_decrypt(&keys.key, &nonce, &header, &body)?;
    eprintln!(
        "[qdbg] plaintext len = {} head = {}",
        plaintext.len(),
        to_hex(&plaintext[..plaintext.len().min(12)])
    );
    Some(DecryptedInitial {
        dcid,
        packet_number,
        crypto: extract_crypto_frames(&plaintext),
    })
}

/// Walk a decrypted payload and collect CRYPTO frames. Unknown frame types
/// stop the walk; everything before them is still usable.
fn extract_crypto_frames(payload: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut frames = Vec::new();
    let mut offset = 0usize;
    while offset < payload.len() {
        match payload[offset] {
            0x00 | 0x01 => offset += 1,
            0x02 | 0x03 => {
                let Some(next) = skip_ack_frame(payload, offset) else {
                    break;
                };
                offset = next;
            }
            0x06 => {
                let Some((frame_offset, bytes)) = read_varint(payload, offset + 1) else {
                    break;
                };
                let Some(cursor) = (offset + 1).checked_add(bytes) else {
                    break;
                };
                let Some((length, bytes)) = read_varint(payload, cursor) else {
                    break;
                };
                let Some(cursor) = cursor.checked_add(bytes) else {
                    break;
                };
                let Some(length) = usize::try_from(length).ok() else {
                    break;
                };
                let Some(data) = payload.get(cursor..cursor.saturating_add(length)) else {
                    break;
                };
                frames.push((frame_offset, data.to_vec()));
                offset = cursor + length;
            }
            0x07 => {
                let Some((token_len, bytes)) = read_varint(payload, offset + 1) else {
                    break;
                };
                let Some(next) = (offset + 1).checked_add(bytes).and_then(|cursor| {
                    cursor.checked_add(usize::try_from(token_len).unwrap_or(usize::MAX))
                }) else {
                    break;
                };
                if next > payload.len() {
                    break;
                }
                offset = next;
            }
            0x1c | 0x1d => {
                let mut cursor = offset + 1;
                let mut varints = if payload[offset] == 0x1c { 2 } else { 1 };
                let mut reason_len = 0u64;
                let mut aborted = false;
                while varints > 0 {
                    let Some((value, bytes)) = read_varint(payload, cursor) else {
                        aborted = true;
                        break;
                    };
                    cursor += bytes;
                    varints -= 1;
                    if varints == 0 {
                        reason_len = value;
                    }
                }
                if aborted {
                    break;
                }
                cursor = cursor.saturating_add(usize::try_from(reason_len).unwrap_or(usize::MAX));
                if cursor > payload.len() {
                    break;
                }
                offset = cursor;
            }
            _ => break,
        }
    }
    frames
}

fn skip_ack_frame(payload: &[u8], offset: usize) -> Option<usize> {
    let mut cursor = offset + 1;
    for _ in 0..3 {
        let (_, bytes) = read_varint(payload, cursor)?;
        cursor += bytes;
    }
    let (ranges, bytes) = read_varint(payload, cursor)?;
    cursor += bytes;
    for _ in 0..ranges.min(1024) {
        for _ in 0..2 {
            let (_, bytes) = read_varint(payload, cursor)?;
            cursor += bytes;
        }
    }
    if payload[offset] == 0x03 {
        for _ in 0..3 {
            let (_, bytes) = read_varint(payload, cursor)?;
            cursor += bytes;
        }
    }
    Some(cursor)
}

// ---------------------------------------------------------------- table

/// Client hello recovered from a reassembled `Initial` CRYPTO stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicInitialHello {
    /// Destination connection ID as lowercase hex.
    pub dcid_hex: String,
    /// `ClientHello` SNI hostname.
    pub sni: Option<String>,
    /// Comma-joined `ClientHello` ALPN protocols.
    pub alpn: Option<String>,
}

#[derive(Clone, Default)]
struct ConnectionEntry {
    segments: BTreeMap<u64, Vec<u8>>,
    hello: Option<QuicInitialHello>,
}

/// Per-connection CRYPTO reassembly across the first `Initial` datagrams.
///
/// The BPF handshake sensor yields one datagram per socket per counter tick,
/// so client hellos split across datagrams are joined here before parsing.
#[derive(Clone)]
pub struct QuicInitialTable {
    entries: HashMap<Vec<u8>, ConnectionEntry>,
    order: VecDeque<Vec<u8>>,
    capacity: usize,
}

impl std::fmt::Debug for QuicInitialTable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuicInitialTable")
            .field("entries", &self.entries.len())
            .field("order", &self.order.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl QuicInitialTable {
    /// Create a table holding at most `capacity` connections.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    /// Create a table with the default connection budget.
    pub fn default_table() -> Self {
        Self::new(DEFAULT_CONNECTIONS)
    }

    /// Feed one captured datagram. Returns the client hello the first time a
    /// connection's CRYPTO stream completes one, then `None` for that connection.
    pub fn feed(&mut self, datagram: &[u8]) -> Option<QuicInitialHello> {
        let initial = decrypt_initial(datagram)?;
        let dcid = initial.dcid;
        {
            let entry = self.entry_for(dcid.as_slice())?;
            for (offset, data) in initial.crypto {
                if entry.segments.len() >= MAX_SEGMENTS && !entry.segments.contains_key(&offset) {
                    return None;
                }
                entry.segments.insert(offset, data);
            }
        }
        let entry = self.entries.get(&dcid)?;
        if entry.hello.is_some() {
            return None;
        }
        let Some(stream) = contiguous_stream(&entry.segments) else {
            self.order.retain(|seen| seen != &dcid);
            self.entries.remove(&dcid);
            return None;
        };
        let meta = parse_client_hello_from_stream(&stream)?;
        let recovered = QuicInitialHello {
            dcid_hex: to_hex(&dcid),
            sni: meta.sni,
            alpn: meta.alpn,
        };
        if let Some(entry) = self.entries.get_mut(&dcid) {
            entry.hello = Some(recovered.clone());
            entry.segments.clear();
        }
        Some(recovered)
    }

    fn entry_for(&mut self, dcid: &[u8]) -> Option<&mut ConnectionEntry> {
        if !self.entries.contains_key(dcid) {
            while self.entries.len() >= self.capacity {
                match self.order.pop_front() {
                    Some(oldest) => {
                        self.entries.remove(&oldest);
                    }
                    None => break,
                }
            }
            self.entries
                .insert(dcid.to_vec(), ConnectionEntry::default());
            self.order.push_back(dcid.to_vec());
        }
        self.entries.get_mut(dcid)
    }
}

fn contiguous_stream(segments: &BTreeMap<u64, Vec<u8>>) -> Option<Vec<u8>> {
    let mut stream = Vec::new();
    for (offset, data) in segments {
        let Ok(offset) = usize::try_from(*offset) else {
            return None;
        };
        if offset > stream.len() {
            break; // gap; wait for more datagrams
        }
        if stream.len() + data.len() > CRYPTO_STREAM_CAP {
            return None;
        }
        stream.extend_from_slice(data);
    }
    Some(stream)
}

fn parse_client_hello_from_stream(stream: &[u8]) -> Option<crate::handshake::HandshakeMeta> {
    if stream.len() < 4 || stream[0] != 0x01 {
        return None;
    }
    let length =
        (usize::from(stream[1]) << 16) | (usize::from(stream[2]) << 8) | usize::from(stream[3]);
    if stream.len() < 4 + length {
        return None;
    }
    parse_client_hello_body(&stream[..4 + length])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn sha256_known_answer() {
        assert_eq!(
            to_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hmac_known_answer() {
        assert_eq!(
            to_hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hkdf_known_answer() {
        let salt: Vec<u8> = (0x00u8..=0x0c).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();
        let prk = hkdf_extract(&salt, &[0x0b; 22]);
        let okm = hkdf_expand(&prk, &info, 42);
        assert_eq!(
            to_hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn aes128_known_answer() {
        let aes = Aes128::new(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]);
        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        aes.encrypt_block(&mut block);
        assert_eq!(to_hex(&block), "69c4e0d86a7b0430d8cdb78070b4c55a");
    }

    #[test]
    fn gcm_known_answer() {
        let key = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08,
        ];
        let nonce = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let plaintext: Vec<u8> = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55,
        ]
        .to_vec();
        let ciphertext: Vec<u8> = [
            0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0,
            0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23,
            0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f,
            0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
            0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f, 0x59, 0x85,
        ]
        .iter()
        .chain(
            [
                0x4d, 0x5c, 0x2a, 0xf3, 0x27, 0xcd, 0x64, 0xa6, 0x2c, 0xf3, 0x5a, 0xbd, 0x2b, 0xa6,
                0xfa, 0xb4,
            ]
            .iter(),
        )
        .copied()
        .collect();
        let opened = aes128_gcm_decrypt(&key, &nonce, &[], &ciphertext).expect("gcm");
        assert_eq!(opened, plaintext);
        assert!(
            aes128_gcm_decrypt(&key, &nonce, &[], &ciphertext[..ciphertext.len() - 1]).is_none()
        );
    }

    #[test]
    fn initial_keys_match_rfc9001_appendix_a() {
        let keys = initial_keys(&hex_bytes("8394c8f03e515708"), b"client in").expect("keys");
        assert_eq!(to_hex(&keys.key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(to_hex(&keys.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(to_hex(&keys.hp), "9f50449e04a0e810283a1e9933adedd2");
    }

    const V1_PACKET_HEX: &str = "c400000001080011223344556677000044d29287f5085800f3d3dffd98583979b28c09c535c908aa4c7b72414f85f8b80590c1942ba47239dee92ea18dfe530100859d12152427566552f91a82196929b3ba609e7b5814f0256b9976e2d1478404bdc6dbd28dfaf3802352f22432dcc5980f337fc22952603f276d0f7207b49169e0ca8182b6f4c4304fc4d9aca20a6166be0d6564a653fe4d7b575567ff2e2275a26ba37ea3e98494bbf1ccf7d7f65f225bc539ec380cd3f1424dd8162261ebc699ab7c26854198b6ed5ac661a97a680447166d3484b584c1a7ee1fdf20c494e525317954bcdbb22ad33c811da942638a7db4add90dc698033d7115e73be9bf51f47b8dbfb4d5d8b864acbb74ac1d3f12328c22a5c481660c63c2ae9b19eee4687125befe0737ce0a0511c555f61cba13f764d4e46e0b505a9ea8b25ef68d62c913f285d2ab787eb9bffd2208bf19ca3d57fa493791b63d0640097692766b19eda0b35b14b03e97dac7c8f48a22d04664439725b8a52d28173c82a736f9d8bba007aee0191a253d8e1d9eb09e0e87030b21b2557bdb67b8e44dfde40b6ca5951830cf7f885283bbabd061107feac8e2c024f99dbc41908aabdc2d9231d73bece795bb80685c1611607ce1ee0b0224241b145b2db2159147b896b2869c2c808586b0fd4322e9a0e7f47c6974baeb469b7682d916acbb13d0054c94aa8617f7864c6039edd7cf134780a629a2ba4d372c4860ab6b2718e0501591c06d5735de6e87cd860c19a3ad53730b70f64f893c5b52b8f7b5a4b31b40539718d2629ef37ba10298ba908d3d0b99872a011be42ad634cd9bd5485ebb24b8bf05a5c179f8fa9808e2b7b796873fdf5b7c47a44eb62f632aaaa3b2bf6029cf88bd2958d9a368c06de62a153932151aa42d0211009812909f23c776b216ac3d1b9557dded58e0ea2579e2e04b92856aabd66b4746e42611351716d351832726a1e3fe68312d8bf258f9721930f1d8f573b9674387930afc6bd3f8d04bb8242cf67254e6b1677774f6032e98a7dee799b3a8a4606f2e5eeecfb0d2db0eb3aaaf1231a305b9edbf2d2fde9444fcfc290820f1246469ee2efd8fdd49d704f540eb29f6a3f975c65694269e26f35bb5dcb0029383ef2756c83aaeb723f1d97f476194eae72be238f97c5714c287d85ba883c66d08d26b100edefa86a3192181accfb4f8e693b64fb917d9861d3c6d6691ea0932784fab2835d2c449ba5337c78df2af1bbff800b289be8e521f2f080c6c7fe1efa8973a53ce8570567e2150058016be3913f2a6c7b36072034414b20c521506314071cdb8a33e0897464f248465021d92c9b7056058170789bac9b0066a47a2e3851deb0e9a86d5b9fbdfa95ec41354019fea6ba5119b6c09821b669cb54067455349bf624056cb1aec9e8ae5164e965c7651e06cde3f99df052ee75f261095d6fac34d5cdca6557473b28f90d40fc70a8b46196b9ac7591fdf3af5baebb281525090868e3f5aa256d97c06d26d2efefecd2d71e61b7f27a0e3c814684afea0f1979cb7dcbbc114294b7e50e1faa710b64ce431f8777e2b1c9236d9d742b453c7cec7ea3259a4f57ee96bfd88d3f22151577b5e15686e6fdba16108e274d6a8c23555d9c2b98207efb5060a4aa27e19deaafca70fb47d065cc9839bfde654ea1d5022629596bd1954249b30ce21f0ddc79bfb407d76075e74bc7e16af3faa501ebb8282d35b6601a61655b8c106762898f08979f73af20935b1";
    const V2A_PACKET_HEX: &str = "c60000000108aabbccddeeff0011000040e027b7f0032f3609a065cda2092dad4685ff9c52e69c13c2cdb494b8ef54f9814a772c948d1b3e7e29df95f04b2e9b616996be74e64ef43076975d03a1cd62be94d86143ce07a75d6e7b5dfd9bc555de3aa0597aa2b2fd62c8d11abae07a4d894451529f493d9ed9a4915cf52743a10c3316cdf992e840f8bf003a3410f65ecb2c7175064d0bc32b2951d1566846a717a6a58506df3ceb57bfecf4f1f97c12e70b2ea742dc74269a5ba8c953270fc9c658f4a72c3e65bda6c89c966e45027cdf5defc506632de4188f8ec6a55b19d328a520f154e100965bab7baf2ade698363a8";
    const V2B_PACKET_HEX: &str = "c90000000108aabbccddeeff0011000040e09ff456ff3d4045e4f1ecc8ef7fecbc6baff597a4380642bf94af09726bf79ae2a8ae1bc19ccec99432f0f3bf7c97398e0dcf3d79d325264c1d97cb1a4cfc15a1c185feeb1910cd3c6710df0c317b84e5dd6b538ae4475117a8618d0d1bac4615826a1d0fd1855f19568be70123be9ba337d5335067920f054614cea4623028edf5c1587e5b344f7101d791071a467594e0080a2f14d70a0aab71adc7999667e15bd7a9fc93d7ebfc5b38d91b0b6c3d0b8aa2d4e56c40de6974a7a622efce4a92d149d7f78a8ea309e858b9b4d87c7b1501fc4e60ebc6b577d941ecb615f03fb5";

    #[test]
    fn decrypts_client_hello_from_single_datagram() {
        let mut table = QuicInitialTable::default_table();
        let hello = table.feed(&hex_bytes(V1_PACKET_HEX)).expect("hello");
        assert_eq!(hello.dcid_hex, "0011223344556677");
        assert_eq!(hello.sni.as_deref(), Some("probe.kernsight.test"));
        assert_eq!(hello.alpn.as_deref(), Some("h3"));
        assert!(table.feed(&hex_bytes(V1_PACKET_HEX)).is_none());
    }

    #[test]
    fn reassembles_client_hello_split_across_initials() {
        let mut table = QuicInitialTable::default_table();
        assert!(table.feed(&hex_bytes(V2A_PACKET_HEX)).is_none());
        let hello = table.feed(&hex_bytes(V2B_PACKET_HEX)).expect("hello");
        assert_eq!(hello.dcid_hex, "aabbccddeeff0011");
        assert_eq!(hello.sni.as_deref(), Some("split.kernsight.test"));
        assert_eq!(hello.alpn.as_deref(), Some("h3,h3-29"));
    }

    #[test]
    fn truncated_datagram_fails_closed() {
        let datagram = hex_bytes(V1_PACKET_HEX);
        let mut table = QuicInitialTable::default_table();
        // The old 512-byte capture cap cannot contain the GCM tag.
        assert!(table.feed(&datagram[..512]).is_none());
        // Corrupting the last byte breaks the tag.
        let mut corrupted = datagram.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0xff;
        assert!(table.feed(&corrupted).is_none());
    }

    #[test]
    fn non_initial_packets_are_ignored() {
        let mut table = QuicInitialTable::default_table();
        // Handshake packet type 0b10, and version negotiation (version 0).
        assert!(table
            .feed(&[0xe0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0])
            .is_none());
        assert!(table
            .feed(&[0xc0, 0, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0])
            .is_none());
    }
}

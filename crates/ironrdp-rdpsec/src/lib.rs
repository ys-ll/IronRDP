//! Standard RDP Security (PROTOCOL_RDP, MS-RDPBCGR 5.3) crypto engine.
//!
//! Verified bit-for-bit against FreeRDP `security.c` and against live
//! Windows TermService wire behavior (differential fixture below).
//!
//! Contents:
//! - `Rc4Stream`: RC4 with keystream state that persists across PDUs (a new
//!   context is only created on the 4096-package key update).
//! - `RdpSecurity`: master secret / session key schedule, PDU MAC (plain and
//!   SECURE_CHECKSUM counter variants), encrypt/decrypt with 4096-update, and
//!   `decrypt_checked` — MAC-guided keystream resynchronisation that survives
//!   the server encrypting PDUs internally without ever sending them
//!   ("phantom" keystream consumption, observed live after License PDUs).
//! - `encrypt_client_random`: raw textbook RSA over the little-endian
//!   proprietary server certificate public key (MS-RDPBCGR 2.2.1.4.3.1.1).

#![allow(clippy::print_stdout)] // example-support crate; no tracing dependency by design

use md5::Md5;
use sha1::Sha1;

use digest::Digest;

/// MS-RDPBCGR 2.2.8.1.1.2 encryption method flags.
pub const ENCRYPTION_FLAG_40BIT: u32 = 0x1;
pub const ENCRYPTION_FLAG_128BIT: u32 = 0x2;
pub const ENCRYPTION_FLAG_56BIT: u32 = 0x8;

const PAD1: [u8; 40] = [0x36; 40];
const PAD2: [u8; 48] = [0x5c; 48];
const SALT_40: [u8; 3] = [0xd1, 0x26, 0x9e];

/// Slow-path security header flags (MS-RDPBCGR 2.2.8.1.1.2.1).
pub const SEC_CLIENT_RANDOM: u16 = 0x0001;
pub const SEC_TRANSPORT_RSP: u16 = 0x0004;
pub const SEC_ENCRYPT: u16 = 0x0008;
pub const SEC_INFO_PKT: u16 = 0x0040;
pub const SEC_LICENSE_PKT: u16 = 0x0080;
pub const SEC_LICENSE_ENCRYPT_CS: u16 = 0x0100;
pub const SEC_LICENSE_ENCRYPT_SC: u16 = 0x0200;
/// TS_SEC_SECURE_CHECKSUM — MAC mixes in the per-direction package counter.
pub const SEC_SECURE_CHECKSUM: u16 = 0x0800;
pub const SEC_AUTODETECT_RSP: u16 = 0x2000;

/// A single RC4 keystream context reused across PDUs until a key update.
#[derive(Clone)]
pub struct Rc4Stream {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4Stream {
    pub fn new(key: &[u8]) -> Self {
        let mut s: [u8; 256] = [0; 256];
        for (idx, val) in s.iter_mut().enumerate() {
            *val = idx as u8;
        }
        let mut j: u8 = 0;
        for idx in 0..256_usize {
            j = j.wrapping_add(s[idx]).wrapping_add(key[idx % key.len()]);
            s.swap(idx, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    pub fn crypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; data.len()];
        for (dst, src) in out.iter_mut().zip(data) {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            *dst = *src ^ self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
        }
        out
    }
}

fn md5(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize().into()
}

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}

fn u32le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// Standard RDP Security engine, client side (client encrypt = server decrypt key).
///
/// [`Debug`] is manual and deliberately redacted: the struct carries the live
/// RC4 keys and MAC state, none of which may reach a log line.
pub struct RdpSecurity {
    method: u32,
    key_len: usize,
    sign_key: Vec<u8>,
    encrypt_key: Vec<u8>,
    decrypt_key: Vec<u8>,
    enc_update_key: Vec<u8>,
    dec_update_key: Vec<u8>,
    salt: [u8; 3],
    salt_len: usize,

    enc_rc4: Rc4Stream,
    dec_rc4: Rc4Stream,
    enc_use: u32,
    dec_use: u32,
    /// Server→client monotonic package counter including "phantom" packages
    /// the server encrypted internally but never sent; used for MAC-candidate
    /// enumeration in `decrypt_checked`.
    dec_total: u32,
    /// totalEncryptCount — direction-level monotonic counter, NOT reset by key
    /// updates; used by the SECURE_CHECKSUM MAC variant.
    total_enc: u32,
    /// TS_ENC_SECURE_CHECKSUM negotiation result (server Demand Active
    /// extraFlags bit 0x10); set once the Demand Active PDU has been processed.
    pub secure_checksum: bool,
}

impl core::fmt::Debug for RdpSecurity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RdpSecurity")
            .field("method", &self.method)
            .field("key_len", &self.key_len)
            .field("enc_use", &self.enc_use)
            .field("dec_use", &self.dec_use)
            .field("dec_total", &self.dec_total)
            .field("total_enc", &self.total_enc)
            .field("secure_checksum", &self.secure_checksum)
            .finish_non_exhaustive()
    }
}

impl RdpSecurity {
    /// Derive the key material (client perspective) per MS-RDPBCGR 5.3.2 /
    /// FreeRDP `security_establish_keys`.
    ///
    /// `method` is the server-selected `encryptionMethod` from the GCC
    /// SC_SECURITY block.
    pub fn new(client_random: &[u8], server_random: &[u8], method: u32) -> Self {
        let pre = [
            client_random.get(..24).unwrap_or(client_random),
            server_random.get(..24).unwrap_or(server_random),
        ]
        .concat();

        let premaster_hash = |tag: &[u8]| -> [u8; 16] {
            md5(&[
                pre.as_slice(),
                &sha1(&[tag, &pre, client_random, server_random].concat())[..],
            ]
            .concat())
        };
        let salted_hash = |master: &[u8], tag: &[u8]| -> [u8; 16] {
            md5(&[master, &sha1(&[tag, master, client_random, server_random].concat())[..]].concat())
        };

        // MasterSecret = PremasterHash('A' + 'BB' + 'CCC')
        let mut master = Vec::with_capacity(48);
        master.extend_from_slice(&premaster_hash(b"A"));
        master.extend_from_slice(&premaster_hash(b"BB"));
        master.extend_from_slice(&premaster_hash(b"CCC"));

        // SessionKeyBlob = MasterHash('X' + 'YY' + 'ZZZ')
        let mut blob = Vec::with_capacity(48);
        blob.extend_from_slice(&salted_hash(&master, b"X"));
        blob.extend_from_slice(&salted_hash(&master, b"YY"));
        blob.extend_from_slice(&salted_hash(&master, b"ZZZ"));

        let mut key_len = 16usize;
        // Client view: encrypt key = MD5(blob[32:48] || c || s), decrypt = MD5(blob[16:32] || c || s).
        let mut sign_key = blob[0..16].to_vec();
        let mut encrypt_key = md5(&[&blob[32..48], client_random, server_random].concat()).to_vec();
        let mut decrypt_key = md5(&[&blob[16..32], client_random, server_random].concat()).to_vec();

        // 40-bit salts the first 3 bytes, 56-bit the first 1 (FreeRDP security.c).
        let salt_len = if method & ENCRYPTION_FLAG_40BIT != 0 {
            3
        } else if method & ENCRYPTION_FLAG_56BIT != 0 {
            1
        } else {
            0
        };
        let salt = SALT_40;
        if salt_len != 0 {
            sign_key[..salt_len].copy_from_slice(&salt[..salt_len]);
            encrypt_key[..salt_len].copy_from_slice(&salt[..salt_len]);
            decrypt_key[..salt_len].copy_from_slice(&salt[..salt_len]);
            key_len = 8;
        }

        Self {
            method,
            key_len,
            sign_key,
            salt,
            salt_len,
            enc_update_key: encrypt_key.clone(),
            enc_rc4: Rc4Stream::new(&encrypt_key[..key_len]),
            encrypt_key,
            dec_update_key: decrypt_key.clone(),
            dec_rc4: Rc4Stream::new(&decrypt_key[..key_len]),
            decrypt_key,
            enc_use: 0,
            dec_use: 0,
            dec_total: 0,
            total_enc: 0,
            secure_checksum: false,
        }
    }

    pub fn method(&self) -> u32 {
        self.method
    }

    fn update_key(&self, key: &[u8], update_key: &[u8]) -> Vec<u8> {
        let kl = self.key_len;
        let sha = sha1(&[&update_key[..kl], &PAD1[..], &key[..kl]].concat());
        let mut out = md5(&[&update_key[..kl], &PAD2[..], &sha].concat());
        // FreeRDP security_key_update: RC4-encrypt the MD5 result with itself, then re-salt.
        let mut encrypted = Rc4Stream::new(&out[..kl]);
        let head = encrypted.crypt(&out[..kl]);
        out[..kl].copy_from_slice(&head);
        if self.salt_len != 0 {
            out[..self.salt_len].copy_from_slice(&self.salt[..self.salt_len]);
        }
        out.to_vec()
    }

    /// PDU MAC (FreeRDP `security_mac_signature`): MD5(signKey + PAD2 +
    /// SHA1(signKey + PAD1 + len + data))[:8]. When `count` is given, the
    /// SECURE_CHECKSUM variant appends the little-endian counter to the SHA1
    /// tail (the GenerateMACSignature variant with fIncludeEncryptionCount).
    pub fn mac(&self, data: &[u8], count: Option<u32>) -> [u8; 8] {
        // The MAC key is the sign key truncated to the effective RC4 key
        // length (FreeRDP security_mac_signature uses sign_key with
        // rc4_key_len; xrdp's xrdp_sec_sign does the same). Only 128-bit uses
        // the full 16 bytes.
        let k = &self.sign_key[..self.key_len];
        let mut sha_input = Vec::with_capacity(k.len() + PAD1.len() + 4 + data.len() + 4);
        sha_input.extend_from_slice(k);
        sha_input.extend_from_slice(&PAD1[..]);
        sha_input.extend_from_slice(&u32le(data.len() as u32));
        sha_input.extend_from_slice(data);
        if let Some(count) = count {
            sha_input.extend_from_slice(&u32le(count));
        }
        let sha = sha1(&sha_input);
        let mut md_input = Vec::with_capacity(k.len() + PAD2.len() + 20);
        md_input.extend_from_slice(k);
        md_input.extend_from_slice(&PAD2[..]);
        md_input.extend_from_slice(&sha);
        let md = md5(&md_input);
        md[..8].try_into().unwrap()
    }

    /// Encrypt a C2S payload: RC4 applies to the plaintext *after* the MAC was
    /// computed over it (MAC-then-encrypt, as observed on the wire).
    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let out = self.enc_rc4.crypt(data);
        self.enc_use += 1;
        self.total_enc += 1;
        if self.enc_use == 4096 {
            self.encrypt_key = self.update_key(&self.encrypt_key, &self.enc_update_key);
            self.enc_use = 0;
            self.enc_rc4 = Rc4Stream::new(&self.encrypt_key[..self.key_len]);
        }
        out
    }

    /// Decrypt an S2C payload, plain variant (no MAC verification).
    pub fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let out = self.dec_rc4.crypt(data);
        self.dec_use += 1;
        if self.dec_use == 4096 {
            self.decrypt_key = self.update_key(&self.decrypt_key, &self.dec_update_key);
            self.dec_use = 0;
            self.dec_rc4 = Rc4Stream::new(&self.decrypt_key[..self.key_len]);
        }
        out
    }

    /// Decrypt an S2C payload with MAC verification and keystream resync.
    ///
    /// Live-observed behaviour of Windows TermService: the server occasionally
    /// burns keystream internally without sending anything (24B right after the
    /// License PDU), so the wire position of a package can be ahead of our
    /// stream position. Since the 8-byte MAC covers the plaintext and a single
    /// point mismatch has a false-positive rate of 2^-64, we scan forward a
    /// bounded number of bytes and try both MAC variants (plain SaltedMAC and
    /// the SECURE_CHECKSUM counter variant, around the expected count ±2)
    /// until one matches.
    pub fn decrypt_checked(&mut self, cipher: &[u8], wire_mac: &[u8]) -> Vec<u8> {
        let candidates: [Option<u32>; 5] = [
            None,
            Some(self.dec_total),
            Some(self.dec_total.wrapping_sub(1)),
            Some(self.dec_total.wrapping_add(1)),
            Some(self.dec_total.wrapping_add(2)),
        ];
        let snap = self.dec_rc4.clone();
        for skip in 0..=256usize {
            let mut rc4 = snap.clone();
            if skip != 0 {
                rc4.crypt(&vec![0u8; skip]);
            }
            let pt = rc4.crypt(cipher);
            for count in candidates {
                if self.mac(&pt, count) == wire_mac {
                    self.dec_rc4 = rc4;
                    let consumed = 1 + usize::from(skip != 0);
                    self.dec_use += consumed as u32;
                    self.dec_total += consumed as u32;
                    if self.dec_use >= 4096 {
                        self.decrypt_key = self.update_key(&self.decrypt_key, &self.dec_update_key);
                        self.dec_use = 0;
                        self.dec_rc4 = Rc4Stream::new(&self.decrypt_key[..self.key_len]);
                    }
                    return pt;
                }
            }
        }
        // No MAC match: fall through and advance the stream anyway (mirrors the
        // Python reference, which logs loudly here — verify at the caller).
        self.dec_total += 1;
        self.decrypt(cipher)
    }

    /// Encrypt an S2C-direction... no-op placeholder kept for API symmetry (the
    /// client never encrypts server-direction traffic).
    pub fn total_enc(&self) -> u32 {
        self.total_enc
    }

    /// Wrap a slow-path PDU payload in the security envelope sent as the MCS
    /// `SendDataRequest` user data:
    ///
    /// `[flags u16 | SEC_ENCRYPT][pad u16][MAC 8B][RC4(payload)]`
    ///
    /// The MAC covers the plaintext (MAC-then-encrypt, as observed on the
    /// wire). With `secure_checksum` set, the SECURE_CHECKSUM counter variant
    /// is used instead of the plain MAC — field-validated on the wire as the
    /// always-on choice for message-channel uplinks and, after the Demand
    /// Active `extraFlags` handshake, for other virtual channels; I/O-channel
    /// slow-path traffic must always use the plain MAC.
    pub fn encrypt_envelope(&mut self, flags: u16, payload: &[u8], secure_checksum: bool) -> Vec<u8> {
        let count = if secure_checksum { Some(self.total_enc) } else { None };
        let mac = self.mac(payload, count);
        let body = self.encrypt(payload);

        let mut out = Vec::with_capacity(4 + mac.len() + body.len());
        out.extend_from_slice(&(flags | SEC_ENCRYPT).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&mac);
        out.extend_from_slice(&body);
        out
    }
}

/// Security-header flag bits seen on the wire (S2C envelopes included), kept
/// next to [`RdpSecurity`] for callers parsing or building envelopes.
pub const SEC_XP_VARIANT: u16 = 0x8000;

/// A cryptor shared between the connection sequence and the session layer:
/// armed by the connector once the Security Exchange is sent, then used for
/// the lifetime of the session (key streams persist across both phases).
pub type SharedSecurity = std::sync::Arc<std::sync::Mutex<RdpSecurity>>;

/// RSA-encrypt the 32-byte client random with the proprietary server
/// certificate public key (the "RSA1" blob inside ServerSecurityData).
///
/// Ground truth from live captures: modulus, plaintext and ciphertext are all
/// **little-endian** on the wire; the plaintext block is client_random (32B)
/// zero-padded to the modulus length — no PKCS#1 padding.
pub fn encrypt_client_random(server_cert: &[u8], client_random: &[u8]) -> Result<Vec<u8>, SecurityError> {
    encrypt_with_server_public_key(server_cert, client_random)
}

/// RSA-encrypt a small secret (client random, licensing premaster secret)
/// with the public key embedded in the GCC server certificate blob, using
/// the same raw little-endian modpow convention the wire expects for the
/// Security Exchange client random.
///
/// Both GCC certificate formats are supported: the proprietary "RSA1" blob
/// (legacy servers) and the X.509 certificate chain (e.g. Server 2003 with a
/// real certificate bound to the RDP listener). The raw little-endian modpow
/// convention applies to both — FreeRDP normalizes the X.509 chain the same
/// way and interoperates with these servers.
pub fn encrypt_with_server_public_key(server_cert: &[u8], secret: &[u8]) -> Result<Vec<u8>, SecurityError> {
    const CERT_CHAIN_VERSION_MASK: u32 = 0x7fff_ffff;
    const CERT_CHAIN_VERSION_PROPRIETARY: u32 = 1;
    const CERT_CHAIN_VERSION_X509: u32 = 2;

    if server_cert.len() < 4 {
        return Err(SecurityError::CertTruncated(format!(
            "blob is {} bytes, too short for the dwVersion field",
            server_cert.len()
        )));
    }
    let raw_version = u32::from_le_bytes(server_cert[..4].try_into().unwrap());
    let version = raw_version & CERT_CHAIN_VERSION_MASK;
    match version {
        CERT_CHAIN_VERSION_PROPRIETARY => encrypt_with_proprietary_key(server_cert, secret),
        CERT_CHAIN_VERSION_X509 => encrypt_with_x509_chain_key(server_cert, secret),
        _ => Err(SecurityError::CertNoPublicKey(format!(
            "unsupported certificate format version 0x{raw_version:08X}; {}",
            cert_blob_head(server_cert)
        ))),
    }
}

/// One-line diagnostic head for the certificate blob: size plus the first 32
/// bytes in hex. Appended to every parse failure so a failing Security
/// Exchange can be attributed from the desktop log alone (the WASM client's
/// tracing does not reach it).
fn cert_blob_head(blob: &[u8]) -> String {
    let head: Vec<String> = blob.iter().take(32).map(|byte| format!("{byte:02X}")).collect();
    format!("blob {}B head {}", blob.len(), head.join(" "))
}

fn encrypt_with_proprietary_key(server_cert: &[u8], secret: &[u8]) -> Result<Vec<u8>, SecurityError> {
    const RSA1_MAGIC: &[u8; 4] = b"RSA1";
    let head = cert_blob_head(server_cert);
    let pos = server_cert
        .windows(4)
        .position(|w| w == RSA1_MAGIC)
        .ok_or_else(|| {
            SecurityError::CertNoPublicKey(format!("no RSA1 key blob found (dwVersion 1); {head}"))
        })?;
    let key_len = u32::from_le_bytes(
        server_cert
            .get(pos + 4..pos + 8)
            .ok_or_else(|| {
                SecurityError::CertTruncated(format!("RSA1 keyLen overruns the blob at offset {}; {head}", pos + 4))
            })?
            .try_into()
            .unwrap(),
    ) as usize;
    let pub_exp = u32::from_le_bytes(
        server_cert
            .get(pos + 16..pos + 20)
            .ok_or_else(|| {
                SecurityError::CertTruncated(format!(
                    "RSA1 public exponent overruns the blob at offset {}; {head}",
                    pos + 16
                ))
            })?
            .try_into()
            .unwrap(),
    );
    let mod_len = key_len - 8;
    let modulus = server_cert
        .get(pos + 20..pos + 20 + mod_len)
        .ok_or_else(|| {
            SecurityError::CertTruncated(format!(
                "RSA1 modulus ({} bytes) overruns the blob at offset {}; {head}",
                mod_len,
                pos + 20
            ))
        })?;

    let m = num_bigint::BigUint::from_bytes_le(modulus);
    let e = num_bigint::BigUint::from(pub_exp);
    let mut block = secret.to_vec();
    block.resize(mod_len, 0u8);
    let b = num_bigint::BigUint::from_bytes_le(&block);
    let cipher = b.modpow(&e, &m);
    let mut out = cipher.to_bytes_le();
    out.resize(mod_len, 0u8);
    Ok(out)
}

/// RSA-encrypt `secret` with the RSA public key of the leaf certificate in
/// the GCC X.509 chain blob (`dwVersion` = 2). The blob layout is
/// `certCount u32` followed by `certCount` × (`certLen u32` + DER + 8-byte
/// padding); the last certificate is the server's leaf.
///
/// Byte conventions per FreeRDP (`cert_common.c` + `crypto.c`): modulus and
/// exponent are read big-endian straight out of the DER, the plaintext is
/// interpreted little-endian and zero-padded to the modulus length, and the
/// ciphertext comes back little-endian — the same raw-modpow shape the
/// proprietary path uses.
fn encrypt_with_x509_chain_key(server_cert: &[u8], secret: &[u8]) -> Result<Vec<u8>, SecurityError> {
    const CHAIN_HEADER_SIZE: usize = 8; // dwVersion + numCertBlobs
    const CERT_LENGTH_FIELD_SIZE: usize = 4;
    let head = cert_blob_head(server_cert);

    // [MS-RDPBCGR 2.2.1.4.3.1.1.2] X.509 Certificate Chain: numCertBlobs
    // followed by numCertBlobs × (certLen + certData) laid out back to back —
    // no inter-certificate padding (FreeRDP's certificate_read_server_x509_
    // certificate_chain walks them the same way). The last certificate is the
    // Terminal Server certificate whose key encrypts the client random.
    if server_cert.len() < CHAIN_HEADER_SIZE {
        return Err(SecurityError::CertTruncated(format!(
            "blob is {} bytes, too short for dwVersion + numCertBlobs; {head}",
            server_cert.len()
        )));
    }
    let cert_count = u32::from_le_bytes(server_cert[4..8].try_into().unwrap()) as usize;
    if cert_count == 0 {
        return Err(SecurityError::CertNoPublicKey(format!(
            "X.509 chain carries zero certificates; {head}"
        )));
    }

    let mut offset = CHAIN_HEADER_SIZE;
    let mut chain_lengths = Vec::with_capacity(cert_count);
    let mut leaf: &[u8] = &[];
    let mut leaf_offset = 0usize;
    for index in 0..cert_count {
        let cert_len = u32::from_le_bytes(
            server_cert
                .get(offset..offset + CERT_LENGTH_FIELD_SIZE)
                .ok_or_else(|| {
                    SecurityError::CertTruncated(format!(
                        "certificate #{} of {} has no room for its length field at offset {} ({}-byte blob); {}",
                        index + 1,
                        cert_count,
                        offset,
                        server_cert.len(),
                        head
                    ))
                })?
                .try_into()
                .unwrap(),
        ) as usize;
        offset += CERT_LENGTH_FIELD_SIZE;
        let cert = server_cert
            .get(offset..offset + cert_len)
            .ok_or_else(|| {
                SecurityError::CertTruncated(format!(
                    "certificate #{} of {} ({} bytes at offset {}) overruns the {}-byte blob; {}",
                    index + 1,
                    cert_count,
                    cert_len,
                    offset,
                    server_cert.len(),
                    head
                ))
            })?;
        offset += cert_len;
        chain_lengths.push(cert_len);
        leaf = cert;
        leaf_offset = offset - cert_len;
    }

    use x509_cert::der::Decode as _;
    let certificate = x509_cert::Certificate::from_der(leaf).map_err(|error| {
        SecurityError::CertNoPublicKey(format!(
            "leaf X.509 certificate ({} bytes at offset {}) failed to parse: {error}; chain lengths {chain_lengths:?}; {head}",
            leaf.len(),
            leaf_offset
        ))
    })?;
    let spki = certificate.tbs_certificate().subject_public_key_info();

    // The subjectPublicKeyInfo BIT STRING wraps an RSAPublicKey DER SEQUENCE
    // (`SEQUENCE { INTEGER modulus, INTEGER publicExponent }`). der's
    // `as_bytes` returns None while unused bits are present and excludes the
    // unused-bits octet otherwise — the RSAPublicKey follows immediately.
    let rsa_der = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| {
            SecurityError::CertNoPublicKey(format!(
                "leaf certificate SPKI BIT STRING carries unused bits; chain lengths {chain_lengths:?}; {head}"
            ))
        })?;
    let (modulus, exponent) = parse_rsa_public_key(rsa_der, &head)
        .map_err(|error| SecurityError::CertNoPublicKey(format!("{error}; {head}")))?;

    let m = num_bigint::BigUint::from_bytes_be(modulus);
    let e = num_bigint::BigUint::from_bytes_be(exponent);
    let mut block = secret.to_vec();
    block.resize(modulus.len(), 0u8);
    let b = num_bigint::BigUint::from_bytes_le(&block);
    let cipher = b.modpow(&e, &m);
    let mut out = cipher.to_bytes_le();
    out.resize(modulus.len(), 0u8);
    Ok(out)
}

/// Reads one DER TLV at `offset`, returning `(tag, value)` and advancing
/// `offset` past the whole element.
fn read_der_tlv<'a>(
    data: &'a [u8],
    offset: &mut usize,
    what: &'static str,
    context: &str,
) -> Result<(u8, &'a [u8]), SecurityError> {
    let len = data.len();
    let tag = *data.get(*offset).ok_or_else(|| {
        SecurityError::CertTruncated(format!(
            "expected the {what} at offset {offset} but the {}-byte buffer ended; {context}",
            len
        ))
    })?;
    *offset += 1;
    let length_byte = *data.get(*offset).ok_or_else(|| {
        SecurityError::CertTruncated(format!(
            "expected the {what} length byte at offset {offset} but the {}-byte buffer ended; {context}",
            len
        ))
    })?;
    *offset += 1;
    let length = if length_byte & 0x80 == 0 {
        length_byte as usize
    } else {
        let count = (length_byte & 0x7f) as usize;
        if count == 0 || count > 4 {
            return Err(SecurityError::CertTruncated(format!(
                "unsupported DER length form ({} length bytes) for the {what} at offset {}; {context}",
                count,
                *offset - 1
            )));
        }
        let mut length = 0usize;
        for _ in 0..count {
            length = (length << 8) | *data.get(*offset).ok_or(SecurityError::CertTruncated(format!(
                "DER length bytes for the {what} overrun the {}-byte buffer at offset {}; {context}",
                len, offset
            )))? as usize;
            *offset += 1;
        }
        length
    };
    let value = data.get(*offset..*offset + length).ok_or_else(|| {
        SecurityError::CertTruncated(format!(
            "the {what} ({length} bytes at offset {}) overruns the {}-byte buffer; {context}",
            offset, len
        ))
    })?;
    *offset += length;
    Ok((tag, value))
}

/// Extracts `(modulus, exponent)` from an `RSAPublicKey` DER SEQUENCE
/// (`SEQUENCE { INTEGER modulus, INTEGER publicExponent }`).
fn parse_rsa_public_key<'a>(der: &'a [u8], context: &str) -> Result<(&'a [u8], &'a [u8]), SecurityError> {
    let mut offset = 0;
    let (tag, sequence) = read_der_tlv(der, &mut offset, "RSAPublicKey SEQUENCE", context)?;
    if tag != 0x30 {
        return Err(SecurityError::CertNoPublicKey(format!(
            "expected the RSAPublicKey SEQUENCE but found tag 0x{tag:02X}; {context}"
        )));
    }

    let mut offset = 0;
    let (tag, modulus) = read_der_tlv(sequence, &mut offset, "modulus INTEGER", context)?;
    if tag != 0x02 {
        return Err(SecurityError::CertNoPublicKey(format!(
            "expected the modulus INTEGER but found tag 0x{tag:02X}; {context}"
        )));
    }
    // A positive INTEGER may carry a leading zero byte for the sign bit
    // (FreeRDP skips all leading zeros for the same reason).
    let modulus = modulus.strip_prefix(&[0u8]).unwrap_or(modulus);
    if modulus.is_empty() {
        return Err(SecurityError::CertNoPublicKey(format!(
            "the modulus INTEGER is empty; {context}"
        )));
    }

    let (tag, exponent) = read_der_tlv(sequence, &mut offset, "public exponent INTEGER", context)?;
    if tag != 0x02 {
        return Err(SecurityError::CertNoPublicKey(format!(
            "expected the public exponent INTEGER but found tag 0x{tag:02X}; {context}"
        )));
    }
    let exponent = exponent.strip_prefix(&[0u8]).unwrap_or(exponent);
    if exponent.is_empty() || exponent.len() > 4 {
        return Err(SecurityError::CertNoPublicKey(format!(
            "the public exponent INTEGER is {} bytes, expected 1-4; {context}",
            exponent.len()
        )));
    }

    Ok((modulus, exponent))
}

/// Errors.
#[derive(Debug)]
pub enum SecurityError {
    /// No RSA public key could be recovered from the server certificate blob.
    /// The payload carries the blob size, format version and parse position so
    /// the failure can be attributed from the desktop log alone.
    CertNoPublicKey(String),
    /// A structure overran the certificate blob. The payload carries the blob
    /// size, the failing offset and a hex head of the blob.
    CertTruncated(String),
    RandomTooShort,
}

impl core::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SecurityError::CertNoPublicKey(message) => {
                write!(f, "server certificate carries no RSA public key ({message})")
            }
            SecurityError::CertTruncated(message) => write!(f, "server certificate truncated ({message})"),
            SecurityError::RandomTooShort => write!(f, "client random shorter than modulus"),
        }
    }
}

impl std::error::Error for SecurityError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// RC4 correctness: the classic "Key"/"Plaintext" vector plus the first
    /// keystream bytes for the 16-byte key 0102..10 (cross-checked against a
    /// from-scratch textbook implementation; the Python `Rc4Stream` this crate
    /// was ported from produced identical bytes).
    #[test]
    fn rc4_vectors() {
        let mut rc4 = Rc4Stream::new(b"Key");
        assert_eq!(
            rc4.crypt(b"Plaintext"),
            [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]
        );
        let key: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        ];
        let mut rc4 = Rc4Stream::new(&key);
        assert_eq!(rc4.crypt(&[0u8; 8]), [0x9a, 0xc7, 0xcc, 0x9a, 0x60, 0x9d, 0x1e, 0xf7]);
    }

    #[test]
    fn mac_is_deterministic_and_8b() {
        let c = [0x11u8; 32];
        let s = [0x22u8; 32];
        let sec = RdpSecurity::new(&c, &s, ENCRYPTION_FLAG_128BIT);
        let m1 = sec.mac(b"hello", None);
        let m2 = sec.mac(b"hello", None);
        assert_eq!(m1, m2);
        assert_eq!(m1.len(), 8);
    }

    /// Differential fixture: a field-validated Python reference implementation
    /// of `RdpSecurity` (checked against live Windows TermService) was run
    /// with client_random 0x11*32, server_random 0x22*32 and produced these
    /// exact ciphertexts/MACs. The
    /// Rust port must agree byte-for-byte, including the keystream continuing
    /// across PDUs, for both the plain 128-bit schedule and the 40-bit-salted
    /// one (GCC encryptionMethod 0x1B, the real 144 negotiation).
    #[test]
    fn differential_against_python_reference() {
        let c = [0x11u8; 32];
        let s = [0x22u8; 32];
        let pt = b"The quick brown fox jumps over the lazy dog";
        for (method, ct1, ct2, mac) in [
            (
                ENCRYPTION_FLAG_128BIT,
                "73ad9f310777d0ff56d1458a4f0f669d115f7c2ac2f4b36706f6fd94586a3b0dafb0f1866d663432f10ebf",
                "b84d7a0405ab",
                "fd0f1dc6ebd35d79",
            ),
            (
                ENCRYPTION_FLAG_40BIT | ENCRYPTION_FLAG_128BIT | ENCRYPTION_FLAG_56BIT,
                "c2931e1f6af814fedebb8d3a6f5843cd9c320a65b5fdf33796b66f8289d0930a04437054885a0dac2b96bb",
                "09395fcf6a56",
                "7966996ed0fa7cdc",
            ),
        ] {
            let hex = |h: &str| {
                (0..h.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
                    .collect::<Vec<u8>>()
            };
            let mut sec = RdpSecurity::new(&c, &s, method);
            assert_eq!(sec.encrypt(pt), hex(ct1), "ct1 for method {method:#04x}");
            assert_eq!(sec.encrypt(b"second"), hex(ct2), "ct2 for method {method:#04x}");
            // Fresh engine for the MAC: encrypt() above must not matter, but a
            // new instance keeps the fixture identical to the Python run.
            assert_eq!(
                RdpSecurity::new(&c, &s, method).mac(pt, None),
                hex(mac).as_slice(),
                "mac for method {method:#04x}"
            );
        }
    }

    #[test]
    fn encrypt_roundtrip_4096() {
        let c = [0x01u8; 32];
        let s = [0x02u8; 32];
        let mut client = RdpSecurity::new(&c, &s, ENCRYPTION_FLAG_128BIT);
        // Twin engine in the server role: InitialServerEncryptSecret equals the
        // client's InitialClientDecryptSecret (MS-RDPBCGR 5.3.2), so swap both
        // key directions — only then does encrypt/decrypt round-trip.
        let mut server = RdpSecurity::new(&c, &s, ENCRYPTION_FLAG_128BIT);
        let cek = client.encrypt_key.clone();
        let cdk = client.decrypt_key.clone();
        server.encrypt_key = cdk.clone();
        server.decrypt_key = cek.clone();
        server.enc_update_key = cdk;
        server.dec_update_key = cek;
        server.enc_rc4 = Rc4Stream::new(&server.encrypt_key[..server.key_len]);
        server.dec_rc4 = Rc4Stream::new(&server.decrypt_key[..server.key_len]);

        let pt = vec![0x5au8; 100];
        // Cross the 4096-package key-update boundary in both directions and
        // keep round-tripping afterwards.
        for i in 0..4200 {
            let ct = client.encrypt(&pt);
            assert_eq!(server.decrypt(&ct), pt, "s2c iteration {i}");
            let up = server.encrypt(&pt);
            assert_eq!(client.decrypt(&up), pt, "c2s iteration {i}");
        }
    }
}

/// Fixed RSA-2048 key material generated with OpenSSL for the tests: the
/// X.509 certificate DER, the modulus (big-endian, no DER sign byte) and the
/// private exponent used to recover the secret on the other side.
const TEST_CERT_DER_HEX: &str = "3082030d308201f5a00302010202144f78e76f54a92e91ad7d9e0515719eb7ac6ac174300d06092a864886f70d01010b050030163114301206035504030c0b7264707365632d74657374301e170d3236313131393031343132395a170d3336313131363031343132395a30163114301206035504030c0b7264707365632d7465737430820122300d06092a864886f70d01010105000382010f003082010a0282010100b533e82804e1f7cf9a5bdb827e3deaaf178cbcc927b54d2288c580602f13966e5a03645c040b2d0efc3bed37e3a1b488de7a0d7105ae28975641f2e563f9a646de7af9c1b0f88c097d6f540889d1670eacef0a668d02971e446f35ca930fe11063f965bab49b852cfc922e83de403442e925093195aac0d6fbcf1879bfcd6082d265b50c8dc1d2e7d0694638a92fd98fb722e45d8a0964b16226ed1e87778e58285583f5fd89033e434741f847325558502c1f67f3e02371847903264d5345b458b27a7ab97e35427e2a5d0276bb1707c5e53709ec562aa3b8f65ab384ce4e56ee0b82a3e36570c8e38c372f23e19a6c86dd8270758768e1e7a9e9bd233a36230203010001a3533051301d0603551d0e041604140e84db0b172bc9cdfe3cf1b6018971509c98c752301f0603551d230418301680140e84db0b172bc9cdfe3cf1b6018971509c98c752300f0603551d130101ff040530030101ff300d06092a864886f70d01010b05000382010100626881f49af3ff317ad6c6f255433c6a7c40685dad536f357a14a07b6693eefcfc8ae8a873d76b5148ffdd97e9788211303a308002454642ed0ae14a3ff3ff3c2449e20f320846253b29a76b80d9fc575dab257dc476a5a54490ade8979a71cc719149e8549248f0fc4a2dd445b223c90c60fa458f7e3303ef4e97c83d85e1a898dcd39bd0574848c8b270a8bf734e035e6202854e14d3f0003f81ef2d3702a2ff445e82e5d13bf2cbc0ab8e3b5608a6602d0a84ef99d27ea4b1eba95f6fa005ffb154cf8dec60c003484a64c39e92bfd231b5dda1351115fefbc6de06fae0c727b1c672cfe2ec66d9ccf6d515c8131268eb03ae4c91a6e93dca19034c380395";
const TEST_N_HEX: &str = "b533e82804e1f7cf9a5bdb827e3deaaf178cbcc927b54d2288c580602f13966e5a03645c040b2d0efc3bed37e3a1b488de7a0d7105ae28975641f2e563f9a646de7af9c1b0f88c097d6f540889d1670eacef0a668d02971e446f35ca930fe11063f965bab49b852cfc922e83de403442e925093195aac0d6fbcf1879bfcd6082d265b50c8dc1d2e7d0694638a92fd98fb722e45d8a0964b16226ed1e87778e58285583f5fd89033e434741f847325558502c1f67f3e02371847903264d5345b458b27a7ab97e35427e2a5d0276bb1707c5e53709ec562aa3b8f65ab384ce4e56ee0b82a3e36570c8e38c372f23e19a6c86dd8270758768e1e7a9e9bd233a3623";
const TEST_D_HEX: &str = "4c4eeab287b3dd9748caec3b1d0cd81b1a50c363f6dbebfae21c423ebf3481824157f258a9bf471f6b6b952f97260f102098c7b6540d0ebd04af4b29fd1b3241e0096bca7ccb7eb5b46440c043c1b2a3c481fa204bbbce86098dc7da626a2a7eab8b68a2e2d227985558fe4bbc39cf886a0495c592e0d0caf84a33657a37742f8cf9fdebb8ab7d90efb3b3bf38e5f3d0beb8eea339a03a8fb9ac42d81ed5d904f2ea5130cd1d79e4f4d237f8b76a934d1e4d1d065f497a6666f44ab62bcab21f2bbebe208e508fd8ca97fa0ab09437e6b4ac86b9e24104f6770a0df5e269f322cea3ac09000e2222d683b2170760dba5703bc76de2a770045f61466acf22c571";

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[cfg(test)]
mod x509_tests {
    use super::*;

    /// Builds an X.509 chain blob (dwVersion = 2) carrying one certificate.
    fn x509_chain_blob(cert_der: &[u8]) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.extend_from_slice(&2u32.to_le_bytes());
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&(cert_der.len() as u32).to_le_bytes());
        blob.extend_from_slice(cert_der);
        blob
    }

    /// The X.509 chain path must round-trip under the wire's little-endian
    /// modpow convention: whatever the client encrypts with the leaf key, the
    /// private-key holder recovers byte for byte.
    #[test]
    fn x509_chain_round_trip() {
        let cert_der = unhex(TEST_CERT_DER_HEX);
        let blob = x509_chain_blob(&cert_der);
        let secret: Vec<u8> = (0..32u8).collect();
        let cipher = encrypt_with_server_public_key(&blob, &secret).expect("encrypt must succeed on a valid X.509 chain");

        let n = num_bigint::BigUint::from_bytes_be(&unhex(TEST_N_HEX));
        let d = num_bigint::BigUint::from_bytes_be(&unhex(TEST_D_HEX));
        let c = num_bigint::BigUint::from_bytes_le(&cipher);
        let x = c.modpow(&d, &n);
        let recovered = x.to_bytes_le();
        assert_eq!(&recovered[..secret.len()], &secret[..]);
    }

    /// The proprietary RSA1 path must round-trip the same way (the blob's
    /// modulus is stored little-endian on the wire).
    #[test]
    fn proprietary_round_trip() {
        let n = num_bigint::BigUint::from_bytes_be(&unhex(TEST_N_HEX));
        let n_wire_le = n.to_bytes_le();

        let mut blob = Vec::new();
        blob.extend_from_slice(&1u32.to_le_bytes()); // dwVersion = proprietary
        blob.extend_from_slice(b"RSA1");
        blob.extend_from_slice(&((n_wire_le.len() + 8) as u32).to_le_bytes()); // keyLen
        blob.extend_from_slice(&((n_wire_le.len() * 8) as u32).to_le_bytes()); // bitLen
        blob.extend_from_slice(&((n_wire_le.len() - 1) as u32).to_le_bytes()); // dataLen
        blob.extend_from_slice(&65537u32.to_le_bytes()); // pubExp
        blob.extend_from_slice(&n_wire_le); // modulus

        let secret: Vec<u8> = (0..32u8).collect();
        let cipher = encrypt_with_server_public_key(&blob, &secret).expect("encrypt must succeed on a valid RSA1 blob");

        let d = num_bigint::BigUint::from_bytes_be(&unhex(TEST_D_HEX));
        let c = num_bigint::BigUint::from_bytes_le(&cipher);
        let x = c.modpow(&d, &n);
        let recovered = x.to_bytes_le();
        assert_eq!(&recovered[..secret.len()], &secret[..]);
    }

    /// A single-certificate chain whose length field claims a shorter blob
    /// must surface the truncation with blob diagnostics, not panic.
    #[test]
    fn truncated_blob_reports_diagnostics() {
        let blob = vec![2u8, 0, 0, 0, 1, 0, 0, 0, 0xFF, 0, 0, 0];
        let error = encrypt_with_server_public_key(&blob, &[0u8; 32]).unwrap_err();
        assert!(matches!(error, SecurityError::CertTruncated(_)));
        assert!(error.to_string().contains("blob 12B"));
    }

    /// A chain whose leaf certificate is not valid DER surfaces the parse
    /// failure with the blob diagnostics (instead of a bare error).
    #[test]
    fn x509_leaf_parse_failure_carries_context() {
        let mut blob = x509_chain_blob(&unhex(TEST_CERT_DER_HEX));
        // Replace the leaf certificate with a short garbage buffer, keeping
        // the declared length field consistent so the chain walk succeeds
        // and the failure lands in the leaf parse.
        let leaf_start = blob.len() - unhex(TEST_CERT_DER_HEX).len();
        for byte in &mut blob[leaf_start..] {
            *byte = 0xA5;
        }
        let error = encrypt_with_server_public_key(&blob, &[0u8; 32]).unwrap_err();
        assert!(matches!(error, SecurityError::CertNoPublicKey(_)));
        assert!(error.to_string().contains("blob"));
    }
}

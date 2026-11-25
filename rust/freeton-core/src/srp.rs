use std::hint::black_box;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use num_bigint::BigUint;
use pgp::composed::{CleartextSignedMessage, Deserializable as _, SignedPublicKey};
use pgp::types::KeyDetails as _;
use pkcs8::DecodePrivateKey as _;
use rand::Rng as _;
use sha2::{Digest as _, Sha512};
use thiserror::Error;
use zeroize::Zeroizing;

/// Expected lowercase hex fingerprint of Proton's embedded SRP modulus signing key.
pub const SRP_MODULUS_FINGERPRINT: &str = "248097092b458509c508dac0350585c4e9518f26";

/// Proton's embedded Ed25519 OpenPGP public key used to verify SRP modulus payloads.
pub const SRP_MODULUS_KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\
xjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm\n\
L8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ\n\
BwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U\n\
MnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat\n\
Sv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE\n\
kSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF\n\
hcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU\n\
WO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE\n\
=Y4Mw\n\
-----END PGP PUBLIC KEY BLOCK-----";

const SRP_WIDTH: usize = 256;
const SRP_MODULUS_BITS: u64 = (SRP_WIDTH * 8) as u64;
const BCRYPT_COST: u32 = 10;

/// Errors returned by Proton SRP proof generation, OpenPGP modulus verification, and key derivation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SrpError {
    #[error("Vui lòng nhập username và mật khẩu Proton.")]
    MissingCredentials,
    #[error("Tài khoản đang dùng phiên bản xác thực Proton không được hỗ trợ ({0}).")]
    UnsupportedVersion(u8),
    #[error("Không thể xác minh chữ ký OpenPGP của modulus SRP Proton.")]
    InvalidModulusSignature,
    #[error("Modulus SRP Proton không hợp lệ: {0}")]
    InvalidModulus(String),
    #[error("Dữ liệu thử thách SRP từ Proton không hợp lệ: {0}")]
    InvalidChallenge(String),
    #[error("Lỗi tạo khóa băm bcrypt cho SRP: {0}")]
    BcryptError(String),
    #[error("Khóa Ed25519 PKCS#8 PEM không hợp lệ: {0}")]
    InvalidPrivateKeyPem(String),
}

/// SRP challenge parameters returned by Proton's `/auth/info` endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrpChallenge {
    pub version: u8,
    pub modulus_armored: String,
    pub server_ephemeral_b64: String,
    pub salt_b64: String,
}

/// Computed client SRP proof values to submit to Proton's `/auth` endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrpProof {
    pub client_ephemeral_b64: String,
    pub client_proof_b64: String,
    pub expected_server_proof: Vec<u8>,
}

/// Verifies Proton's OpenPGP cleartext-signed SRP modulus and returns its 256-byte little-endian
/// representation alongside the parsed 2048-bit odd `BigUint`.
pub fn verify_and_read_modulus(armored: &str) -> Result<([u8; 256], BigUint), SrpError> {
    verify_and_read_modulus_with_key(armored, SRP_MODULUS_KEY, SRP_MODULUS_FINGERPRINT)
}

fn verify_and_read_modulus_with_key(
    armored: &str,
    public_key_armored: &str,
    expected_fingerprint: &str,
) -> Result<([u8; 256], BigUint), SrpError> {
    let (public_key, _) = SignedPublicKey::from_string(public_key_armored)
        .map_err(|_| SrpError::InvalidModulusSignature)?;
    let fingerprint = format!("{:x}", public_key.fingerprint());
    if !fingerprint.eq_ignore_ascii_case(expected_fingerprint) {
        return Err(SrpError::InvalidModulusSignature);
    }

    let (message, _) = CleartextSignedMessage::from_string(armored)
        .map_err(|_| SrpError::InvalidModulusSignature)?;
    if message.signatures().is_empty() {
        return Err(SrpError::InvalidModulusSignature);
    }
    message
        .verify(&public_key)
        .map_err(|_| SrpError::InvalidModulusSignature)?;

    let signed_text = message.signed_text();
    let compact_b64: String = signed_text
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();
    if compact_b64.is_empty() {
        return Err(SrpError::InvalidModulus("Empty modulus payload".to_owned()));
    }

    let decoded = STANDARD
        .decode(&compact_b64)
        .map_err(|err| SrpError::InvalidModulus(format!("Invalid modulus base64: {err}")))?;
    let modulus_bytes: [u8; SRP_WIDTH] = decoded.try_into().map_err(|bytes: Vec<u8>| {
        SrpError::InvalidModulus(format!(
            "Expected {SRP_WIDTH}-byte modulus, got {} bytes",
            bytes.len()
        ))
    })?;

    let modulus = bigint_from_le(&modulus_bytes);
    if modulus.bits() != SRP_MODULUS_BITS || !modulus.bit(0) {
        return Err(SrpError::InvalidModulus(
            "Modulus must be an odd 2048-bit integer".to_owned(),
        ));
    }

    Ok((modulus_bytes, modulus))
}

/// Computes Proton SRP v3/v4 client ephemeral (`A`), client proof (`M1`), and expected server proof
/// (`M2`) for the given challenge and credentials.
pub fn create_srp_proof(
    challenge: &SrpChallenge,
    username: &str,
    password: &str,
) -> Result<SrpProof, SrpError> {
    let mut random = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(&mut *random);
    random[31] |= 0x80;
    create_srp_proof_with_random(challenge, username, password, &random)
}

fn create_srp_proof_with_random(
    challenge: &SrpChallenge,
    username: &str,
    password: &str,
    client_secret_bytes: &[u8; 32],
) -> Result<SrpProof, SrpError> {
    if username.is_empty() || password.is_empty() {
        return Err(SrpError::MissingCredentials);
    }
    if challenge.version != 3 && challenge.version != 4 {
        return Err(SrpError::UnsupportedVersion(challenge.version));
    }

    let (modulus_bytes, modulus) = verify_and_read_modulus(&challenge.modulus_armored)?;
    create_srp_proof_from_modulus(
        challenge,
        password,
        &modulus_bytes,
        &modulus,
        client_secret_bytes,
    )
}

fn create_srp_proof_from_modulus(
    challenge: &SrpChallenge,
    password: &str,
    modulus_bytes: &[u8; SRP_WIDTH],
    modulus: &BigUint,
    client_secret_bytes: &[u8; 32],
) -> Result<SrpProof, SrpError> {
    let server_ephemeral_vec = STANDARD
        .decode(challenge.server_ephemeral_b64.trim())
        .map_err(|err| {
            SrpError::InvalidChallenge(format!("Invalid ServerEphemeral base64: {err}"))
        })?;
    let server_ephemeral_bytes: [u8; SRP_WIDTH] =
        server_ephemeral_vec.try_into().map_err(|bytes: Vec<u8>| {
            SrpError::InvalidChallenge(format!(
                "ServerEphemeral must be {SRP_WIDTH} bytes, got {} bytes",
                bytes.len()
            ))
        })?;

    let salt = STANDARD
        .decode(challenge.salt_b64.trim())
        .map_err(|err| SrpError::InvalidChallenge(format!("Invalid Salt base64: {err}")))?;
    if salt.len() < 10 {
        return Err(SrpError::InvalidChallenge(format!(
            "Salt must be at least 10 bytes, got {} bytes",
            salt.len()
        )));
    }

    let server_ephemeral = bigint_from_le(&server_ephemeral_bytes);
    if (&server_ephemeral % modulus) == BigUint::ZERO {
        return Err(SrpError::InvalidChallenge(
            "ServerEphemeral is congruent to 0 mod N".to_owned(),
        ));
    }

    let mut extended_salt = Zeroizing::new(Vec::with_capacity(salt.len() + 6));
    extended_salt.extend_from_slice(&salt);
    extended_salt.extend_from_slice(b"proton");
    let salt_16: [u8; 16] = extended_salt[..16]
        .try_into()
        .map_err(|_| SrpError::InvalidChallenge("Extended salt must be 16 bytes".to_owned()))?;

    // Proton hashes with the $2y$ marker and feeds the full 60-character bcrypt string into PMHash.
    // Using $2b$ instead of $2y$ produces a different SRP verifier.
    let bcrypt_parts = bcrypt::hash_with_salt(password.as_bytes(), BCRYPT_COST, salt_16)
        .map_err(|err| SrpError::BcryptError(err.to_string()))?;
    let bcrypt_hash = Zeroizing::new(bcrypt_parts.format_for_version(bcrypt::Version::TwoY));

    srp_proof_from_bcrypt_hash(
        modulus_bytes,
        modulus,
        &server_ephemeral_bytes,
        &server_ephemeral,
        client_secret_bytes,
        &bcrypt_hash,
    )
}

fn srp_proof_from_bcrypt_hash(
    modulus_bytes: &[u8; SRP_WIDTH],
    modulus: &BigUint,
    server_ephemeral_bytes: &[u8; SRP_WIDTH],
    server_ephemeral: &BigUint,
    client_secret_bytes: &[u8; 32],
    bcrypt_hash: &str,
) -> Result<SrpProof, SrpError> {
    let mut secret_arr = Zeroizing::new(*client_secret_bytes);
    secret_arr[31] |= 0x80;
    let client_secret = bigint_from_le(&*secret_arr);

    let g = BigUint::from(2u8);
    let client_ephemeral = g.modpow(&client_secret, modulus);
    let client_ephemeral_bytes = bigint_to_le(&client_ephemeral)?;
    let g_bytes = bigint_to_le(&g)?;

    let k = bigint_from_le(&pm_hash_parts(&[&g_bytes, modulus_bytes]));
    let u = bigint_from_le(&pm_hash_parts(&[
        &client_ephemeral_bytes,
        server_ephemeral_bytes,
    ]));
    if u == BigUint::ZERO {
        return Err(SrpError::InvalidChallenge(
            "Scrambling parameter u cannot be zero".to_owned(),
        ));
    }

    let password_key_input =
        Zeroizing::new(concat_slices(&[bcrypt_hash.as_bytes(), modulus_bytes]));
    let password_key = bigint_from_le(&pm_hash(&password_key_input));
    let verifier = g.modpow(&password_key, modulus);

    let kv = (&k * &verifier) % modulus;
    let b_mod = server_ephemeral % modulus;
    let base = if b_mod >= kv {
        b_mod - kv
    } else {
        modulus + b_mod - kv
    };

    let exponent = client_secret + (u * password_key);
    let shared_secret = base.modpow(&exponent, modulus);
    let shared_key = Zeroizing::new(bigint_to_le(&shared_secret)?);

    let client_proof = pm_hash_parts(&[
        &client_ephemeral_bytes,
        server_ephemeral_bytes,
        &*shared_key,
    ]);
    let expected_server_proof =
        pm_hash_parts(&[&client_ephemeral_bytes, &client_proof, &*shared_key]).to_vec();

    Ok(SrpProof {
        client_ephemeral_b64: STANDARD.encode(client_ephemeral_bytes),
        client_proof_b64: STANDARD.encode(client_proof),
        expected_server_proof,
    })
}

/// Verifies Proton's `ServerProof` response in constant time against the locally derived proof.
pub fn verify_server_proof(expected: &[u8], actual_b64: &str) -> bool {
    let Ok(actual) = STANDARD.decode(actual_b64.trim()) else {
        return false;
    };
    if expected.len() != actual.len() {
        return false;
    }

    let mut diff = 0u8;
    for (&lhs, &rhs) in expected.iter().zip(actual.iter()) {
        diff |= lhs ^ rhs;
    }
    black_box(diff) == 0
}

/// Derives a base64-encoded X25519 WireGuard private key from an Ed25519 PKCS#8 PEM private key
/// via `SHA-512(seed)[..32]` with Curve25519 scalar clamping.
pub fn ed25519_pem_to_wireguard_privkey(priv_pem: &str) -> Result<String, SrpError> {
    let signing_key = SigningKey::from_pkcs8_pem(priv_pem.trim())
        .map_err(|err| SrpError::InvalidPrivateKeyPem(err.to_string()))?;
    let seed = Zeroizing::new(signing_key.to_bytes());
    let digest = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(*seed)));

    let mut clamped = Zeroizing::new([0u8; 32]);
    clamped.copy_from_slice(&digest[..32]);
    clamped[0] &= 0xF8;
    clamped[31] &= 0x7F;
    clamped[31] |= 0x40;

    Ok(STANDARD.encode(*clamped))
}

fn concat_slices(parts: &[&[u8]]) -> Vec<u8> {
    let total_len = parts.iter().map(|part| part.len()).sum();
    let mut out = Vec::with_capacity(total_len);
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

fn pm_hash(bytes: &[u8]) -> [u8; SRP_WIDTH] {
    pm_hash_parts(&[bytes])
}

fn pm_hash_parts(parts: &[&[u8]]) -> [u8; SRP_WIDTH] {
    let mut output = [0u8; SRP_WIDTH];
    for round in 0u8..4 {
        let mut hasher = Sha512::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.update([round]);
        let digest = hasher.finalize();
        let start = usize::from(round) * 64;
        output[start..start + 64].copy_from_slice(&digest);
    }
    output
}

#[cfg(test)]
fn encode_proton_bcrypt_salt(salt: &[u8; 16]) -> String {
    bcrypt::BASE_64.encode(salt)
}

fn bigint_from_le(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_le(bytes)
}

fn bigint_to_le(value: &BigUint) -> Result<[u8; SRP_WIDTH], SrpError> {
    let raw = value.to_bytes_le();
    if raw.len() > SRP_WIDTH {
        return Err(SrpError::InvalidChallenge(format!(
            "SRP integer exceeds {SRP_WIDTH} bytes ({} bytes)",
            raw.len()
        )));
    }
    let mut out = [0u8; SRP_WIDTH];
    out[..raw.len()].copy_from_slice(&raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::composed::SignedKeyDetails;
    use pgp::crypto::{
        ed25519::{Mode, SecretKey as PgpEd25519SecretKey},
        eddsa_legacy::SecretKey as PgpEddsaLegacySecretKey,
        hash::HashAlgorithm,
        public_key::PublicKeyAlgorithm,
    };
    use pgp::packet::{
        PubKeyInner, PublicKey as PgpPublicKey, SecretKey as PgpSecretKey, SignatureConfig,
        SignatureType, Subpacket, SubpacketData,
    };
    use pgp::types::{
        KeyVersion, Password, PlainSecretParams, PublicParams, SecretParams, Timestamp,
    };

    fn build_test_ed25519_pgp_key_and_signed_modulus(
        modulus_bytes: &[u8],
    ) -> (String, String, String) {
        let secret = PgpEd25519SecretKey::try_from_bytes([0x42u8; 32], Mode::EdDSALegacy)
            .expect("valid Ed25519 secret");
        let public_params = PublicParams::EdDSALegacy((&secret).into());
        let plain_secret = PlainSecretParams::EdDSALegacy(PgpEddsaLegacySecretKey::Ed25519(secret));

        let pub_inner = PubKeyInner::new(
            KeyVersion::V4,
            PublicKeyAlgorithm::EdDSALegacy,
            Timestamp::from_secs(1_700_000_000),
            None,
            public_params,
        )
        .expect("valid v4 pubkey inner");
        let primary_pub = PgpPublicKey::from_inner(pub_inner).expect("valid pubkey packet");
        let secret_key = PgpSecretKey::new(primary_pub.clone(), SecretParams::Plain(plain_secret))
            .expect("valid secret key packet");

        let signed_pub = SignedPublicKey::new(
            primary_pub,
            SignedKeyDetails::new(vec![], vec![], vec![], vec![]),
            vec![],
        );
        let pub_armored = signed_pub
            .to_armored_string(None.into())
            .expect("armored public key");
        let fingerprint = format!("{:x}", signed_pub.fingerprint());

        let b64 = STANDARD.encode(modulus_bytes);
        let wrapped = b64
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).expect("ascii base64"))
            .collect::<Vec<_>>()
            .join("\n");

        let mut config = SignatureConfig::v4(
            SignatureType::Text,
            PublicKeyAlgorithm::EdDSALegacy,
            HashAlgorithm::Sha512,
        );
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                1_700_000_100,
            )))
            .expect("creation time subpacket"),
            Subpacket::regular(SubpacketData::IssuerFingerprint(signed_pub.fingerprint()))
                .expect("issuer fingerprint subpacket"),
        ];
        config.unhashed_subpackets =
            vec![
                Subpacket::regular(SubpacketData::IssuerKeyId(signed_pub.legacy_key_id()))
                    .expect("issuer key id subpacket"),
            ];

        let cleartext =
            CleartextSignedMessage::new(&wrapped, config, &secret_key, &Password::empty())
                .expect("cleartext signature");
        let armored_msg = cleartext
            .to_armored_string(None.into())
            .expect("armored cleartext message");

        (pub_armored, fingerprint, armored_msg)
    }

    fn sample_odd_2048_modulus_bytes() -> [u8; 256] {
        // Construct a 2048-bit odd integer in little-endian representation:
        // bit 0 = 1 (odd), bit 2047 = 1 (2048-bit).
        let mut bytes = [0xA5u8; 256];
        bytes[0] |= 0x01;
        bytes[255] |= 0x80;
        bytes
    }

    #[test]
    fn test_rejects_unsigned_or_tampered_modulus() {
        let unsigned = "not a pgp signed message";
        assert_eq!(
            verify_and_read_modulus(unsigned),
            Err(SrpError::InvalidModulusSignature)
        );

        let tampered = "-----BEGIN PGP SIGNED MESSAGE-----\n\
Hash: SHA512\n\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
-----BEGIN PGP SIGNATURE-----\n\n\
iHUEARYKAB0WIQQkgJcJK0WFCcUI2sA1BYXE6VGJpgUCXAHLgxAKCRA1BYXE6VGJ\n\
pgAAAQAAAP9tamperedtamperedtamperedtamperedtamperedtamperedtamp\n\
=AAAA\n\
-----END PGP SIGNATURE-----";
        assert_eq!(
            verify_and_read_modulus(tampered),
            Err(SrpError::InvalidModulusSignature)
        );
    }

    #[test]
    fn test_verify_and_read_modulus_positive_signature_and_validation() {
        // Confirm embedded Proton key parses, has valid self-bindings, and matches pinned fingerprint.
        let (proton_pub, _) =
            SignedPublicKey::from_string(SRP_MODULUS_KEY).expect("embedded Proton key parses");
        proton_pub
            .verify_bindings()
            .expect("embedded Proton key self-bindings verify");
        assert_eq!(
            format!("{:x}", proton_pub.fingerprint()),
            SRP_MODULUS_FINGERPRINT
        );

        // Positive OpenPGP v4 EdDSALegacy cleartext verification path with wrapped base64 lines.
        let expected_bytes = sample_odd_2048_modulus_bytes();
        let (test_pub, test_fp, armored_msg) =
            build_test_ed25519_pgp_key_and_signed_modulus(&expected_bytes);

        let (parsed_bytes, parsed_big) =
            verify_and_read_modulus_with_key(&armored_msg, &test_pub, &test_fp)
                .expect("valid v4 Ed25519 cleartext signature verifies");
        assert_eq!(parsed_bytes, expected_bytes);
        assert_eq!(parsed_big.bits(), 2048);
        assert!(parsed_big.bit(0));

        // Signature from a non-Proton key must be rejected by verify_and_read_modulus.
        assert_eq!(
            verify_and_read_modulus(&armored_msg),
            Err(SrpError::InvalidModulusSignature)
        );

        // Modifying a single character in the signed payload invalidates the cryptographic signature.
        let tampered_msg = armored_msg.replacen("paWl", "paWm", 1);
        assert_ne!(tampered_msg, armored_msg);
        assert_eq!(
            verify_and_read_modulus_with_key(&tampered_msg, &test_pub, &test_fp),
            Err(SrpError::InvalidModulusSignature)
        );

        // Validly signed even modulus must be rejected as an invalid modulus.
        let mut even_bytes = sample_odd_2048_modulus_bytes();
        even_bytes[0] &= !0x01;
        let (even_pub, even_fp, even_msg) =
            build_test_ed25519_pgp_key_and_signed_modulus(&even_bytes);
        assert!(matches!(
            verify_and_read_modulus_with_key(&even_msg, &even_pub, &even_fp),
            Err(SrpError::InvalidModulus(_))
        ));

        // Validly signed <2048-bit modulus (top bit zero) must be rejected.
        let mut short_bits = sample_odd_2048_modulus_bytes();
        short_bits[255] &= 0x7f;
        let (short_pub, short_fp, short_msg) =
            build_test_ed25519_pgp_key_and_signed_modulus(&short_bits);
        assert!(matches!(
            verify_and_read_modulus_with_key(&short_msg, &short_pub, &short_fp),
            Err(SrpError::InvalidModulus(_))
        ));

        // Mismatched fingerprint must be rejected even if the signature matches the supplied key.
        assert_eq!(
            verify_and_read_modulus_with_key(
                &armored_msg,
                &test_pub,
                "0000000000000000000000000000000000000000"
            ),
            Err(SrpError::InvalidModulusSignature)
        );
    }

    #[test]
    fn test_rejects_unsupported_srp_version() {
        let challenge = SrpChallenge {
            version: 2,
            modulus_armored: String::new(),
            server_ephemeral_b64: String::new(),
            salt_b64: String::new(),
        };
        assert_eq!(
            create_srp_proof(&challenge, "", "secret"),
            Err(SrpError::MissingCredentials)
        );
        assert_eq!(
            create_srp_proof(&challenge, "user@proton.me", ""),
            Err(SrpError::MissingCredentials)
        );
        assert_eq!(
            create_srp_proof(&challenge, "user@proton.me", "secret"),
            Err(SrpError::UnsupportedVersion(2))
        );
        let bad_sig_challenge = SrpChallenge {
            version: 4,
            modulus_armored: "unsigned".to_owned(),
            server_ephemeral_b64: String::new(),
            salt_b64: String::new(),
        };
        assert_eq!(
            create_srp_proof(&bad_sig_challenge, "user@proton.me", "secret"),
            Err(SrpError::InvalidModulusSignature)
        );
    }

    #[test]
    fn test_srp_proof_deterministic_vector_and_constant_time_server_proof() {
        let digest = pm_hash(b"proton-test-input");
        assert_eq!(digest.len(), 256);
        for round in 0u8..4 {
            let mut hasher = Sha512::new();
            hasher.update(b"proton-test-input");
            hasher.update([round]);
            let expected_chunk = hasher.finalize();
            let start = usize::from(round) * 64;
            assert_eq!(&digest[start..start + 64], expected_chunk.as_slice());
        }

        let zero_salt = [0u8; 16];
        assert_eq!(
            encode_proton_bcrypt_salt(&zero_salt),
            "......................"
        );

        let salt_16 = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let encoded_salt = encode_proton_bcrypt_salt(&salt_16);
        assert_eq!(encoded_salt.len(), 22);
        assert_eq!(encoded_salt, "./CgKyPTXlcGkYo5xL1s9u");
        assert!(encoded_salt
            .chars()
            .all(|c| c == '.' || c == '/' || c.is_ascii_alphanumeric()));

        let bcrypt_parts = bcrypt::hash_with_salt(b"hunter2", 10, salt_16).expect("bcrypt hashes");
        let bcrypt_str = bcrypt_parts.format_for_version(bcrypt::Version::TwoY);
        assert_eq!(bcrypt_str.len(), 60);
        assert!(bcrypt_str.starts_with("$2y$10$./CgKyPTXlcGkYo5xL1s9u"));
        assert!(bcrypt::verify("hunter2", &bcrypt_str).expect("bcrypt verify succeeds"));

        // Known jBCrypt vector re-formatted with Proton's $2y$ prefix.
        let jbcrypt_salt = [
            0xa3, 0x61, 0x2d, 0x8c, 0x9a, 0x37, 0xda, 0xc2, 0xf9, 0x9d, 0x94, 0xda, 0x03, 0xbd,
            0x45, 0x21,
        ];
        let jbcrypt_2y = bcrypt::hash_with_salt(b"a", 6, jbcrypt_salt)
            .expect("jbcrypt vector")
            .format_for_version(bcrypt::Version::TwoY);
        assert_eq!(
            jbcrypt_2y,
            "$2y$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe"
        );

        let mut le_bytes = [0u8; 256];
        le_bytes[0] = 0x01;
        le_bytes[127] = 0x5a;
        le_bytes[255] = 0x81;
        let big = bigint_from_le(&le_bytes);
        assert_eq!((&big & BigUint::from(0xffu8)), BigUint::from(0x01u8));
        assert_eq!(big.bits(), 2048);
        let roundtrip = bigint_to_le(&big).expect("256-byte roundtrip");
        assert_eq!(roundtrip, le_bytes);

        // Cross-verify full SRP math against an independently computed proton-srp.js vector.
        let mut vec_mod: [u8; 256] = core::array::from_fn(|i| ((i * 73 + 19) & 0xff) as u8);
        vec_mod[0] |= 0x01;
        vec_mod[255] |= 0x80;
        let vec_mod_big = bigint_from_le(&vec_mod);
        let mut vec_b: [u8; 256] = core::array::from_fn(|i| ((i * 41 + 7) & 0xff) as u8);
        vec_b[255] &= 0x7f;
        let vec_b_big = bigint_from_le(&vec_b);
        let vec_a: [u8; 32] = core::array::from_fn(|i| ((i * 37 + 11) & 0xff) as u8);
        let vec_proof = srp_proof_from_bcrypt_hash(
            &vec_mod,
            &vec_mod_big,
            &vec_b,
            &vec_b_big,
            &vec_a,
            "$2y$10$./CgKyPTXlcGkYo5xL1s9uABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
        )
        .expect("cross-verified SRP vector");
        assert_eq!(
            vec_proof.client_ephemeral_b64,
            "zqnX7ipqW9ODPt6wGIvp9xz1jboR2C7kqsk4xjD/z1vtfcDQPR8RNqFRlEGI/sYUqKLLitfNS0QBxe+wWAtM+fEuiL/6gkrzFdufcMm0sF6fLwOSorMZTP2vQsFFOJx25GcWote6FJiHQoPoqzsFFIkAxQy2B77aAlhqi+6OokMvrqerx3hqJ8I0o5cZvA0Sw372a26sBNKADEuloUdVkZaLiuYSmO1QAG7e+lhO9HZQA4AKwpXPDqxNJ5vz+RXsE7JFgNSz2Kk7ONow8n+NwCthEp7JXcD9OWQFyqf4aogJuMOL2YZLUQDoH5KSKqf0/FyZzL+4dGxmisecTK+woQ=="
        );
        assert_eq!(
            vec_proof.client_proof_b64,
            "Ir8sI5izMmX4dNOQ6MJl2tE9huuMTlepcdPuP5Fm4VVcBM+N3oLfOzZlZTsgAKEUY2/xNHynWpcF3J5eGqWaCWFYeA3pOxch43y0eGoMm+c0JYKTl+h0aUj4tKfeA9L3mnHbb3e/f7fIg6yVvnKan8GQadohyKhwALAk1dm1wT/UBU6pPNVCW0ShYRiLdfm/+Q2utEue2e8l3piFQvI0wAJ9IAQcVYDizUUmoHID2Tn8g8jNpUXDZa/R0d+mlLmhajp49eHHziAjGNBSS6/mo66hfXDGIA88/gKcAopQ1lnU3q0D8PFppqQOJWzdfh9XiIrMY1L0LAYwvbaq/iK+GA=="
        );
        assert_eq!(
            STANDARD.encode(&vec_proof.expected_server_proof),
            "YIiyrwDsyBzfYbKwpFYqZ3iDu4kVncZ/VhZfvhQiYiCZ3Ub5wgA5QFsgXWOlC3gdZEPNjAdUTyZ05tOsW2rR4EW4gPSxZoIVyDZqD6/al6kgjiVDnCghTzEH4e6bOy6o70qc0de4vkz/r2c5yTTWMx62EqLS+CjbIz2KAqNMLeymddPxaZDoCttLQ2GuzWXdGF6doho+2TwqaL+heT0U+DkJfAJbOIQvnDUH418rncajMwbCQvGWqcfQz1FukrZf/P41uVw50q2MvVFvHU/3bCBA6q2KgiwwBwM7YCg6fzknLsgsAkUyem267ToR/n9XfLgyxakYE3eriTN7kyv0sQ=="
        );

        let modulus_bytes = sample_odd_2048_modulus_bytes();
        let modulus = bigint_from_le(&modulus_bytes);
        let mut server_ephemeral = [0x33u8; 256];
        server_ephemeral[255] = 0x7f;
        let salt_10 = [0x10u8, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0];

        let challenge = SrpChallenge {
            version: 4,
            modulus_armored: String::new(),
            server_ephemeral_b64: STANDARD.encode(server_ephemeral),
            salt_b64: STANDARD.encode(salt_10),
        };
        let fixed_a = [0x55u8; 32];
        let proof_a = create_srp_proof_from_modulus(
            &challenge,
            "correct-horse",
            &modulus_bytes,
            &modulus,
            &fixed_a,
        )
        .expect("deterministic proof");
        let proof_b = create_srp_proof_from_modulus(
            &challenge,
            "correct-horse",
            &modulus_bytes,
            &modulus,
            &fixed_a,
        )
        .expect("deterministic proof repeat");
        assert_eq!(proof_a, proof_b);
        assert_eq!(
            STANDARD
                .decode(&proof_a.client_ephemeral_b64)
                .expect("valid A base64")
                .len(),
            256
        );
        assert_eq!(
            STANDARD
                .decode(&proof_a.client_proof_b64)
                .expect("valid M1 base64")
                .len(),
            256
        );
        assert_eq!(proof_a.expected_server_proof.len(), 256);

        let valid_b64 = STANDARD.encode(&proof_a.expected_server_proof);
        assert!(verify_server_proof(
            &proof_a.expected_server_proof,
            &valid_b64
        ));

        let mut flipped = proof_a.expected_server_proof.clone();
        flipped[128] ^= 0x01;
        let flipped_b64 = STANDARD.encode(&flipped);
        assert!(!verify_server_proof(
            &proof_a.expected_server_proof,
            &flipped_b64
        ));
        assert!(!verify_server_proof(
            &proof_a.expected_server_proof,
            "not-valid-base64!!!"
        ));
        assert!(!verify_server_proof(
            &proof_a.expected_server_proof,
            &STANDARD.encode([0u8; 32])
        ));
    }

    #[test]
    fn test_ed25519_pem_to_wireguard_privkey_matches_sha512_clamping() {
        // RFC 8410 PKCS#8 v1 Ed25519 private key for 32-byte seed [0, 1, ..., 31]
        let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
        let der: [u8; 48] = [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let body = STANDARD.encode(der);
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n");

        let wg_b64 = ed25519_pem_to_wireguard_privkey(&pem).expect("valid Ed25519 PEM");
        let bytes = STANDARD.decode(&wg_b64).expect("valid WireGuard base64");
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0] & 0x07, 0);
        assert_eq!(bytes[31] & 0x80, 0);
        assert_eq!(bytes[31] & 0x40, 0x40);

        let full_hash = Sha512::digest(seed);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&full_hash[..32]);
        expected[0] &= 0xF8;
        expected[31] &= 0x7F;
        expected[31] |= 0x40;
        assert_eq!(bytes.as_slice(), expected);

        assert!(matches!(
            ed25519_pem_to_wireguard_privkey("not-a-pem"),
            Err(SrpError::InvalidPrivateKeyPem(_))
        ));
    }
}

use aes_gcm::{
    Aes256Gcm, Key, Nonce as AesGcmIv,
    aead::{Aead, KeyInit},
};
use argon2::Argon2;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use libp2p::PeerId;
use libp2p::identity::{Keypair, PublicKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io::{Error as IoError, ErrorKind, Write};
use std::path::Path;

pub const IDENTITY_FILE_MAGIC: &[u8; 8] = b"AINID1\0\0";
pub const IDENTITY_SALT_LEN: usize = 16;
pub const IDENTITY_IV_LEN: usize = 12;

#[derive(Debug)]
pub enum IdentityError {
    Io(std::io::Error),
    Encoding(String),
    Crypto(String),
    InvalidPassword,
    MissingPassword,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Encoding(err) => write!(f, "{err}"),
            Self::Crypto(err) => write!(f, "{err}"),
            Self::InvalidPassword => write!(f, "identity decryption failed"),
            Self::MissingPassword => write!(f, "identity password must not be empty"),
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<std::io::Error> for IdentityError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityLoadStatus {
    Created,
    Loaded,
    MigratedPlaintext,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdentityManifest {
    pub peer_id: String,
    pub public_key_sha256: String,
    pub public_key_protobuf_base64: String,
    pub storage_format: &'static str,
}

#[derive(Debug, Clone)]
pub struct NodeIdentity {
    keypair: Keypair,
}

impl NodeIdentity {
    pub fn generate_ed25519() -> Self {
        Self {
            keypair: Keypair::generate_ed25519(),
        }
    }

    pub fn from_keypair(keypair: Keypair) -> Self {
        Self { keypair }
    }

    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    pub fn peer_id(&self) -> PeerId {
        self.keypair.public().to_peer_id()
    }

    pub fn manifest(&self) -> Result<IdentityManifest, IdentityError> {
        let peer_id = self.peer_id();
        let public_key = self.public_key_protobuf();
        let digest = Sha256::digest(&public_key);

        Ok(IdentityManifest {
            peer_id: peer_id.to_string(),
            public_key_sha256: hex::encode(digest),
            public_key_protobuf_base64: BASE64.encode(public_key),
            storage_format: "agent-identity-node/v1/aes-256-gcm+argon2",
        })
    }

    pub fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, IdentityError> {
        self.keypair
            .sign(payload)
            .map_err(|err| IdentityError::Crypto(err.to_string()))
    }

    pub fn verify(&self, payload: &[u8], signature: &[u8]) -> bool {
        self.keypair.public().verify(payload, signature)
    }

    pub fn public_key_protobuf(&self) -> Vec<u8> {
        self.keypair.public().encode_protobuf()
    }

    pub fn issue_grant(
        &self,
        subject: impl Into<String>,
        scopes: Vec<String>,
        expires_at: i64,
        request_code: impl Into<String>,
    ) -> Result<SignedCapabilityGrant, IdentityError> {
        let claims = CapabilityGrantClaims {
            schema_version: "agent-node/grant/v0alpha1".to_string(),
            issuer_peer_id: self.peer_id().to_string(),
            subject: subject.into(),
            scopes: normalize_scopes(scopes),
            issued_at: unix_timestamp(),
            expires_at,
            request_code: request_code.into(),
        };
        SignedCapabilityGrant::sign(claims, self)
    }

    pub fn verify_grant(
        &self,
        grant: &SignedCapabilityGrant,
        required_scope: &str,
        now: i64,
    ) -> Result<CapabilityGrantClaims, GrantVerificationError> {
        grant.verify_with_public_key(
            &self.keypair.public(),
            Some(&self.peer_id().to_string()),
            now,
        )?;
        if !grant.claims.has_scope(required_scope) {
            return Err(GrantVerificationError::MissingScope(
                required_scope.to_string(),
            ));
        }
        Ok(grant.claims.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityGrantClaims {
    pub schema_version: String,
    pub issuer_peer_id: String,
    pub subject: String,
    pub scopes: Vec<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub request_code: String,
}

impl CapabilityGrantClaims {
    pub fn has_scope(&self, required_scope: &str) -> bool {
        let required = required_scope.trim().to_ascii_lowercase();
        self.scopes.iter().any(|scope| {
            let scope = scope.trim().to_ascii_lowercase();
            scope == "*" || scope == required
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedCapabilityGrant {
    pub claims: CapabilityGrantClaims,
    pub signature_base64: String,
}

impl SignedCapabilityGrant {
    pub fn sign(
        claims: CapabilityGrantClaims,
        identity: &NodeIdentity,
    ) -> Result<Self, IdentityError> {
        let payload = grant_payload_bytes(&claims)?;
        let signature = identity.sign(&payload)?;
        Ok(Self {
            claims,
            signature_base64: BASE64.encode(signature),
        })
    }

    pub fn encode_base64_json(&self) -> Result<String, IdentityError> {
        serde_json::to_vec(self)
            .map(|bytes| BASE64.encode(bytes))
            .map_err(|err| IdentityError::Encoding(err.to_string()))
    }

    pub fn decode_base64_json(value: &str) -> Result<Self, GrantVerificationError> {
        let bytes = BASE64
            .decode(value.trim())
            .map_err(|err| GrantVerificationError::Malformed(err.to_string()))?;
        serde_json::from_slice(&bytes)
            .map_err(|err| GrantVerificationError::Malformed(err.to_string()))
    }

    pub fn verify_with_public_key(
        &self,
        public_key: &PublicKey,
        expected_issuer_peer_id: Option<&str>,
        now: i64,
    ) -> Result<(), GrantVerificationError> {
        if self.claims.schema_version != "agent-node/grant/v0alpha1" {
            return Err(GrantVerificationError::UnsupportedSchema(
                self.claims.schema_version.clone(),
            ));
        }
        if let Some(expected) = expected_issuer_peer_id {
            if self.claims.issuer_peer_id != expected {
                return Err(GrantVerificationError::WrongIssuer {
                    expected: expected.to_string(),
                    actual: self.claims.issuer_peer_id.clone(),
                });
            }
        }
        if now > self.claims.expires_at {
            return Err(GrantVerificationError::Expired);
        }
        if self.claims.subject.trim().is_empty() || self.claims.request_code.trim().is_empty() {
            return Err(GrantVerificationError::Malformed(
                "subject and request_code must not be empty".to_string(),
            ));
        }

        let payload = grant_payload_bytes(&self.claims)
            .map_err(|err| GrantVerificationError::Malformed(err.to_string()))?;
        let signature = BASE64
            .decode(self.signature_base64.trim())
            .map_err(|err| GrantVerificationError::Malformed(err.to_string()))?;
        if public_key.verify(&payload, &signature) {
            Ok(())
        } else {
            Err(GrantVerificationError::BadSignature)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantVerificationError {
    Malformed(String),
    UnsupportedSchema(String),
    WrongIssuer { expected: String, actual: String },
    Expired,
    MissingScope(String),
    BadSignature,
}

impl fmt::Display for GrantVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(err) => write!(f, "malformed grant: {err}"),
            Self::UnsupportedSchema(schema) => write!(f, "unsupported grant schema: {schema}"),
            Self::WrongIssuer { expected, actual } => {
                write!(f, "wrong grant issuer: expected {expected}, got {actual}")
            }
            Self::Expired => write!(f, "grant has expired"),
            Self::MissingScope(scope) => write!(f, "grant is missing required scope: {scope}"),
            Self::BadSignature => write!(f, "grant signature is invalid"),
        }
    }
}

impl std::error::Error for GrantVerificationError {}

#[derive(Debug, Clone, Copy, Default)]
pub struct LoadOptions {
    pub allow_plaintext_migration: bool,
}

pub fn load_or_create_identity(
    path: impl AsRef<Path>,
    password: &str,
    options: LoadOptions,
) -> Result<(NodeIdentity, IdentityLoadStatus), IdentityError> {
    require_password(password)?;
    let path = path.as_ref();

    if path.exists() {
        let file_bytes = fs::read(path)?;
        match decrypt_keypair(&file_bytes, password) {
            Ok(identity) => Ok((identity, IdentityLoadStatus::Loaded)),
            Err(err) if options.allow_plaintext_migration => {
                let keypair = Keypair::from_protobuf_encoding(&file_bytes).map_err(|_| err)?;
                let identity = NodeIdentity::from_keypair(keypair);
                write_encrypted_identity(path, &identity, password)?;
                Ok((identity, IdentityLoadStatus::MigratedPlaintext))
            }
            Err(err) => Err(err),
        }
    } else {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let identity = NodeIdentity::generate_ed25519();
        write_encrypted_identity(path, &identity, password)?;
        Ok((identity, IdentityLoadStatus::Created))
    }
}

pub fn write_encrypted_identity(
    path: impl AsRef<Path>,
    identity: &NodeIdentity,
    password: &str,
) -> Result<(), IdentityError> {
    require_password(password)?;
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let raw_bytes = identity
        .keypair
        .to_protobuf_encoding()
        .map_err(|err| IdentityError::Encoding(err.to_string()))?;
    let mut salt = [0u8; IDENTITY_SALT_LEN];
    let mut iv_bytes = [0u8; IDENTITY_IV_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut iv_bytes);

    let key_bytes = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes))
        .encrypt(AesGcmIv::from_slice(&iv_bytes), raw_bytes.as_ref())
        .map_err(|_| IdentityError::Crypto("identity encryption failed".to_string()))?;

    let mut file = fs::File::create(path)?;
    file.write_all(IDENTITY_FILE_MAGIC)?;
    file.write_all(&salt)?;
    file.write_all(&iv_bytes)?;
    file.write_all(&cipher)?;
    Ok(())
}

pub fn decrypt_keypair(file_bytes: &[u8], password: &str) -> Result<NodeIdentity, IdentityError> {
    require_password(password)?;
    if !file_bytes.starts_with(IDENTITY_FILE_MAGIC) {
        return Err(IdentityError::Encoding(
            "identity file is not an agent-identity-node encrypted identity".to_string(),
        ));
    }

    let payload = &file_bytes[IDENTITY_FILE_MAGIC.len()..];
    if payload.len() <= IDENTITY_SALT_LEN + IDENTITY_IV_LEN {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "encrypted identity file is too small",
        )
        .into());
    }

    let (salt, rest) = payload.split_at(IDENTITY_SALT_LEN);
    let (iv, cipher) = rest.split_at(IDENTITY_IV_LEN);
    let key_bytes = derive_key(password, salt)?;
    let raw = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes))
        .decrypt(AesGcmIv::from_slice(iv), cipher)
        .map_err(|_| IdentityError::InvalidPassword)?;
    let keypair = Keypair::from_protobuf_encoding(&raw)
        .map_err(|err| IdentityError::Encoding(err.to_string()))?;
    Ok(NodeIdentity::from_keypair(keypair))
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], IdentityError> {
    let mut key_bytes = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
        .map_err(|err| IdentityError::Crypto(format!("identity key derivation failed: {err}")))?;
    Ok(key_bytes)
}

fn require_password(password: &str) -> Result<(), IdentityError> {
    if password.trim().is_empty() {
        Err(IdentityError::MissingPassword)
    } else {
        Ok(())
    }
}

fn grant_payload_bytes(claims: &CapabilityGrantClaims) -> Result<Vec<u8>, IdentityError> {
    serde_json::to_vec(claims).map_err(|err| IdentityError::Encoding(err.to_string()))
}

fn normalize_scopes(scopes: Vec<String>) -> Vec<String> {
    let mut scopes: Vec<String> = scopes
        .into_iter()
        .map(|scope| scope.trim().to_ascii_lowercase())
        .filter(|scope| !scope.is_empty())
        .collect();
    scopes.sort();
    scopes.dedup();
    scopes
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_round_trip_preserves_peer_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.id");

        let (created, status) = load_or_create_identity(
            &path,
            "correct horse battery staple",
            LoadOptions::default(),
        )
        .unwrap();
        assert_eq!(status, IdentityLoadStatus::Created);

        let (loaded, status) = load_or_create_identity(
            &path,
            "correct horse battery staple",
            LoadOptions::default(),
        )
        .unwrap();
        assert_eq!(status, IdentityLoadStatus::Loaded);
        assert_eq!(created.peer_id(), loaded.peer_id());
    }

    #[test]
    fn wrong_password_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.id");
        let _ = load_or_create_identity(&path, "right", LoadOptions::default()).unwrap();

        let err = load_or_create_identity(&path, "wrong", LoadOptions::default()).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidPassword));
    }

    #[test]
    fn signatures_verify_with_public_identity() {
        let identity = NodeIdentity::generate_ed25519();
        let payload = b"capability grant";
        let signature = identity.sign(payload).unwrap();
        assert!(identity.verify(payload, &signature));
        assert!(!identity.verify(b"tampered", &signature));
    }

    #[test]
    fn signed_grant_verifies_scope_and_issuer() {
        let identity = NodeIdentity::generate_ed25519();
        let grant = identity
            .issue_grant(
                "python-agent",
                vec!["tool:scan_vault".to_string()],
                unix_timestamp() + 60,
                "request-code-1",
            )
            .unwrap();

        let claims = identity
            .verify_grant(&grant, "tool:scan_vault", unix_timestamp())
            .unwrap();
        assert_eq!(claims.subject, "python-agent");

        let err = identity
            .verify_grant(&grant, "tool:archive_data", unix_timestamp())
            .unwrap_err();
        assert!(matches!(err, GrantVerificationError::MissingScope(_)));
    }

    #[test]
    fn encoded_grant_round_trips() {
        let identity = NodeIdentity::generate_ed25519();
        let grant = identity
            .issue_grant(
                "agent",
                vec!["status:read".to_string()],
                unix_timestamp() + 60,
                "n",
            )
            .unwrap();
        let encoded = grant.encode_base64_json().unwrap();
        let decoded = SignedCapabilityGrant::decode_base64_json(&encoded).unwrap();
        assert_eq!(decoded.claims.subject, "agent");
        identity
            .verify_grant(&decoded, "status:read", unix_timestamp())
            .unwrap();
    }
}

use tokio::net::TcpListener;
use serde_json::Value as JValue;
use std::fmt;
use plonky2::plonk::config::Hasher;
use ssh_key::{self, 
    public::{KeyData, RsaPublicKey}, Algorithm, HashAlg, Mpint, PublicKey, SshSig
};
use plonky2::{
    field::types::Field,
    hash::poseidon::PoseidonHash
};
use sha2::{Digest, Sha256, Sha512};
use pod2::{self,
    middleware::{
        VDSet,
        Params,
        Pod,
        PodId,
        Key,
        ValueRef,
        AnchoredKey,
        Hash,
        RecursivePod,
        Value,
        containers::Set,
        RawValue,
        KEY_SIGNER,
        CustomPredicateRef, PodType, Predicate, Statement,
        StatementArg, TypedValue, KEY_TYPE, Operation
    },
    backends::plonky2::{
        Error,
        Result,
        basetypes::{C, D, F},
    },

    frontend::{
        MainPodBuilder,
        MainPod
    },
    backends::plonky2::mainpod,
    timed,
    op
};

const RSA_BYTE_SIZE: usize = 512;

// Define the error type for our verification function
#[derive(Debug)]
pub enum VerificationError {
    InvalidProofFormat,
    FileReadError(String),
    JsonParseError(String),
    VerificationFailed,
}

// Implement Display for VerificationError
impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VerificationError::InvalidProofFormat => write!(f, "Invalid proof format"),
            VerificationError::FileReadError(e) => write!(f, "File read error: {}", e),
            VerificationError::JsonParseError(e) => write!(f, "JSON parse error: {}", e),
            VerificationError::VerificationFailed => write!(f, "Verification failed"),
        }
    }
}

/// Build SSH signed data format
pub fn build_ssh_signed_data(namespace: &str, raw_msg: &[u8], hash_alg: HashAlg, alg: Algorithm) -> Result<Vec<u8>> {
    // Use the SSH library's built-in method to create the data to sign
    let encoded_data = ssh_key::SshSig::signed_data(namespace, hash_alg, raw_msg)
        .expect("failed to build encoded SSH data");

    
    // Hash the data to sign and generate the digest info
    let (hashed_data, digest_info): (Vec<u8>, Vec<u8>) = match alg {
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
        } => (Sha256::digest(&encoded_data).to_vec(), vec![
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ]),
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
        } => (Sha512::digest(&encoded_data).to_vec(), vec![
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ]),
        _ => {
            return Err(Error::custom(String::from(
                "rsa-sha2-256 and rsa-sha2-256 only",
            )));
        }
    };

    let mut combined_data = digest_info;
    combined_data.extend_from_slice(&hashed_data);

    let comb_len = combined_data.len();

    if RSA_BYTE_SIZE < comb_len + 11 {
        return Err(Error::custom(String::from(
            "Internal encoding error. Encoded message overflows modulus.",
        )));
    }

    // Generate padding string PS
    let ps_len = RSA_BYTE_SIZE - comb_len - 3;
    let ps = vec![0xff; ps_len]; // PS consists of 0xff octets

    // Concatenate to form the encoded message EM
    // EM = 0x00 || 0x01 || PS || 0x00 || T
    let mut padded_data = Vec::with_capacity(RSA_BYTE_SIZE);
    padded_data.push(0x00); // Leading 0x00
    padded_data.push(0x01); // 0x01 byte
    padded_data.extend_from_slice(&ps); // Padding string PS (all 0xff)
    padded_data.push(0x00); // Separator 0x00
    padded_data.extend_from_slice(&combined_data); // DigestInfo T

    Ok(padded_data)
}

pub fn convert_password(original_msg: &[u8], namespace :String) -> Result<Value, VerificationError> {
    let calculated_msg_bytes = build_ssh_signed_data(
            &namespace, 
            original_msg, 
            HashAlg::Sha512, 
            Algorithm::Rsa { hash: Some(HashAlg::Sha512) }
        ).map_err(|e| VerificationError::InvalidProofFormat)?;
    let msg_fields: Vec<F> = calculated_msg_bytes.iter().map(|&b| F::from_canonical_u8(b)).collect();
    let msg_hash = PoseidonHash::hash_no_pad(&msg_fields);
    let raw_message = Value::from(RawValue(msg_hash.elements));
    Ok(raw_message)
}

/// Returns the value of a Equal statement with self id that defines key if it exists.
pub fn get_data(pod: MainPod, key: impl Into<Key>) -> Option<Value> {
        let key: Key = key.into();
        pod.public_statements
            .iter()
            .find_map(|st| match st {
                Statement::Equal(ValueRef::Key(ak), ValueRef::Literal(value))
                    if ak.key.hash() == key.hash() =>
                {
                    Some(value)
                }
                _ => None,
            })
            .cloned()
}

// Main verification function
pub async fn verify_pod(pod: MainPod, pk_list: Value, password: String) -> Result<bool, VerificationError>{
    let pk_list_pod = pod.get("public_keys").ok_or(VerificationError::InvalidProofFormat)?;
    let pod_password:Value = get_data(pod.clone(), "signed_msg").ok_or(VerificationError::InvalidProofFormat)?;
    let conv_password = convert_password(password.as_bytes(), "double-blind.xyz".to_string())?;
    if (pk_list_pod != pk_list) || (pod_password != conv_password) {
        return Ok(false);
    }
    match pod.pod.verify(){
        Ok(()) => Ok(true),
        Err(_) =>  Ok(false)
    }
}

use tokio::net::TcpListener;
use serde_json::Value as JValue;
use std::fmt;

use pod2::{self,
    middleware::{
        VDSet,
        Params,
        Pod,
        PodId,
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


// Main verification function
pub async fn verify_pod(pod: MainPod, pk_list: Value) -> Result<bool, VerificationError>{
    let pk_list_pod = pod.get("public_keys").ok_or(VerificationError::InvalidProofFormat)?;
    if pk_list_pod != pk_list {
        return Ok(false);
    }
    match pod.pod.verify(){
        Ok(()) => Ok(true),
        Err(_) =>  Ok(false)
    }
}

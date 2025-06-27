use reqwest::get;
use anyhow::{anyhow};
use serde::{Serialize, Deserialize};
use ssh_key::{public::{PublicKey, KeyData}};
use std::fs::File;
use std::io::Write;
use plonky2::{
    field::types::Field,
    hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    },
    plonk::config::Hasher,
};
use pod2::{self,
    middleware::{
        VDSet,
        Params,
        Value,
        containers::{Set, Array},
        RawValue,
        KEY_SIGNER,
        PodType, Predicate, Statement,
        StatementArg, TypedValue, KEY_TYPE, Operation
    },
    backends::plonky2::{
        basetypes::{F},
    },
    frontend::MainPod,
    backends::plonky2::mainpod,
    timed,
    op
};


const MAX_GROUP_SIZE : usize = 300;
const RSA_BYTE_SIZE: usize = 512;


pub async fn extract_rsa_from_ssh(ssh_key: &str) -> anyhow::Result<Vec<u8>> {
    let rsa_public_key : PublicKey = PublicKey::from_openssh(ssh_key)
        .map_err(|_| anyhow!("Failed to parse SSH key"))?;

    let key_data : KeyData = rsa_public_key.key_data().clone();
    let pk = match key_data {
            KeyData::Rsa(pk) => pk,
            _ => {
                return Err(anyhow!("signature does not carry an Rsa key"));
            }
        };
    let pk_bytes =
            pk.n.as_positive_bytes()
                .expect("Public key was negative")
                .to_vec();
    if pk_bytes.len() != RSA_BYTE_SIZE {
        return Err(anyhow!("Public key was not the correct size"));
    }
    Ok(pk_bytes)
}

pub async fn parse_keys(all_data: &str) -> anyhow::Result<Vec<String>>{
    let key_list: Vec<&str> = all_data.trim().split("ssh-").collect();
    let mut result : Vec<String> = Vec::new();
    for key in key_list{
        if key != ""{
            let parts: Vec<&str> = key.trim().split_whitespace().collect();
            if parts.len() < 2 {
                return Err(anyhow!("Could not read the github keys. Check the formating."));
            }
            if parts[0].starts_with("rsa") {
                let key = "ssh-rsa ".to_owned() + parts[1] + "\n";
                result.push(key.to_string());
            }
        }
    }
    Ok(result)
}

pub async fn get_and_process_username(username : String) -> anyhow::Result<Vec<Vec<u8>>> {
    let address = format!("{}{}{}", "https://github.com/", username, ".keys");
    let mut result : Vec<Vec<u8>> = Vec::new();
    match get(&address).await {
        Ok(response) => {
            if response.status().is_success() {
                match response.text().await {
                    Ok(body) => {
                        let list_keys = parse_keys(&body).await?;
                        for key in list_keys{
                            let extracted_key = extract_rsa_from_ssh(&key).await?;
                            result.push(extracted_key);
                        }
                        return Ok(result);
                    },
                    Err(err) =>{
                        return Err(anyhow!("Error {err} reading the keys of {username}. Check the username again."));
                    }
                }
            } else {
                return Err(anyhow!("Request failed. Check Internet connection."));
            }

        }
        Err(err) => {
            return Err(anyhow!("Request error: {err}"));
        }
    }
}

pub async fn get_all_users(list_usernames: Vec<String>) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut result: Vec<Vec<u8>> = Vec::new();
    let mut sorted_usernames: Vec<String> = list_usernames.clone();
    sorted_usernames.sort();
    for username in sorted_usernames{
        match get_and_process_username(username.clone()).await {
            Ok(keys) => {
                for key in keys{
                    result.push(key);
                }
            },
            Err(_) => {
                return Err(anyhow!("Failed to process username {:?}, please check spelling", username));
            }
        };
    }
    if result.len() > MAX_GROUP_SIZE {
        return Err(anyhow!("Too many keys in the group. Maximum is {MAX_GROUP_SIZE}."));
    }
    let mut file = File::create("group_keys.txt")
        .map_err(|e| anyhow!("Failed to create file: {e}"))?;
    file.write(format!("{result:?}").as_bytes())
        .map_err(|e| anyhow!("Failed to write to file: {e}"))?;
    return Ok(result);
}



pub async fn get_set_of_all_users(group_pod: MainPod) -> anyhow::Result<(Vec<String>, Value)> {
    let usernames_array: Option<Array> = match group_pod.get("usernames").expect("Pod doesn't have usernames field").typed(){
        TypedValue::Array(arr) => {
            Some(arr.clone())
        },
        _ => {
            None
        }
    };
    let binding = usernames_array.ok_or(anyhow!("Incorrect pod. Does not consists list of usernames."))?;
    let option_usernames: Vec<Option<String>> = binding.array().into_iter().map(|value| match value.typed() {
        TypedValue::String(s) => {
            Some(s.clone())
        },
        _ => {
            None
        }
    }).collect();
    let usernames: Vec<String> = option_usernames.into_iter().map(|opt| opt.unwrap()).collect();

    let pub_keys = get_all_users(usernames.clone()).await?;
    let mut list_of_signers : Vec<Value> = Vec::new();
    for pub_key in pub_keys{
        let pk_fields: Vec<F> = pub_key[..].iter().map(|&b| F::from_canonical_u8(b)).collect();
        let pk_hash = PoseidonHash::hash_no_pad(&pk_fields);
        let signer = Value::from(RawValue(pk_hash.elements));
        list_of_signers.push(signer);
    }
    let set_username = Value::from(Set::new(group_pod.params.max_depth_mt_containers,
        list_of_signers.into_iter().map(Value::from).collect(),)?);
    Ok((usernames, set_username))
}


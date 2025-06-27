use axum::{Router, routing::{get, post}, extract::{State, Json}, debug_handler};
use serde::{Serialize, Deserialize};
use anyhow::{anyhow};
use std::{sync::{Arc, Mutex}, net::SocketAddr};
use serde_json;
use tokio::net::TcpListener;
use lettre::message::{header, Message};
use lettre::{SmtpTransport, Transport, transport::smtp::authentication::Credentials};
use rusqlite::{params, Connection, Result};
use fetch_data_lib :: {get_set_of_all_users};
use verify_proof_lib :: {verify_pod};
use database_lib::{Email, create_table, insert_email_to_database, get_email_from_database, list_all_emails_in_database};
use chrono::prelude::*;
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


#[derive(Debug, Deserialize, Clone, Serialize, PartialEq)]
pub struct EmailReceived{
    pub to: Option<String>, 
    pub header: String,
    pub message: String,
    pub senders: Vec<String>,
    pub group_signature: String
}

type EmailDatabase = Arc<Mutex<Connection>>;
// show all emails in database
//todo: add better error handling
async fn send_list_emails(State(database_conn): State<EmailDatabase>) -> Json<Vec<Email>> {
    let data = list_all_emails_in_database(&database_conn.lock().unwrap()).unwrap(); // Access the vector
    Json(data.clone())   
}

async fn create_the_message(list_senders: Vec<String>, message : String) -> String{
    let mut result :String = "".to_string();
    result = message + "\nBest, \nParticipant of a group : \n";
    for sender in list_senders{
        result = result + &sender + "\n";
    }
    result 
}

async fn parse_pod(pod: MainPod) -> anyhow::Result<String>{
    
    let message:String = match pod.get("message"){
        Some(body) => match body.typed() {
            TypedValue::String(s) => s.to_string(),
            _ => return Err(anyhow!("Sorry, could not find the message.")),
        },
        None => return Err(anyhow!("Sorry, could not find the message.")),
    };
    Ok(message)
}

#[debug_handler]
async fn receive_email(State(database_conn): State<EmailDatabase>, email_str : String) -> String{
    let email : MainPod = match serde_json::from_str(&email_str.clone()) {
        Ok(body) => body,
        Err(err) => return format!("Sorry, could not parse the pod due to {err}."),
    };
    println!("Here, got pod!");
    let date: String= Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let to_addr = "sansome-talk@0xparc.org";
    let subject   = "Kudos!";      // or borrow &email.header
    let (list_of_senders, pb_signals) = match get_set_of_all_users(email.clone()).await {
        Ok(body) => body,
        Err(err) => return format!("Sorry, could not parse the pod due to {err}."),
    };

    let flag = verify_pod(email.clone(), pb_signals.clone(), "0xPARC-double-blind".to_string()).await;
    println!("Verified proof here!");
    let message = match parse_pod(email.clone()).await{
        Ok(body) => body,
        Err(err) => return format!("{err}"),
    };
    println!("Got the message here!");
    let email_database = Email{to:Some("sansome-talk@0xparc.org".to_string()), header: "Kudos!".into(), message: message.clone(), senders: list_of_senders.clone(), group_signature: email_str.clone(), date: date.clone()};
    let mut text = create_the_message(list_of_senders.clone(), message.clone()).await;
    println!("Got text: \n {text}");
    match flag {
        Ok(body) => { 
            if body {
                let email_id = insert_email_to_database(&database_conn.lock().unwrap(), &email_database).unwrap();
                println!("Sending message now...");
                let letter = Message::builder()
                                    .from("kudos@0xparc.org".parse().unwrap())
                                    .to(to_addr.parse().unwrap())
                                    .subject(subject)
                                    .header(header::ContentType::TEXT_PLAIN)
                                    .body(text + &format!("\n \n Date: {} \n Email id: {} \n \n Group Signature: {} \n(Trust us)", date, email_id, email_str.clone()))
                                    .unwrap();
                                    
                println!("Created the message...");
                let creds = Credentials::new("kudos@0xparc.org".into(), "szmi aljp ugko evld".into());
                let mailer = SmtpTransport::relay("smtp.gmail.com").unwrap().credentials(creds).build();
                match mailer.send(&letter){
                    Ok(response) => {
                        return format!("Email sent! Server said: {:?}", response); },
                    Err(e) => {
                        return format!("Failed to send email: {:#?}", e);
                    }
                };
            } else {
                return format!("Sorry, signature is incorrect");
            }
        },
        Err(err) => return format!("Sorry, could not verify proof due to the {err}."),
    };
    return "End of the function".to_string();
}

#[tokio::main]
async fn main() {
    let database: EmailDatabase =  Arc::new(Mutex::new(Connection::open("emails.db").expect("Failed to open database")));
    create_table(&database.lock().unwrap()).expect("Failed to create table");
    
    let router = Router::new()
                    .route("/", get(send_list_emails))
                    .route("/", post(receive_email))
                    .with_state(database);

    let addr = SocketAddr::from(([127,0,0,1], 8000));
    let tcp = TcpListener::bind(&addr).await.unwrap();

    axum::serve(tcp, router).await.unwrap();
}

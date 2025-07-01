# send_group_emails_server
web server to send group emails :)
The server needs to have Rust installed. 

To run the web server, navigate to the "server_setup" project directory and execute the "cargo run" command in the terminal.


"verify_proof_lib" consists of the code necessary to verify the incoming group signature pod. It checks that the set of users indicated in the pod corresponds to public keys and that the message was hashed correctly. It also verifies the received pod. 
"fetch_data_lib" is responsible for fetching and parsing GitHub RSA public keys and converting them into a POD Set data structure. 
The "database_lib" code creates a SQL database for emails and is responsible for handling the insertion of new emails. 
"server_setup" combines the code, launches the server, and handles receiving PODs and creating emails. 

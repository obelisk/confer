#[macro_use]
extern crate log;
#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_migrations;

use std::collections::HashMap;
use std::env;
use std::time::SystemTime;

use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel::pg::PgConnection;
use env_logger;
use hex;
use hmac::{Hmac, Mac, NewMac};
use rand::prelude::*;
use sha2::{Sha256, Digest};
use tonic::transport::{Server};
use tonic::{Request, Response, Status};

use ::confer::build_hmac_for_time;
use self::models::*;

pub mod schema;
pub mod models;
pub mod confer {
    tonic::include_proto!("confer");
}
embed_migrations!("migrations");

#[derive(Default)]
pub struct ConferServer;
type GenericResult<T> = Result<Response<T>, Status>;
type HmacSha256 = Hmac<Sha256>;


fn establish_connection() -> PgConnection {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    PgConnection::establish(&database_url).expect(&format!("Error connecting to {}", &database_url))
}

fn get_admin_auth_key() -> String {
    env::var("ADMIN_KEY").expect("ADMIN_KEY must be set")
}

#[tonic::async_trait]
impl confer::confer_server::Confer for ConferServer {
    async fn get_configs(&self, request: Request<confer::GetConfigsRequest>) -> GenericResult<confer::GetConfigsReply> {
        let configs_request = request.into_inner();

        info!(target: "confer-server", "auth_key_id: [{}] Requested Configs: [{}]", &configs_request.auth_key_id, &configs_request.config_names.join(","));
        use schema::auth_keys::dsl::{auth_keys};

        let connection = establish_connection();
        let results = auth_keys.filter(schema::auth_keys::dsl::auth_key_id.eq(&configs_request.auth_key_id))
            .load::<AuthKey>(&connection)
            .expect("Error loading auth keys");

        if results.len() != 1 {
            info!(target: "confer-server", "No such authorization key: {}", &configs_request.auth_key_id);
            return Err(tonic::Status::not_found("No such key"));
        }

        let found_auth_key = &results[0].auth_key;
        let confs = configs_request.config_names.join(",");

        let hmac = build_hmac_for_time(
            found_auth_key,
            vec![&confs, &configs_request.auth_key_id],
            configs_request.time
        );

        if hmac != configs_request.hmac {
            return Err(tonic::Status::permission_denied("Denied"));
        }

        use schema::authorizations::dsl::{authorizations, time_from, time_until};

        use schema::configs::dsl::configs as config_table;

        let results = authorizations.filter(schema::authorizations::dsl::auth_key_id.eq(&configs_request.auth_key_id))
            .filter(time_from.lt(diesel::dsl::now))
            .filter(time_until.gt(diesel::dsl::now))
            .inner_join(config_table)
            .select((schema::configs::dsl::config_name, schema::configs::dsl::config, schema::configs::dsl::encrypted))
            .load::<(String, String, bool)>(&connection)
            .expect("Error loading authorizations");

        let returned_configs: HashMap<String, confer::EncryptedConfig> = results
            .into_iter()
            .filter(|x| configs_request.config_names.contains(&x.0))
            .map(|x| (x.0, confer::EncryptedConfig {
                config: x.1,
                encrypted: x.2
            })).collect();

        Ok(Response::new(confer::GetConfigsReply {
            configs: returned_configs,
        }))
    }

    async fn upload_config(&self, request: Request<confer::UploadConfigRequest>) -> GenericResult<confer::UploadConfigReply> {
        let req = request.into_inner();
        let encrypted = if req.encrypted {format!("1")} else {format!("0")};

        let pieces = vec![&req.config_name, &req.config, &encrypted];
        let hmac = build_hmac_for_time(&get_admin_auth_key(), pieces, req.time);

        if hmac != req.hmac {
            return Err(tonic::Status::permission_denied("Denied"))
        }

        let new_config = NewConfig {
            config_name: &req.config_name,
            config: &req.config,
            encrypted: req.encrypted,
        };

        use schema::configs::dsl::configs;

        let connection = establish_connection();
        let success = match diesel::insert_into(configs)
        .values(&new_config)
        .execute(&connection) {
            Ok(_) => true,
            Err(e) => {
                error!(target: "confer-server", "Error saving config: {}", e);
                false
            }
        };

        if success {
            Ok(Response::new(confer::UploadConfigReply {}))
        } else {
            Err(tonic::Status::invalid_argument("Config already exists"))
        }
    }

    async fn create_auth_key(&self, request: Request<confer::CreateAuthKeyRequest>) -> GenericResult<confer::CreateAuthKeyReply> {
        let req = request.into_inner();
        let mut mac = HmacSha256::new_varkey(&get_admin_auth_key().as_bytes()).expect("Could not calculate HMAC");
        mac.update(req.time.to_string().as_bytes());

        if hex::encode(mac.finalize().into_bytes()) != req.hmac {
            return Err(tonic::Status::permission_denied("Denied"))
        }

        let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
        let random_auth_key = hex::encode(random_bytes);

        let mut hasher = Sha256::new();
        hasher.update(random_auth_key.clone());
        let result = hasher.finalize();
        let mut random_auth_key_id = String::new();
        random_auth_key_id.reserve(64);
        for byte in &result[..] {
            random_auth_key_id.push_str(format!("{:02x}", byte).as_str());
        }

        use schema::auth_keys::dsl::*;

        let new_auth_key = NewAuthKey {
            auth_key_id: &random_auth_key_id,
            auth_key: &random_auth_key,
        };

        let connection = establish_connection();
        let success = match diesel::insert_into(auth_keys)
        .values(&new_auth_key)
        .execute(&connection) {
            Ok(_) => true,
            Err(e) => {
                error!(target: "confer-server", "Error saving config: {}", e);
                false
            }
        };

        if success {
            Ok(Response::new(confer::CreateAuthKeyReply {
                auth_key: random_auth_key,
            }))
        } else {
            Err(tonic::Status::unknown("Unknown error occurred"))
        }
    }

    async fn authorize_key_for_configs(&self, request: Request<confer::AuthorizeKeyForConfigsRequest>) -> GenericResult<confer::AuthorizeKeyForConfigsReply> {
        let req = request.into_inner();
        let mut code = String::new();
        code.push_str(&req.config_names.join(","));
        code.push(':');
        code.push_str(&req.auth_key_id);
        code.push(':');
        code.push_str(&req.time.to_string());
    
        let mut mac = HmacSha256::new_varkey(&get_admin_auth_key().as_bytes()).expect("Could not calculate HMAC");
        mac.update(code.as_bytes());
        if hex::encode(mac.finalize().into_bytes()) != req.hmac {
            return Err(tonic::Status::permission_denied("Denied")) 
        }

        let mut authorizations = vec![];
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

        for config_name in &req.config_names {
            let new_authorization = NewAuthorization {
                auth_key_id: &req.auth_key_id,
                config_name: config_name,
                time_from: NaiveDateTime::from_timestamp(now as i64, 0),
                time_until: NaiveDateTime::from_timestamp(now as i64 + 31622400, 0), // One year from issue
            };
            authorizations.push(new_authorization);
        }

        let connection = establish_connection();
        let success = match diesel::insert_into(schema::authorizations::dsl::authorizations)
        .values(&authorizations)
        .execute(&connection) {
            Ok(_) => true,
            Err(e) => {
                error!(target: "confer-server", "Error saving config: {}", e);
                false
            }
        };

        if success {
            Ok(Response::new(confer::AuthorizeKeyForConfigsReply {}))
        } else {
            Err(tonic::Status::unknown("Unknown error occurred"))
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let connection = establish_connection();
    // We unwrap because if we can't migrate the DB we need to bail
    embedded_migrations::run(&connection).unwrap();

    let addr = "[::1]:50051".parse().unwrap();
    let server = ConferServer::default();

    println!("Starting Confer Server");
    Server::builder()
        .add_service(confer::confer_server::ConferServer::new(server))
        .serve(addr)
        .await?;

    Ok(())
}
#[macro_use] extern crate log;

use hex;
use hmac::{Hmac, Mac, NewMac};
use sha2::{Sha256, Digest};

use aes_siv::Aes128SivAead;
use aes_siv::aead::{Aead, NewAead, generic_array::GenericArray};

use std::collections::HashMap;
use std::time::{SystemTime};
use tokio::runtime;
use rand::prelude::*;

use confer::confer_client::ConferClient;

use confer::{AuthorizeKeyForConfigsRequest, CreateAuthKeyRequest, GetConfigsRequest, UploadConfigRequest};

pub mod confer {
    tonic::include_proto!("confer");
}

type HmacSha256 = Hmac<Sha256>;

pub struct Confer {
    address: String,
    admin_key: Option<String>,
    authentication_key: String,
    auth_key_id: String,
    configured_configs: HashMap<String, String>,
    executor: tokio::runtime::Runtime,
}

pub fn build_timed_hmac(secret: &String, pieces: Vec<&String>) -> (u64, String) {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(SystemTime::UNIX_EPOCH).expect("Time went backwards");

    return (since_the_epoch.as_secs(), build_hmac_for_time(secret, pieces, since_the_epoch.as_secs()));
}

pub fn build_hmac_for_time(secret: &String, pieces: Vec<&String>, since_the_epoch: u64) -> String {
    let mut mac = HmacSha256::new_varkey(&secret.as_bytes()).expect("Could not calculate HMAC");

    for piece in pieces {
        mac.update(piece.as_ref());
        mac.update(b":");
    }
    mac.update(since_the_epoch.to_string().as_bytes());

    return hex::encode(mac.finalize().into_bytes());
}

impl Confer {
    pub fn fetch_configs(&mut self, config_names: &Vec<String>) -> Result<HashMap<String, String>, String> {
        // Check all requested configs have keys
        if !config_names.iter().fold(true, |acc, item| acc && self.configured_configs.contains_key(item)) {
            return Err(format!("Not all requested configs have configured decryption keys"));
        }

        let confs = config_names.join(",");
        let pieces: Vec<&String> = vec![&confs, &self.auth_key_id];
        let (now, hmac) = build_timed_hmac(&self.authentication_key, pieces);

        let config = GetConfigsRequest {
            config_names: config_names.clone(),
            auth_key_id: self.auth_key_id.clone(),
            hmac: hmac,
            time: now,
        };

        let address_copy = self.address.clone();
        let result = self.executor.block_on(async move {
            let mut client = match ConferClient::connect(address_copy).await {
                Ok(v) => v,
                Err(e) => {
                    return Err(format!("Could not connect to confer server: {}", e));
                },
            };

            let request = tonic::Request::new(config);
            match client.get_configs(request).await {
                Ok(v) => {
                    return Ok(v.into_inner());
                },
                Err(e) => {
                    return Err(format!("Could not fetch config: {}", e));
                },
            }
        });

        let configs = match result {
            Ok(v) => v.configs,
            Err(e) => return Err(e),
        };

        let mut decrypted_configs = HashMap::new();
        for (config_name, config) in configs {
            if config.config.len() < 16 {
                warn!(target: "confer", "Returned config is not long enough to decrypt");
                continue;
            }

            if !config.encrypted {
                decrypted_configs.insert(config_name.clone(), config.config);
                continue;
            }

            let key_bytes = hex::decode(&self.configured_configs[&config_name]).unwrap();
            let config_bytes = hex::decode(&config.config).unwrap();
            let key = GenericArray::from_slice(&key_bytes);
            let nonce = GenericArray::from_slice(&config_bytes[..16].as_ref());
            let cipher = Aes128SivAead::new(key);
    
            let decrypted = match cipher.decrypt(nonce, config_bytes[16..].as_ref()) {
                Ok(dec) => {
                    dec.into_iter().map(|x| x as char).collect::<String>()
                },
                Err(e) => {
                    warn!(target: "confer", "Error decrypting requested config: [{}]. Error: {}", config_name, e);
                    continue;
                },
            };
            decrypted_configs.insert(config_name.clone(), decrypted);
        }

        return Ok(decrypted_configs)
    }

    pub fn add_config(&mut self, config_name: String, encryption_key: String) {
        self.configured_configs.insert(config_name, encryption_key);
    }

    pub fn change_auth_key(&mut self, new_auth_key: String) {
        let mut hasher = Sha256::new();

        hasher.update(new_auth_key.clone());
        let result = hasher.finalize();
        let mut auth_key_id = String::new();
        auth_key_id.reserve(64);
        for byte in &result[..] {
            auth_key_id.push_str(format!("{:02x}", byte).as_str());
        }
        
        self.authentication_key = new_auth_key;
        self.auth_key_id = auth_key_id;
    }


    /*  ****************************************************************************************************************
        *Admin related functions for a confer server                                                                   *
        ****************************************************************************************************************
        *These are all for adding new configs, requesting new auth keys, and authorizing existing keys for new configs.*
        *All functions below here require the admin key currently.                                                     *
        ****************************************************************************************************************
    */

    // Upload a new config to a confer backend.
    pub fn upload_config(&mut self, config_name: String, config: String, encrypt: bool) -> Result<Option<String>, String> {
        if self.admin_key.is_none() {
            return Err(format!("No admin key, cannot upload new config"));
        }

        let mut encryption_key = None;
        let mut config = config;
        if encrypt {
            let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
            encryption_key = Some(hex::encode(random_bytes));

            let key = GenericArray::from_slice(random_bytes.as_ref());
            let cipher = Aes128SivAead::new(key);

            let bytes = rand::thread_rng().gen::<[u8; 16]>();
            let nonce = GenericArray::from_slice(bytes.as_ref());

            let ciphertext = cipher.encrypt(nonce, config.as_ref()).unwrap();
            config = hex::encode(nonce);
            config.push_str(&hex::encode(&ciphertext));
        }

        let encrypted = if encrypt {format!("1")} else {format!("0")};

        let pieces = vec![&config_name, &config, &encrypted];
        let (now, hmac) = build_timed_hmac(self.admin_key.as_ref().unwrap(), pieces);

        let upload_config_request = UploadConfigRequest {
            config_name: config_name,
            config: config,
            encrypted: encrypt,
            time: now,
            hmac: hmac,
        };

        let address_copy = self.address.clone();
        let result = self.executor.block_on(async move {
            let mut client = match ConferClient::connect(address_copy).await {
                Ok(v) => v,
                Err(e) => {
                    return Err(format!("Could not connect to confer server: {}", e));
                },
            };

            let request = tonic::Request::new(upload_config_request);
            match client.upload_config(request).await {
                Ok(v) => {
                    return Ok(v.into_inner());
                },
                Err(e) => {
                    return Err(format!("Could not upload config: {}", e));
                },
            }
        });

        match result {
            Ok(_) => Ok(encryption_key),
            Err(e) => Err(e),
        }
    }

    // Create a new authorization key in the backend that can access no configs
    pub fn create_new_auth_key(&mut self) -> Result<String, String> {
        if self.admin_key.is_none() {
            return Err(format!("No admin key, cannot create a new auth key"));
        }

        let start = SystemTime::now();
        let now = start.duration_since(SystemTime::UNIX_EPOCH).expect("Time went backwards");

        let mut mac = HmacSha256::new_varkey(&self.admin_key.as_ref().unwrap().as_bytes()).expect("Could not calculate HMAC");
        mac.update(now.as_secs().to_string().as_bytes());

        let request = CreateAuthKeyRequest {
            time: now.as_secs(),
            hmac: hex::encode(mac.finalize().into_bytes()),
        };

        let address_copy = self.address.clone();
        let result = self.executor.block_on(async move {
            let mut client = match ConferClient::connect(address_copy).await {
                Ok(v) => v,
                Err(e) => {
                    return Err(format!("Could not connect to confer server: {}", e));
                },
            };

            let request = tonic::Request::new(request);
            match client.create_auth_key(request).await {
                Ok(v) => {
                    return Ok(v.into_inner());
                },
                Err(e) => {
                    return Err(format!("Could not fetch config: {}", e));
                },
            }
        });

        match result {
            Ok(v) => Ok(v.auth_key),
            Err(e) => Err(e),
        }
    }

    pub fn authorize_key_for_configs(&mut self, config_names: Vec<String>) -> Result<(), String> {
        if self.admin_key.is_none() {
            return Err(format!("No admin key, cannot authorize keys for configs"));
        }

        let confs = config_names.join(",");
        let hmac_pieces = vec![&confs, &self.auth_key_id];
        let (now, hmac) = build_timed_hmac(&self.admin_key.as_ref().unwrap(), hmac_pieces);

        let request = AuthorizeKeyForConfigsRequest {
            config_names: config_names,
            auth_key_id: self.auth_key_id.clone(),
            time: now,
            hmac: hmac,
        };

        let address_copy = self.address.clone();
        let result = self.executor.block_on(async move {
            let mut client = match ConferClient::connect(address_copy).await {
                Ok(v) => v,
                Err(e) => {
                    return Err(format!("Could not connect to confer server: {}", e));
                },
            };

            let request = tonic::Request::new(request);
            match client.authorize_key_for_configs(request).await {
                Ok(v) => {
                    return Ok(v.into_inner());
                },
                Err(e) => {
                    return Err(format!("Could not fetch config: {}", e));
                },
            }
        });

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}


pub fn create_confer(address: String, authentication_key: String, admin_key: Option<String>) -> Confer {
    let rt = runtime::Runtime::new().unwrap();

    let mut c = Confer {
        address: address,
        admin_key: admin_key,
        configured_configs: HashMap::new(),
        authentication_key: format!(""),
        auth_key_id: format!(""),
        executor: rt,
    };

    c.change_auth_key(authentication_key);
    c
}

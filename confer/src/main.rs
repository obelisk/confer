use confer::create_confer;

fn main() {
    env_logger::init();
    println!("Starting Confer Test");

    let mut confer = create_confer(
        format!("http://[::1]:50051"),
        format!(""),
        Some(format!("wafflesinastorm")),
    );
    let requested_configs = vec![format!("test-config-enc-21")];

    match confer.create_new_auth_key() {
        Ok(v) => {
            println!("Got new auth_key: {}", v);
            confer.change_auth_key(v);
        },
        Err(e) => {
            println!("No auth key returned. Error: {}", e);
        },
    };

    let sample_config = String::from("TEST THAT WE BASICALLY BUILT A SIMPLE STRING STORE");

    match confer.upload_config(requested_configs[0].clone(), sample_config, true) {
        Ok(Some(v)) => {
            println!("Uploaded new encrypted config with key: {}", &v);
            confer.add_config(requested_configs[0].clone(), v);
        },
        Ok(None) => {
            println!("Uploaded new unencrypted config")
        },
        Err(e) => println!("Error uploading new config: {}", e),
    }

    match confer.authorize_key_for_configs(requested_configs.clone()) {
        Ok(_) => {
            println!("Key is now authorized for the requested configs for 1 year");
        },
        Err(e) => {
            println!("Could not authorize Error: {}", e);
        },
    }

    match confer.fetch_configs(&requested_configs) {
        Ok(v) => {
            println!("The following configs were available:");
            for (config_name, config) in v {
                println!("{}: {}", config_name, config);
            }
        },
        Err(e) => println!("Error: {}", e),
    }
}

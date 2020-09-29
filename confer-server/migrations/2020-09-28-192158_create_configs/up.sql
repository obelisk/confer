CREATE TABLE configs (
  config_name VARCHAR PRIMARY KEY NOT NULL,
  config VARCHAR NOT NULL,
  encrypted boolean NOT NULL
);

CREATE TABLE authorizations (
    id SERIAL PRIMARY KEY,
    auth_key_id VARCHAR NOT NULL,
    config_name VARCHAR NOT NULL,
    time_from TIMESTAMP NOT NULL,
    time_until TIMESTAMP NOT NULL,
    CONSTRAINT fk_config_name
        FOREIGN KEY(config_name) 
        REFERENCES configs(config_name)
);

CREATE TABLE auth_keys (
    auth_key_id VARCHAR PRIMARY KEY NOT NULL,
    auth_key VARCHAR NOT NULL
);

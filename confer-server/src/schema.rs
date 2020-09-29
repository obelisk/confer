table! {
    auth_keys (auth_key_id) {
        auth_key_id -> Varchar,
        auth_key -> Varchar,
    }
}

table! {
    authorizations (id) {
        id -> Int4,
        auth_key_id -> Varchar,
        config_name -> Varchar,
        time_from -> Timestamp,
        time_until -> Timestamp,
    }
}

table! {
    configs (config_name) {
        config_name -> Varchar,
        config -> Varchar,
        encrypted -> Bool,
    }
}

joinable!(authorizations -> configs (config_name));

allow_tables_to_appear_in_same_query!(
    auth_keys,
    authorizations,
    configs,
);

use super::schema::{authorizations, auth_keys, configs};
use chrono;
use chrono::prelude::*;

#[derive(Queryable)]
pub struct Config {
    pub config_name: String,
    pub config: String,
    pub encrypted: bool,
}

#[derive(Queryable)]
pub struct Authorization {
    pub id: i32,
    pub auth_key_id: String,
    pub config_name: String,
    pub time_from: NaiveDateTime,
    pub time_until: NaiveDateTime,
}

#[derive(Queryable)]
pub struct AuthKey {
    pub auth_key_id: String,
    pub auth_key: String,
}

#[derive(Insertable)]
#[table_name="configs"]
pub struct NewConfig<'a> {
    pub config_name: &'a str,
    pub config: &'a str,
    pub encrypted: bool,
}

#[derive(Insertable)]
#[table_name="authorizations"]
pub struct NewAuthorization<'a> {
    pub auth_key_id: &'a str,
    pub config_name: &'a str,
    pub time_from: NaiveDateTime,
    pub time_until: NaiveDateTime,
}

#[derive(Insertable)]
#[table_name="auth_keys"]
pub struct NewAuthKey<'a> {
    pub auth_key_id: &'a str,
    pub auth_key: &'a str,
}
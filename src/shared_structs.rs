#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_mut)]

/// Guess i'll put all there structs to responding files, but for now..

use std::fmt::Debug;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, base64::Base64};
use zeroize::Zeroize;
use rand::{self, Rng};


pub trait AuditAble<'a> : Debug {
    fn responsible(&'a self) -> &'a str;
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct UserPass {
    pub username: String,
    pub hashed_password: String,
    pub salt: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct AuthMethods {
    pub userpass: Option<UserPass>,
    pub kubernetes: Option<String>,
}

impl AuthMethods {
    pub fn new(userpass_creds: Option<UserPass>, kubernetes_creds: Option<String>) -> Self {
        AuthMethods {
            userpass: None,
            kubernetes: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum AccessTag {
    Read,
    Write,
    Delete,
    Destroy,
}


#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PermissionRule {
    path: String,
    access_tags: Vec<AccessTag>,
    master_id: String,
}

impl<'a> AuditAble<'a> for PermissionRule{
    fn responsible(&'a self) -> &'a str {
        &self.master_id
    }
}


#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Role {
    rolename: String,
    perm_rules: Vec<PermissionRule>,
    master_id: String,
}

impl<'a> AuditAble<'a> for Role {
    fn responsible(&'a self) -> &'a str {
        &self.master_id
    }
}


#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct User {
    pub username: String,
    pub auth_methods: AuthMethods,
    pub roles: Vec<Role>,
    pub name: String,
    pub surname: Option<String>,
    pub mail: Option<String>,
    pub number: Option<String>,
    master_id: String,
}

impl User {
    pub fn new(username: String, auth_methods: AuthMethods, roles: Vec<Role>, name: String, surname: Option<String>, mail: Option<String>, number: Option<String>, master_id: String) -> Self {
        User {
            username,
            auth_methods,
            roles,
            name,
            surname,
            mail,
            number,
            master_id,
        }
    }
}

impl<'a> AuditAble<'a> for User {
    fn responsible(&'a self) -> &'a str {
        &self.master_id
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedUser {
    pub username: String,
    pub data: String,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Token {
    pub ttl: DateTime<Utc>,
    #[serde_as(as = "Base64")]
    pub token: [u8; 128],
    pub user_id: String,
    pub roles: Vec<Role>,
    pub perm_rules: Vec<PermissionRule>,
    master_id: String,
}

impl Token {
    pub fn new(ttl: DateTime<Utc>, user: &User, roles: Vec<Role>, perm_rules: Vec<PermissionRule>) -> Self {
        Token {
            ttl,
            token: generate_random_token(),
            user_id: String::from(&user.username),
            roles,
            perm_rules,
            master_id: String::from(&user.master_id),
        }
    }
}

impl<'a> AuditAble<'a> for Token {
    fn responsible(&'a self) -> &'a str {
        &self.master_id
    }
}

/// Rewrite token in RAM with zeroes on destructor call
impl Drop for Token {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct EncryptedToken {
    #[serde_as(as = "Base64")]
    pub token_half: [u8; 64],
    pub data: String,
}


pub fn generate_random_token() -> [u8; 128] {
    let mut random = [0u8; 128];
    rand::thread_rng().fill(&mut random[..]);
    return random
}
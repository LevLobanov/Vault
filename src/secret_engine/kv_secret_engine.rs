#![allow(irrefutable_let_patterns)]

use std::collections::HashMap;
use mongodb::{bson::doc, results::InsertOneResult, Client, Collection};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use crate::observer::Observer;
use super::{EncryptedSecret, Secret, SecretEngineProperties};


#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct KVSecret {
    pub path: String,
    pub key_value: HashMap<String, String>,
    master_id: String,
}

impl KVSecret {
    pub fn new(path: String, key_value: HashMap<String, String>, master_id: String) -> Self {
        KVSecret {
            path,
            key_value,
            master_id,
        }
    }
}


#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct KVEncryptedSecret {
    pub path: String,
    pub data: String,
}

impl KVEncryptedSecret {
    pub fn new(path: String, data: String) -> Self {
        KVEncryptedSecret{
            path,
            data,
        }
    }
}


pub struct KVSecretEngine<'a> {
    name: String,
    mount_path: String,
    secret_collection: Collection<KVEncryptedSecret>,
    enabled: bool,
    observer: &'a Observer,
}

impl<'a> KVSecretEngine<'a> {
    pub async fn new(name: String, mount_path: String, secret_database_name: &str, conn_uri: &str, observer: &'a Observer) -> Result<KVSecretEngine<'a>> {
        let client = Client::with_uri_str(conn_uri).await?;
        let db = client.database(secret_database_name);
        let secret_coll = db.collection("Secrets");
        Ok(KVSecretEngine{
            name,
            mount_path,
            secret_collection: secret_coll,
            enabled: false,
            observer,
        })
    }

    async fn insert_secret_db(&self, secret: KVSecret) -> Result<InsertOneResult> {
        // TODO: Checks for permissions
        if let EncryptedSecret::KVEncryptedSecret(encrypted_secret) = self.observer.encrypt_secret(Secret::KVSecret(secret))? {
            Ok(self.secret_collection.insert_one(encrypted_secret).await?)
        } else {
            Err(anyhow!("WRONG SECRET TYPE"))
        }
    }

    async fn update_secret_db(&self, path: &str, new_key_value: Vec<HashMap<String, String>>) -> Result<()> {
        todo!()
    }

    async fn get_secret_db(&self, path: &str) -> Result<KVSecret> {
        // Only for internal use, not user interface
        if let Secret::KVSecret(kv_secret) = self.observer.decrypt_secret(EncryptedSecret::KVEncryptedSecret(self.secret_collection.find_one(doc! {"path" : path}).await?.expect("No user with given username found!")))? {
            Ok(kv_secret)
        } else {
            Err(anyhow!("WRONG SECRET TYPE"))
        }
    }
}

impl<'a> SecretEngineProperties for KVSecretEngine<'a> {
    async fn delete_secret_db(&self, path: &str) -> Result<mongodb::results::DeleteResult> {
        // TODO: Checks for permissions
        Ok(self.secret_collection.delete_one(doc! {"path": path}).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_secret_insertion_deletion() {
        let observer = Observer::new(b"an example very very secret key.".to_vec());
        let secret_engine = KVSecretEngine::new("Default".to_string(), "secret/".to_string(), "KVStorage", "mongodb://localhost:27017/Auth", &observer).await.expect("Can't create a kv secret engine");
        let mut key_value: HashMap<String, String> = HashMap::new();
        key_value.insert("login".to_string(), "lev_login".to_string());
        key_value.insert("password".to_string(), "lev_password".to_string());
        let secret = KVSecret::new("twitter/account".to_string(), key_value, "Root".to_string());

        secret_engine.insert_secret_db(secret).await.expect("Can't insert secret in db!");
    }

    #[tokio::test]
    async fn test_getting_secret() {
        let observer = Observer::new(b"an example very very secret key.".to_vec());
        let secret_engine = KVSecretEngine::new("Default".to_string(), "secret/".to_string(), "KVStorage", "mongodb://localhost:27017/Auth", &observer).await.expect("Can't create a kv secret engine");
        let mut key_value: HashMap<String, String> = HashMap::new();
        key_value.insert("login".to_string(), "lev_login".to_string());
        key_value.insert("password".to_string(), "lev_password".to_string());
        let secret = KVSecret::new("twitter/test/get/secret".to_string(), key_value, "Root".to_string());

        secret_engine.insert_secret_db(secret.clone()).await.expect("Can't insert secret in db!");
        let gathered_secret = secret_engine.get_secret_db("twitter/test/get/secret").await.expect("No secret found with given path!");
        assert_eq!(gathered_secret, secret);
    }
}
use kv_secret_engine::{KVEncryptedSecret, KVSecret, KVSecretEngine};
use mongodb::results::DeleteResult;
use anyhow::Result;
use serde::{Deserialize, Serialize};

pub mod kv_secret_engine;

pub trait SecretProperties {}

pub trait SecretEngineProperties {

    async fn delete_secret_db(&self, path: &str) -> Result<DeleteResult>;
}

pub enum SecretEngine<'a> {
    KVSecretEngine(KVSecretEngine<'a>),
}


#[derive(Debug, Serialize, Deserialize)]
pub enum Secret {
    KVSecret(KVSecret),
}


#[derive(Debug, Serialize, Deserialize)]
pub enum EncryptedSecret {
    KVEncryptedSecret(KVEncryptedSecret)
}
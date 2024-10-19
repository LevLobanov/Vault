#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(unused_imports)]

use std::collections::HashMap;
use crate::{secret_engine::{kv_secret_engine::{KVEncryptedSecret, KVSecret}, EncryptedSecret, Secret, SecretEngine, SecretProperties}, shared_structs::{EncryptedToken, EncryptedUser, Token, User}};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, AeadCore, KeyInit}};
use anyhow::{Ok, Result};
use base64::prelude::*;

/// 👀 Big brother grants permissions, registers and wathes you.
/// You can't read secret without him granting you ability to do it!
pub struct Observer {
    master_key: Key<Aes256Gcm>,
    shamir_t: usize,
    shamir_n: usize,
    progress: usize,
    selaed: bool,
}

impl Observer {
    pub fn new(master_key: Vec<u8>) -> Self {
        let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(&master_key);
        Observer {
            master_key: *key,
            shamir_t: 3,
            shamir_n: 5,
            progress: 0,
            selaed: false,
        }
    }

    fn encrypt_with_master(&self, data: &str) -> String {
        let nonce = Nonce::from_slice(b"this will be");

        let cipher = Aes256Gcm::new(&self.master_key);
        let encrypted_data = cipher.encrypt(nonce, data.as_bytes()).expect("Encryption failed");

        BASE64_STANDARD.encode(encrypted_data)
    }

    fn decrypt_with_master(&self, data: &str) -> String {
        let nonce = Nonce::from_slice(b"this will be");

        let cipher = Aes256Gcm::new(&self.master_key);
        let decoded_data = BASE64_STANDARD.decode(data).expect("Decoding failed");
        let decrypted_data = cipher.decrypt(nonce, decoded_data.as_ref()).expect("Decryption failed");

        String::from_utf8(decrypted_data).expect("Invalid UTF-8 sequence")
    }

    pub fn decrypt_user(&self, encrypted_user: EncryptedUser) -> Result<User> {
        let user: User = serde_json::from_str(&self.decrypt_with_master(&encrypted_user.data))?;
        Ok(user)
    }

    pub fn encrypt_user(&self, user: User) -> Result<EncryptedUser> {
        let user_string = serde_json::to_string(&user)?;
        let encrypted_data = self.encrypt_with_master(&user_string);
        Ok(EncryptedUser {
            username: user.username,
            data: encrypted_data,
        })
    }

    pub fn encrypt_token(&self, token: Token) -> Result<EncryptedToken> {
        let second_token_half: [u8; 64] = token.token[64..128].try_into()?;
        let token_string = serde_json::to_string(&token)?;
        let encrypted_token = self.encrypt_with_master(&token_string);
        Ok(EncryptedToken{
            token_half: token.token[0..64].try_into()?,
            data: encrypted_token,
        })
    }

    pub fn decrypt_token(&self, encrypted_token: EncryptedToken) -> Result<Token> {
        let token: Token = serde_json::from_str(&self.decrypt_with_master(&encrypted_token.data))?;
        Ok(token)
    }

    pub fn encrypt_secret(&self, secret: Secret) -> Result<EncryptedSecret> {
        match secret {
            Secret::KVSecret(kvsecret) => {
                let secret_string = serde_json::to_string(&kvsecret)?;
                let encrypted_data = self.encrypt_with_master(&secret_string);
                Ok(EncryptedSecret::KVEncryptedSecret(KVEncryptedSecret::new(kvsecret.path.clone(), encrypted_data)))
            },
        }
    }

    pub fn decrypt_secret(&self, encrypted_secret: EncryptedSecret) -> Result<Secret> {
        match encrypted_secret {
            EncryptedSecret::KVEncryptedSecret(kvencrypted_secret) => {
                let kv_secret: KVSecret = serde_json::from_str(&self.decrypt_with_master(&kvencrypted_secret.data))?;
                Ok(Secret::KVSecret(kv_secret))
            },
        }
    }

    pub fn get_vault_status(&self) -> (bool, usize, usize, usize) {
        (self.selaed, self.shamir_t, self.shamir_n, self.progress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption() {

        let observer = Observer::new(b"an example very very secret key.".to_vec());
        
        let data = "sensitive data";
        let encrypted_data = observer.encrypt_with_master(data);
        println!("encrypted: {}", encrypted_data);
        assert_ne!(data, encrypted_data);
        let decrypted_data = observer.decrypt_with_master(&encrypted_data);
        assert_eq!(data, decrypted_data);
        println!("Decrypted: {}", decrypted_data);
    }
}
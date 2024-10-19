// #![allow(dead_code)]
// #![allow(unused_variables)]
// #![allow(unused_mut)]
// #![allow(unused_imports)]


use chrono::{Duration, Utc};
use mongodb::{bson::doc, results::DeleteResult, Client, Collection, Database};
use crate::{observer::Observer, shared_structs::{EncryptedToken, EncryptedUser, Token, User}};
use anyhow::{anyhow, Ok, Result};
use sha2::{Sha256, Digest};
use base64::prelude::*;


struct AuthBlock<'a> {
    token_collection: Collection<EncryptedToken>, // Forces to store only encrypted variant
    backend_storage_client: Client,
    database: Database,
    user_collection: Collection<EncryptedUser>, // Forces to store only encrypted variant
    observer: &'a Observer,
}

impl<'a> AuthBlock<'a> {
    pub async fn new(conn_uri: &str, observer: &'a Observer) -> Result<AuthBlock<'a>> {
        let client = Client::with_uri_str(conn_uri).await?;
        let db = client.database("Auth");
        let user_coll = db.collection("Users");
        let token_coll = db.collection("Tokens");
        Ok(AuthBlock {
            token_collection: token_coll,
            backend_storage_client: client,
            database: db,
            user_collection: user_coll,
            observer,
        })
    }

    async fn get_hash_and_salt(&self, username: &str) -> Result<(String, String)> {
        let found_user = self.observer.decrypt_user(self.user_collection.find_one(doc! {"username" : username}).await?.expect("No user with given username found!"))?;
        let userpass = found_user.auth_methods.userpass.expect("This user doesn't have userpass auth method on!");
        Ok((userpass.hashed_password, userpass.salt))
    }

    async fn auth_userpass(&self, username: &str, password: Option<&str>, hashed_password: Option<&str>, ttl: Option<usize>) -> Result<[u8; 128]> {
        if let Some(password) = password {
            if let Some(_) = hashed_password {
                return Err(anyhow!("password and hashed password are mutual exclusive, provide only one value."));
            } else {
                let (hash_from_bs, salt) = self.get_hash_and_salt(username).await?;
                if hash_from_bs == self.hash(password, &salt)? {
                    Ok(self.generate_token(username, ttl).await?)
                } else {
                    Err(anyhow!("Wrong credentials"))
                }
            }
        } else {
            if let Some(hashed_password) = hashed_password {
                return Ok([0u8; 128]);
            } else {
                return Err(anyhow!("No password or hashed password provided."));
            }
        }
    }

    async fn generate_token(&self, username: &str, requested_ttl_mins: Option<usize>) -> Result<[u8; 128]> {
        let cur_user = self.get_user_db(username).await?;
        let mut token_ttl = Utc::now();
        if let Some(requested_ttl_mins) = requested_ttl_mins {
            token_ttl += Duration::minutes(requested_ttl_mins as i64);
        } else {
            token_ttl += Duration::minutes(30);
        }
        let new_token = Token::new(token_ttl, &cur_user, cur_user.roles.clone(), Vec::new());
        Ok(new_token.token)
    }

    fn hash(&self, data: &str, salt: &str) -> Result<String> {
        let mut hasher: Sha256 = Sha256::new();
        Ok(String::from_utf8(hasher.finalize().to_vec())?)
    }

    pub async fn insert_user_db(&self, user: User) -> Result<()> {
        // TODO: Checks for permissions
        self.user_collection.insert_one(self.observer.encrypt_user(user)?).await?;
        Ok(())
    }

    pub async fn delete_user_db(&self, username: &str) -> Result<DeleteResult> {
        // TODO: Checks for permissions
        Ok(self.user_collection.delete_one(doc! {"username": username}).await?)
    }

    pub async fn get_user_db(&self, username: &str) -> Result<User> {
        // Only for internal use, not user interface
        self.observer.decrypt_user(self.user_collection.find_one(doc! {"username" : username}).await?.expect("No user with given username found!"))
    }

    pub async fn insert_token_db(&self, token: Token) -> Result<()> {
        // TODO: Checks for permissions
        self.token_collection.insert_one(self.observer.encrypt_token(token)?).await?;
        Ok(())
    }

    pub async fn delete_token_db(&self, token: &[u8; 128]) -> Result<DeleteResult> {
        // TODO: Checks for permissions
        let first_token_half: [u8; 64] = token[0..64].try_into()?;
        let base64_token = BASE64_STANDARD.encode(first_token_half);
        Ok(self.token_collection.delete_one(doc! {"token_half": base64_token}).await?)
    }

    pub async fn get_token_db(&self, token: &[u8; 128]) -> Result<Token> {
        // Only for internal use, not user interface
        let first_token_half: [u8; 64] = token[0..64].try_into()?;
        let base64_token = BASE64_STANDARD.encode(first_token_half);
        self.observer.decrypt_token(self.token_collection.find_one(doc! {"token_half" : base64_token}).await?.expect("No given token found!"))
    }
}


#[cfg(test)]
mod tests {
    use crate::shared_structs::AuthMethods;

    use super::*;

    #[tokio::test]
    async fn test_user_insertion_deletion() {
        let observer = Observer::new(b"an example very very secret key.".to_vec());
        let auth_block = AuthBlock::new("mongodb://localhost:27017/Auth", &observer).await.expect("CANT CREATE AUTH BLOCK");
        let user = User::new("Cluster admin to delete".to_string(), AuthMethods::new(None, None), Vec::new(), "lev".to_string(), Some("lobanov".to_string()), Some("lev.lobanov.g@yandex.ru".to_string()), Some("+71231231234".to_string()), "Root".to_string());

        auth_block.insert_user_db(user).await.expect("Inserting user failed((((");
        auth_block.delete_user_db("Cluster admin to delete").await.expect("Deleting user failed))))");
    }

    #[tokio::test]
    async fn test_getting_user() {
        let observer = Observer::new(b"an example very very secret key.".to_vec());
        let auth_block = AuthBlock::new("mongodb://localhost:27017/Auth", &observer).await.expect("CANT CREATE AUTH BLOCK");
        let user = User::new("Cluster admin to print".to_string(), AuthMethods::new(None, None), Vec::new(), "lev".to_string(), Some("lobanov".to_string()), Some("lev.lobanov.g@yandex.ru".to_string()), Some("+71231231234".to_string()), "Root".to_string());

        auth_block.insert_user_db(user.clone()).await.expect("Inserting user failed((((");
        // println!("User struct from DB: {:#?}", auth_block.get_user("Cluster admin to print").await.expect("showing user failed))))"));
        assert_eq!(user, auth_block.get_user_db("Cluster admin to print").await.expect("showing user failed))))"));
        auth_block.delete_user_db("Cluster admin to print").await.expect("Deleting user failed))))");
    }

    #[tokio::test]
    async fn test_token_insertion_deletion() {
        let observer = Observer::new(b"an example very very secret key.".to_vec());
        let auth_block = AuthBlock::new("mongodb://localhost:27017/Auth", &observer).await.expect("CANT CREATE AUTH BLOCK");
        let user = User::new("Cluster admin to print".to_string(), AuthMethods::new(None, None), Vec::new(), "lev".to_string(), Some("lobanov".to_string()), Some("lev.lobanov.g@yandex.ru".to_string()), Some("+71231231234".to_string()), "Root".to_string());
        let token = Token::new(Utc::now() + Duration::minutes(30), &user, user.roles.clone(), Vec::new());
        let first_token_half: [u8; 64] = token.token[0..64].try_into().expect("no");

        auth_block.insert_token_db(token.clone()).await.expect("Failed to insert token in db(((");
        auth_block.delete_token_db(&token.token).await.expect("Failed to delete token from db(((");
    }

    #[tokio::test]
    async fn test_getting_token() {
        let observer = Observer::new(b"an example very very secret key.".to_vec());
        let auth_block = AuthBlock::new("mongodb://localhost:27017/Auth", &observer).await.expect("CANT CREATE AUTH BLOCK");
        let user = User::new("Cluster admin to print".to_string(), AuthMethods::new(None, None), Vec::new(), "lev".to_string(), Some("lobanov".to_string()), Some("lev.lobanov.g@yandex.ru".to_string()), Some("+71231231234".to_string()), "Root".to_string());
        let token = Token::new(Utc::now() + Duration::minutes(30), &user, user.roles.clone(), Vec::new());
        let first_token_half: [u8; 64] = token.token[0..64].try_into().expect("no");

        auth_block.insert_token_db(token.clone()).await.expect("Failed to insert token in db(((");
        let res = auth_block.get_token_db(&token.token).await.expect("Failed to delete token from db(((");
        assert_eq!(token, res);
    }

    #[tokio::test]
    async fn test_token_generation() {
        let observer = Observer::new(b"an example very very secret key.".to_vec());
        let auth_block = AuthBlock::new("mongodb://localhost:27017/Auth", &observer).await.expect("CANT CREATE AUTH BLOCK");
        let user = User::new("Cluster admin to generate token".to_string(), AuthMethods::new(None, None), Vec::new(), "lev".to_string(), Some("lobanov".to_string()), Some("lev.lobanov.g@yandex.ru".to_string()), Some("+71231231234".to_string()), "Root".to_string());

        auth_block.insert_user_db(user.clone()).await.expect("Inserting user failed((((");
        let token1 = auth_block.generate_token("Cluster admin to generate token", Some(50)).await.expect("Generating token with given ttl failed");
        let token2 = auth_block.generate_token("Cluster admin to generate token", None).await.expect("Generating token with no provided ttl failed");
        assert_ne!(token1, token2);
        auth_block.delete_user_db("Cluster admin to generate token").await.expect("Deleting user failed))))");
    }
}
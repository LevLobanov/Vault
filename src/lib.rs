#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_mut)]

use pyo3::prelude::*;

mod auth;
mod shared_structs;
mod observer;
mod secret_engine;

/// A Python module implemented in Rust.
#[pymodule]
mod vault {
    use super::*;

    /// Authorization module, use it's functions to authorize user and receive token
    #[pymodule]
    mod auth {
        use super::*;

        /// This function authorizes user and returns token, if ok.
        #[pyfunction]
        #[pyo3(signature = (username, password=None, hashed_password=None, token_ttl=None))]
        fn auth_userpass(username: &str, password: Option<&str>, hashed_password: Option<&str>, token_ttl: Option<usize>) -> PyResult<String> {
            todo!()
        }
    }

    #[pymodule]
    mod secrets_engine {
        use super::*;

        #[pymodule]
        mod kv {
            use super::*;

            #[pyfunction]
            fn get_secret(token: &str, path: &str) -> PyResult<String> {
                Ok(format!("Your secret: 🍆, from path: {} and token used: {}", path, token))
            }
        }
    }
}
use pyo3::prelude::*;

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
        #[pyo3(signature = (username, password, token_ttl=None))]
        fn auth_userpass(username: &str, password: &str, token_ttl: Option<usize>) -> PyResult<String> {
            Ok(format!("Token for user: {} with password: {} and requested ttl: {}", username, password, token_ttl.unwrap_or(0)))
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
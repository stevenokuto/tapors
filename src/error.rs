use thiserror::Error;

#[derive(Error, Debug)]
pub enum TapoError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("JSON serialization/deserialization failed: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Authentication failed: {0}")]
    AuthenticationError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Device returned error code {code}: {msg}")]
    DeviceError { code: i32, msg: String },

    #[error("Invalid response from device: {0}")]
    InvalidResponse(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, TapoError>;

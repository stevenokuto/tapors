use crate::crypto::{
    aes_decrypt, aes_encrypt, base64_decode, base64_encode, generate_nonce, md5_hash, sha256_hash,
};
use crate::error::{Result, TapoError};
use crate::types::TapoResponse;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub enum HashMethod {
    Md5,
    Sha256,
}

pub struct TraditionalAuth {
    host: String,
    port: u16,
    client: Client,
    username: String,
    password: String,

    // Session state
    pub stok: Option<String>,
    cnonce: String,
    nonce: Option<String>,
    hash_method: HashMethod,
    lsk: Option<Vec<u8>>, // Local session key
    ivb: Option<Vec<u8>>, // Initialization vector
    seq: u32,             // Sequence number for requests
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginRequest {
    method: String,
    params: LoginParams,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    cnonce: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    encrypt_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginResponse {
    error_code: i32,
    result: Option<LoginResult>,
}

#[derive(Debug, Deserialize, Default)]
struct LoginResult {
    #[serde(default)]
    stok: String,

    #[serde(default)]
    nonce: String,

    #[serde(default)]
    device_confirm: String,

    #[serde(default)]
    user_group: String,
}

impl TraditionalAuth {
    pub fn new(host: String, port: u16, username: String, password: String) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        Ok(Self {
            host,
            port,
            client,
            username,
            password,
            stok: None,
            cnonce: generate_nonce(),
            nonce: None,
            hash_method: HashMethod::Sha256,
            lsk: None,
            ivb: None,
            seq: 1,
        })
    }

    /// Authenticate with the device
    pub fn authenticate(&mut self) -> Result<()> {
        // Step 1: Send initial login request to get nonce
        let login_req = json!({
            "method": "login",
            "params": {
                "cnonce": self.cnonce,
                "encrypt_type": "3",
                "username": self.username
            }
        });

        let url = format!("https://{}:{}", self.host, self.port);
        let response = self.client.post(&url).json(&login_req).send()?;

        let login_resp: TapoResponse<LoginResult> = response.json()?;

        if login_resp.error_code != 0 {
            return Err(TapoError::AuthenticationError(format!(
                "Login failed with error code: {}",
                login_resp.error_code
            )));
        }

        let result = login_resp
            .result
            .ok_or_else(|| TapoError::InvalidResponse("Missing login result".to_string()))?;

        self.nonce = Some(result.nonce.clone());

        // Step 2: Determine hash method by validating device_confirm
        self.detect_hash_method(&result.nonce, &result.device_confirm)?;

        // Step 3: Generate digest password
        let digest_passwd = self.generate_digest_password()?;

        // Step 4: Send final login with digest password
        let final_login = json!({
            "method": "login",
            "params": {
                "cnonce": self.cnonce,
                "encrypt_type": "3",
                "digest_passwd": digest_passwd,
                "username": self.username
            }
        });

        let response = self.client.post(&url).json(&final_login).send()?;
        let final_resp: TapoResponse<LoginResult> = response.json()?;

        if final_resp.error_code != 0 {
            return Err(TapoError::AuthenticationError(format!(
                "Final login failed with error code: {}",
                final_resp.error_code
            )));
        }

        let final_result = final_resp
            .result
            .ok_or_else(|| TapoError::InvalidResponse("Missing final login result".to_string()))?;

        self.stok = Some(final_result.stok);

        // Step 5: Derive encryption keys
        self.derive_keys()?;

        Ok(())
    }

    /// Detect which hash method the device uses
    fn detect_hash_method(&mut self, nonce: &str, device_confirm: &str) -> Result<()> {
        // Try SHA256 first
        let sha256_confirm = sha256_hash(&format!(
            "{}{}{}",
            self.cnonce, self.password, nonce
        ));

        if sha256_confirm == device_confirm {
            self.hash_method = HashMethod::Sha256;
            return Ok(());
        }

        // Try MD5
        let md5_confirm = md5_hash(&format!("{}{}{}", self.cnonce, self.password, nonce));

        if md5_confirm == device_confirm {
            self.hash_method = HashMethod::Md5;
            return Ok(());
        }

        Err(TapoError::AuthenticationError(
            "Could not determine hash method".to_string(),
        ))
    }

    /// Generate digest password based on detected hash method
    fn generate_digest_password(&self) -> Result<String> {
        let nonce = self
            .nonce
            .as_ref()
            .ok_or_else(|| TapoError::AuthenticationError("Nonce not set".to_string()))?;

        let combined = format!("{}{}{}", self.password, self.cnonce, nonce);

        let digest = match self.hash_method {
            HashMethod::Sha256 => sha256_hash(&combined),
            HashMethod::Md5 => md5_hash(&combined),
        };

        Ok(digest)
    }

    /// Derive LSK and IVB from password and nonce
    fn derive_keys(&mut self) -> Result<()> {
        let nonce = self
            .nonce
            .as_ref()
            .ok_or_else(|| TapoError::AuthenticationError("Nonce not set".to_string()))?;

        // LSK = hash(password + nonce)
        let lsk_str = match self.hash_method {
            HashMethod::Sha256 => sha256_hash(&format!("{}{}", self.password, nonce)),
            HashMethod::Md5 => md5_hash(&format!("{}{}", self.password, nonce)),
        };

        // Convert to bytes and take first 16 bytes
        let lsk_bytes = hex::decode(&lsk_str)
            .map_err(|e| TapoError::EncryptionError(format!("Failed to decode LSK: {}", e)))?;
        self.lsk = Some(lsk_bytes[..16].to_vec());

        // IVB = hash(nonce + password)
        let ivb_str = match self.hash_method {
            HashMethod::Sha256 => sha256_hash(&format!("{}{}", nonce, self.password)),
            HashMethod::Md5 => md5_hash(&format!("{}{}", nonce, self.password)),
        };

        let ivb_bytes = hex::decode(&ivb_str)
            .map_err(|e| TapoError::EncryptionError(format!("Failed to decode IVB: {}", e)))?;
        self.ivb = Some(ivb_bytes[..16].to_vec());

        Ok(())
    }

    /// Send an encrypted request to the device
    pub fn send_request(&mut self, request: Value) -> Result<Value> {
        if self.stok.is_none() {
            self.authenticate()?;
        }

        let stok = self
            .stok
            .as_ref()
            .ok_or_else(|| TapoError::AuthenticationError("Not authenticated".to_string()))?;

        // Encrypt the request
        let encrypted = self.encrypt_request(&request)?;

        // Wrap in securePassthrough
        let secure_request = json!({
            "method": "securePassthrough",
            "params": {
                "request": encrypted
            }
        });

        // Send request
        let url = format!("https://{}:{}/stok={}/ds", self.host, self.port, stok);

        let response = self
            .client
            .post(&url)
            .header("Seq", self.seq.to_string())
            .header("Tapo_tag", &self.cnonce)
            .json(&secure_request)
            .send()?;

        self.seq += 1;

        let resp_json: Value = response.json()?;

        // Extract and decrypt response
        if let Some(result) = resp_json.get("result") {
            if let Some(encrypted_response) = result.get("response").and_then(|v| v.as_str()) {
                return self.decrypt_response(encrypted_response);
            }
        }

        Err(TapoError::InvalidResponse(
            "No encrypted response in reply".to_string(),
        ))
    }

    /// Encrypt a request
    fn encrypt_request(&self, request: &Value) -> Result<String> {
        let lsk = self
            .lsk
            .as_ref()
            .ok_or_else(|| TapoError::EncryptionError("LSK not set".to_string()))?;

        let ivb = self
            .ivb
            .as_ref()
            .ok_or_else(|| TapoError::EncryptionError("IVB not set".to_string()))?;

        let json_str = serde_json::to_string(request)?;
        let encrypted = aes_encrypt(json_str.as_bytes(), lsk, ivb)?;
        Ok(base64_encode(&encrypted))
    }

    /// Decrypt a response
    fn decrypt_response(&self, encrypted: &str) -> Result<Value> {
        let lsk = self
            .lsk
            .as_ref()
            .ok_or_else(|| TapoError::EncryptionError("LSK not set".to_string()))?;

        let ivb = self
            .ivb
            .as_ref()
            .ok_or_else(|| TapoError::EncryptionError("IVB not set".to_string()))?;

        let encrypted_bytes = base64_decode(encrypted)?;
        let decrypted = aes_decrypt(&encrypted_bytes, lsk, ivb)?;
        let json_str = String::from_utf8(decrypted)
            .map_err(|e| TapoError::EncryptionError(format!("Invalid UTF-8: {}", e)))?;

        Ok(serde_json::from_str(&json_str)?)
    }

    /// Check if authenticated
    pub fn is_authenticated(&self) -> bool {
        self.stok.is_some()
    }

    /// Re-authenticate if needed
    pub fn ensure_authenticated(&mut self) -> Result<()> {
        if !self.is_authenticated() {
            self.authenticate()?;
        }
        Ok(())
    }
}

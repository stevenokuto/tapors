use crate::auth::{KlapAuth, TraditionalAuth};
use crate::error::{Result, TapoError};
use crate::types::{
    BasicInfo, ChildDevice, ChildDeviceListResult, DeviceInfoResult,
    MultipleRequestResponse, TapoResponse,
};
use serde_json::{json, Value};

/// Main Tapo device client
pub struct Tapo {
    host: String,
    port: u16,
    auth: AuthMethod,
}

enum AuthMethod {
    Traditional(TraditionalAuth),
    Klap(KlapAuth),
}

impl Tapo {
    /// Create a new Tapo instance
    ///
    /// # Arguments
    /// * `host` - IP address or hostname of the Tapo device
    /// * `username` - Username for authentication (typically "admin")
    /// * `password` - Device password
    ///
    /// # Example
    /// ```no_run
    /// use tapors::Tapo;
    ///
    /// let tapo = Tapo::new("192.168.1.100", "admin", "your-password").unwrap();
    /// ```
    pub fn new(host: &str, username: &str, password: &str) -> Result<Self> {
        Self::new_with_port(host, 443, username, password)
    }

    /// Create a new Tapo instance with custom port
    ///
    /// # Arguments
    /// * `host` - IP address or hostname of the Tapo device
    /// * `port` - Port number (default is 443 for HTTPS)
    /// * `username` - Username for authentication (typically "admin")
    /// * `password` - Device password
    pub fn new_with_port(host: &str, port: u16, username: &str, password: &str) -> Result<Self> {
        // Try to detect if device uses KLAP protocol
        let klap_auth = KlapAuth::new(host.to_string(), port)?;

        let auth = if klap_auth.is_klap_device() {
            // KLAP is detected but not fully implemented
            // Fall back to traditional auth
            let mut trad_auth =
                TraditionalAuth::new(host.to_string(), port, username.to_string(), password.to_string())?;
            trad_auth.authenticate()?;
            AuthMethod::Traditional(trad_auth)
        } else {
            // Use traditional HTTPS authentication
            let mut trad_auth =
                TraditionalAuth::new(host.to_string(), port, username.to_string(), password.to_string())?;
            trad_auth.authenticate()?;
            AuthMethod::Traditional(trad_auth)
        };

        Ok(Self {
            host: host.to_string(),
            port,
            auth,
        })
    }

    /// Get basic device information
    ///
    /// Returns information about the device including model, firmware version,
    /// MAC address, and other device details.
    ///
    /// # Example
    /// ```no_run
    /// use tapors::Tapo;
    ///
    /// let mut tapo = Tapo::new("192.168.1.100", "admin", "your-password").unwrap();
    /// let info = tapo.get_basic_info().unwrap();
    /// println!("Device model: {}", info.device_model);
    /// println!("Firmware version: {}", info.fw_ver);
    /// ```
    pub fn get_basic_info(&mut self) -> Result<BasicInfo> {
        match &mut self.auth {
            AuthMethod::Traditional(auth) => {
                auth.ensure_authenticated()?;

                // Use multipleRequest wrapper with getDeviceInfo method
                let request = json!({
                    "method": "multipleRequest",
                    "params": {
                        "requests": [
                            {
                                "method": "getDeviceInfo",
                                "params": {
                                    "device_info": {
                                        "name": ["basic_info"]
                                    }
                                }
                            }
                        ]
                    }
                });

                let response = auth.send_request(request)?;

                // Parse the multipleRequest response
                let multi_resp: MultipleRequestResponse = serde_json::from_value(response)
                    .map_err(|e| TapoError::InvalidResponse(format!("Failed to parse response: {}", e)))?;

                if multi_resp.error_code != 0 {
                    return Err(TapoError::DeviceError {
                        code: multi_resp.error_code,
                        msg: "Request failed".to_string(),
                    });
                }

                // Extract the first response
                let method_resp = multi_resp
                    .result
                    .responses
                    .first()
                    .ok_or_else(|| TapoError::InvalidResponse("No responses returned".to_string()))?;

                if method_resp.error_code != 0 {
                    return Err(TapoError::DeviceError {
                        code: method_resp.error_code,
                        msg: format!("Method {} failed", method_resp.method),
                    });
                }

                // Parse the device info
                let result_value = method_resp
                    .result
                    .as_ref()
                    .ok_or_else(|| TapoError::InvalidResponse("Missing result in response".to_string()))?;

                let device_info: DeviceInfoResult = serde_json::from_value(result_value.clone())
                    .map_err(|e| TapoError::InvalidResponse(format!("Failed to parse device info: {}", e)))?;

                Ok(device_info.device_info.basic_info)
            }
            AuthMethod::Klap(_) => Err(TapoError::KlapError(
                "KLAP protocol not fully supported in this version".to_string(),
            )),
        }
    }

    /// Get list of child devices
    ///
    /// Returns a list of child devices connected to this hub/gateway.
    /// This is useful for devices that act as hubs for multiple cameras or sensors.
    ///
    /// # Example
    /// ```no_run
    /// use tapors::Tapo;
    ///
    /// let mut tapo = Tapo::new("192.168.1.100", "admin", "your-password").unwrap();
    /// let children = tapo.get_child_devices().unwrap();
    /// for child in children {
    ///     println!("Child device: {} ({})", child.device_name, child.device_id);
    /// }
    /// ```
    pub fn get_child_devices(&mut self) -> Result<Vec<ChildDevice>> {
        match &mut self.auth {
            AuthMethod::Traditional(auth) => {
                auth.ensure_authenticated()?;

                let request = json!({
                    "method": "getChildDeviceList",
                    "params": {
                        "childControl": {
                            "start_index": 0
                        }
                    }
                });

                let response = auth.send_request(request)?;

                // Parse response
                let tapo_resp: TapoResponse<ChildDeviceListResult> = serde_json::from_value(response)
                    .map_err(|e| TapoError::InvalidResponse(format!("Failed to parse response: {}", e)))?;

                if tapo_resp.error_code != 0 {
                    return Err(TapoError::DeviceError {
                        code: tapo_resp.error_code,
                        msg: tapo_resp.msg.unwrap_or_else(|| "Unknown error".to_string()),
                    });
                }

                let result = tapo_resp
                    .result
                    .ok_or_else(|| TapoError::InvalidResponse("Missing result in response".to_string()))?;

                Ok(result.child_device_list)
            }
            AuthMethod::Klap(_) => Err(TapoError::KlapError(
                "KLAP protocol not fully supported in this version".to_string(),
            )),
        }
    }

    /// Execute a custom method on the device
    ///
    /// This is an advanced method that allows you to send custom commands to the device.
    /// Use this if you need functionality beyond getBasicInfo and getChildDevices.
    ///
    /// # Arguments
    /// * `method` - The method name to execute
    /// * `params` - Optional parameters for the method
    pub fn execute_method(&mut self, method: &str, params: Option<Value>) -> Result<Value> {
        match &mut self.auth {
            AuthMethod::Traditional(auth) => {
                auth.ensure_authenticated()?;

                let request = if let Some(p) = params {
                    json!({
                        "method": method,
                        "params": p
                    })
                } else {
                    json!({
                        "method": method
                    })
                };

                auth.send_request(request)
            }
            AuthMethod::Klap(_) => Err(TapoError::KlapError(
                "KLAP protocol not fully supported in this version".to_string(),
            )),
        }
    }

    /// Get the device host
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get the device port
    pub fn port(&self) -> u16 {
        self.port
    }
}

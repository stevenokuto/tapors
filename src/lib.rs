//! # Tapors - Pure Rust Tapo Camera Library
//!
//! A clean, efficient Rust implementation for communicating with TP-Link Tapo cameras.
//!
//! ## Features
//!
//! - Pure Rust implementation (no Python dependencies)
//! - Support for traditional HTTPS authentication (SHA256/MD5)
//! - AES encryption for secure communication
//! - Simple, clean API
//!
//! ## Quick Start
//!
//! ```no_run
//! use tapors::Tapo;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a Tapo instance
//!     let mut tapo = Tapo::new("192.168.1.100", "admin", "your-password")?;
//!
//!     // Get basic device information
//!     let info = tapo.get_basic_info()?;
//!     println!("Device: {} ({})", info.device_model, info.device_type);
//!     println!("Firmware: {}", info.fw_ver);
//!     println!("MAC: {}", info.mac);
//!
//!     // Get child devices (for hubs/gateways)
//!     let children = tapo.get_child_devices()?;
//!     for child in children {
//!         println!("Child: {} - {}", child.device_name, child.device_id);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Supported Methods
//!
//! - `get_basic_info()` - Get device information (model, firmware, MAC, etc.)
//! - `get_child_devices()` - Get list of child devices (for hubs)
//! - `execute_method()` - Execute custom methods for advanced usage
//!
//! ## Authentication
//!
//! The library supports traditional HTTPS authentication with both SHA256 and MD5 hashing.
//! The hash method is automatically detected during authentication.
//!
//! KLAP protocol detection is included but not fully implemented in this version.
//! Most Tapo devices work with traditional HTTPS authentication.

mod auth;
mod crypto;
mod error;
mod tapo;
mod types;

// Public API exports
pub use error::{Result, TapoError};
pub use tapo::Tapo;
pub use types::{BasicInfo, ChildDevice};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_types() {
        // Basic smoke test to ensure types are properly defined
        let info = BasicInfo {
            device_type: "camera".to_string(),
            device_model: "C200".to_string(),
            device_name: "test".to_string(),
            device_info: "test_info".to_string(),
            hw_version: "1.0".to_string(),
            sw_version: "1.0".to_string(),
            device_alias: "Test Camera".to_string(),
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            hw_id: "hw123".to_string(),
            fw_id: "fw123".to_string(),
            oem_id: "oem123".to_string(),
            fw_ver: "1.0.0".to_string(),
            additional: Default::default(),
        };

        assert_eq!(info.device_type, "camera");
        assert_eq!(info.device_model, "C200");
    }
}

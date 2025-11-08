# Tapors - Pure Rust Tapo Camera Library

A clean, efficient pure Rust implementation for communicating with TP-Link Tapo cameras.

**This is a complete rewrite from Python to Rust**, focusing on core functionality: device information and child device management.

## Features

- **Pure Rust** - No Python dependencies, fully native Rust implementation
- **Clean API** - Simple, intuitive interface with only the essentials
- **Secure Communication** - AES-128-CBC encryption for all requests
- **Flexible Authentication** - Automatic detection of SHA256/MD5 hash methods
- **Type-Safe** - Strong typing with Rust's type system
- **Error Handling** - Comprehensive error types using `thiserror`

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
tapors = { path = "." }
```

Or if published to crates.io:

```toml
[dependencies]
tapors = "0.1"
```

## Quick Start

```rust
use tapors::{Tapo, Result};

fn main() -> Result<()> {
    // Connect to your Tapo camera
    let mut tapo = Tapo::new("192.168.1.100", "admin", "your-password")?;

    // Get basic device information
    let info = tapo.get_basic_info()?;
    println!("Device: {} ({})", info.device_model, info.device_type);
    println!("Firmware: {}", info.fw_ver);
    println!("MAC: {}", info.mac);

    // Get child devices (for hubs/gateways)
    let children = tapo.get_child_devices()?;
    for child in children {
        println!("Child: {} - {}", child.device_name, child.device_id);
    }

    Ok(())
}
```

## Core API

### Creating a Tapo Instance

```rust
// Standard connection (port 443)
let mut tapo = Tapo::new("192.168.1.100", "admin", "password")?;

// Custom port
let mut tapo = Tapo::new_with_port("192.168.1.100", 8443, "admin", "password")?;
```

### Getting Device Information

```rust
let info = tapo.get_basic_info()?;

// Available fields:
println!("Device Type:  {}", info.device_type);
println!("Device Model: {}", info.device_model);
println!("Device Name:  {}", info.device_name);
println!("Firmware:     {}", info.fw_ver);
println!("Hardware:     {}", info.hw_version);
println!("MAC:          {}", info.mac);
```

### Getting Child Devices

```rust
let children = tapo.get_child_devices()?;

for child in children {
    println!("ID:    {}", child.device_id);
    println!("Name:  {}", child.device_name);
    println!("Type:  {}", child.device_type);
    println!("Model: {}", child.device_model);
}
```

### Advanced: Custom Method Execution

```rust
use serde_json::json;

// Execute any custom method
let params = json!({
    "some_param": "value"
});

let response = tapo.execute_method("customMethod", Some(params))?;
```

## Examples

Run the basic example:

```bash
cargo run --example basic_usage
```

Make sure to edit `examples/basic_usage.rs` with your camera's IP address and credentials first.

## Authentication

The library supports traditional HTTPS authentication with automatic detection of the hash method:

- **SHA256** - Used by newer firmware versions
- **MD5** - Used by older firmware versions

The correct method is automatically detected during authentication.

### Camera Account Setup

You need to create a camera account via the Tapo app:
1. Open Tapo app
2. Go to camera Settings
3. Navigate to Advanced Settings
4. Create a Camera Account
5. Use those credentials with this library

**Note:** KLAP protocol detection is included but not fully implemented. Most Tapo devices work fine with traditional HTTPS authentication.

## Architecture

The library is organized into clean, focused modules:

```
src/
├── lib.rs              # Public API and documentation
├── tapo.rs             # Main Tapo struct and methods
├── error.rs            # Error types
├── types.rs            # Data structures (BasicInfo, ChildDevice, etc.)
├── crypto.rs           # Encryption utilities (AES, hashing)
└── auth/
    ├── mod.rs          # Auth module exports
    ├── traditional.rs  # HTTPS authentication implementation
    └── klap.rs         # KLAP protocol (placeholder)
```

## Security

- All communication with the camera is encrypted using AES-128-CBC
- TLS/SSL with self-signed certificate support
- Session tokens (stok) for authenticated requests
- Password never sent in plain text (hashed with nonce)

## Error Handling

The library uses `thiserror` for comprehensive error types:

```rust
use tapors::{TapoError, Result};

match tapo.get_basic_info() {
    Ok(info) => println!("Success: {:?}", info),
    Err(TapoError::AuthenticationError(msg)) => println!("Auth failed: {}", msg),
    Err(TapoError::ConnectionError(msg)) => println!("Connection failed: {}", msg),
    Err(TapoError::DeviceError { code, msg }) => println!("Device error {}: {}", code, msg),
    Err(e) => println!("Other error: {}", e),
}
```

## Comparison with Python Version

| Feature | Python (pytapo) | Rust (tapors) |
|---------|-----------------|---------------|
| Language | Python 3.13 | Rust 2021 |
| Dependencies | requests, pycryptodome, python-kasa | Pure Rust crates |
| Basic Info | ✅ | ✅ |
| Child Devices | ✅ | ✅ |
| Media Streaming | ✅ | ❌ (out of scope) |
| Full Camera Control | ✅ (200+ methods) | ⚠️ (via execute_method) |
| KLAP Support | ✅ Full | ⚠️ Placeholder |
| Performance | Good | Excellent |
| Memory Safety | Runtime | Compile-time |

## Why Rust?

This rewrite to Rust provides:

- **Performance**: Native compiled code is significantly faster
- **Memory Safety**: No runtime errors from memory issues
- **Concurrency**: Safe concurrent access without data races
- **Type Safety**: Catch errors at compile time
- **Zero-cost Abstractions**: High-level code with low-level performance
- **No GC Pauses**: Predictable performance

## Testing

Run the test suite:

```bash
cargo test
```

Run with output:

```bash
cargo test -- --nocapture
```

## Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run examples
cargo run --example basic_usage
```

## Contributing

This is a focused implementation providing only the core functionality needed for most users:
- Device information (`get_basic_info`)
- Child device management (`get_child_devices`)

If you need additional functionality, you can use the `execute_method()` function to send custom commands.

## License

MIT License - See LICENSE file for details

## Acknowledgments

- Originally forked from [pytapo](https://github.com/JurajNyiri/pytapo) Python library
- Complete rewrite to pure Rust focusing on clean, efficient implementation
- Thanks to the original pytapo contributors for reverse engineering the Tapo protocol

## Support

For issues and questions:
- Check the [examples/](examples/) directory
- Review the inline documentation: `cargo doc --open`
- Open an issue on GitHub

## Roadmap

- [x] Core authentication (traditional HTTPS)
- [x] AES encryption/decryption
- [x] Basic device info
- [x] Child device listing
- [ ] Full KLAP protocol implementation
- [ ] Async API support
- [ ] More device control methods
- [ ] Media streaming (if requested)

---

**Note**: This library focuses on providing clean, efficient access to Tapo camera information. For advanced camera control (PTZ, privacy mode, recordings, etc.), consider extending the `execute_method()` function or using the original Python library.

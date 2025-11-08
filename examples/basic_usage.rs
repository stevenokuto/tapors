use tapors::{Result, Tapo};

fn main() -> Result<()> {
    // Replace with your device's IP address and credentials
    let host = "192.168.1.100";
    let username = "admin";
    let password = "your-password";

    println!("Connecting to Tapo device at {}...", host);

    // Create a new Tapo instance
    // This will automatically authenticate with the device
    let mut tapo = Tapo::new(host, username, password)?;

    println!("Successfully connected and authenticated!");
    println!();

    // Get basic device information
    println!("=== Device Information ===");
    let info = tapo.get_basic_info()?;

    println!("Device Type:    {}", info.device_type);
    println!("Device Model:   {}", info.device_model);
    println!("Device Name:    {}", info.device_name);
    println!("Device Alias:   {}", info.device_alias);
    println!("Hardware Ver:   {}", info.hw_version);
    println!("Firmware Ver:   {}", info.fw_ver);
    println!("MAC Address:    {}", info.mac);
    println!();

    // Get child devices (if this is a hub/gateway)
    println!("=== Child Devices ===");
    match tapo.get_child_devices() {
        Ok(children) => {
            if children.is_empty() {
                println!("No child devices found.");
            } else {
                println!("Found {} child device(s):", children.len());
                for (i, child) in children.iter().enumerate() {
                    println!("  {}. {} ({})", i + 1, child.device_name, child.device_id);
                    println!("     Type: {}", child.device_type);
                    println!("     Model: {}", child.device_model);
                    println!("     Status: {}", child.status);
                }
            }
        }
        Err(e) => {
            println!("Failed to get child devices: {}", e);
            println!("(This is normal if the device is not a hub/gateway)");
        }
    }

    Ok(())
}

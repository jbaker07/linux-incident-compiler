//! usb_monitor sensor v2
//! Sysfs usb inventory; new device insertions and class-based risk (HID/storage)

use crate::core::event_keys;
use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Collect usb_monitor events
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check 1: High-precision invariant - new USB device insertions
    events.extend(detect_new_devices(host));

    // Check 2: Heuristic - risky device classes (HID, storage)
    events.extend(detect_risky_devices(host));

    events
}

fn detect_new_devices(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Scan /sys/bus/usb/devices for USB devices
    if let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") {
        for entry in entries.flatten() {
            if let Ok(path) = entry.path().into_os_string().into_string() {
                // Extract device ID
                let device_name = path.split('/').last().unwrap_or("unknown");

                // Check if this is a device (has : in name)
                if !device_name.contains(':') {
                    continue;
                }

                // Try to read device info
                let product_path = format!("{}/product", path);
                let manufacturer_path = format!("{}/manufacturer", path);
                let serial_path = format!("{}/serial", path);

                let product = fs::read_to_string(&product_path).unwrap_or_default();
                let manufacturer = fs::read_to_string(&manufacturer_path).unwrap_or_default();
                let serial = fs::read_to_string(&serial_path).unwrap_or_default();

                // Track new devices
                let key = format!("usb:{}", device_name);
                if super::common::seen_once("usb_monitor", &key) {
                    let mut fields = BTreeMap::new();
                    fields.insert(event_keys::DEVICE_ID.to_string(), json!(device_name));
                    fields.insert(event_keys::USB_PRODUCT.to_string(), json!(product.trim()));
                    fields.insert(
                        event_keys::USB_MANUFACTURER.to_string(),
                        json!(manufacturer.trim()),
                    );
                    if !serial.trim().is_empty() {
                        fields.insert(event_keys::USB_SERIAL.to_string(), json!(serial.trim()));
                    }

                    events.push(event_builders::event(
                        host,
                        "usb_monitor",
                        "usb_device_inserted",
                        "info",
                        fields,
                    ));
                }
            }
        }
    }

    events
}

fn detect_risky_devices(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Risky device classes
    let risky_classes = vec![
        ("03", "HID"),          // Human Interface Device (keyboard, mouse, can do keylogging)
        ("08", "MASS_STORAGE"), // Mass storage (data exfiltration)
        ("09", "HUB"),          // Hub (can be used to add dangerous devices)
        ("0e", "VIDEO"),        // Video/camera (privacy concern)
        ("ff", "VENDOR"),       // Vendor-specific (highest risk)
    ];

    // Scan /sys/bus/usb/devices for risky classes
    if let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") {
        for entry in entries.flatten() {
            if let Ok(path) = entry.path().into_os_string().into_string() {
                let device_name = path.split('/').last().unwrap_or("unknown");

                // Check if this is a device
                if !device_name.contains(':') {
                    continue;
                }

                // Try to read bDeviceClass
                let class_path = format!("{}/bDeviceClass", path);
                if let Ok(class_hex) = fs::read_to_string(&class_path) {
                    let class_str = class_hex.trim();

                    for (class_id, class_name) in &risky_classes {
                        if class_str == *class_id {
                            let key = format!("risky:{}:{}", device_name, class_name);
                            if super::common::rate_limit("usb_monitor", &key, 3600000) {
                                let product = fs::read_to_string(&format!("{}/product", path))
                                    .unwrap_or_default();
                                let manufacturer =
                                    fs::read_to_string(&format!("{}/manufacturer", path))
                                        .unwrap_or_default();

                                let mut fields = BTreeMap::new();
                                fields
                                    .insert(event_keys::DEVICE_ID.to_string(), json!(device_name));
                                fields.insert(
                                    event_keys::USB_CLASS.to_string(),
                                    json!(class_name.to_string()),
                                );
                                fields.insert(
                                    event_keys::USB_PRODUCT.to_string(),
                                    json!(product.trim()),
                                );
                                fields.insert(
                                    event_keys::USB_MANUFACTURER.to_string(),
                                    json!(manufacturer.trim()),
                                );

                                let severity = match *class_id {
                                    "ff" => "high",
                                    "08" => "high",
                                    "03" => "medium",
                                    "09" => "medium",
                                    _ => "low",
                                };

                                events.push(event_builders::event(
                                    host,
                                    "usb_monitor",
                                    "risky_usb_device",
                                    severity,
                                    fields,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    events
}

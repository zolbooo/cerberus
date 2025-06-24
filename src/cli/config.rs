use ed25519_dalek::{SigningKey, pkcs8::DecodePrivateKey};
use std::path::Path;
use tracing::{Level, event, instrument};

use crate::config::{Config, InputConfig, SignedConfig};

pub fn gen_config(key_path: &Path, input_config_path: &Path, output_path: &Path) {
    if !key_path.exists() {
        eprintln!("Key file was not found.");
        return;
    }
    let key_der = std::fs::read(key_path);
    if key_der.is_err() {
        eprintln!("Failed to read key file: {}", key_der.unwrap_err());
        return;
    }
    let mut key = SigningKey::from_pkcs8_der(&key_der.unwrap());
    if key.is_err() {
        eprintln!("Failed to parse signing key: {}", key.unwrap_err());
        return;
    }

    let input_config = InputConfig::from_file(input_config_path);
    if input_config.is_err() {
        eprintln!(
            "Failed to load input config from file: {}",
            input_config.unwrap_err()
        );
        return;
    }

    let config = Config::from_input_config(input_config.unwrap(), key.as_mut().unwrap());

    let signed_config = config.unwrap().sign(key.as_mut().unwrap());
    let file = std::fs::File::create(output_path);
    if file.is_err() {
        eprintln!("Failed to create output file: {}", file.unwrap_err());
        return;
    }
    if let Err(e) = ciborium::into_writer(&signed_config, file.unwrap()) {
        eprintln!("Failed to write signed configuration: {}", e);
        return;
    }

    println!("Signed configuration written to {}", output_path.display());
}

#[instrument]
pub fn test_config(config_path: &Path) {
    if !config_path.exists() {
        event!(
            Level::ERROR,
            "Config file not found: {}",
            config_path.display()
        );
        return;
    }
    event!(
        Level::TRACE,
        "Reading config file: {}",
        config_path.display()
    );

    let signed_config = SignedConfig::from_file(config_path);
    if signed_config.is_err() {
        event!(
            Level::ERROR,
            "Failed to load signed config from file: {}",
            signed_config.as_ref().unwrap_err()
        );
        return;
    }

    let config = signed_config.unwrap().get_verified_config();
    if config.is_err() {
        event!(
            Level::ERROR,
            "Failed to load verified config: {}",
            config.as_ref().unwrap_err()
        );
        return;
    }
    println!("Configuration is valid and verified.");
}

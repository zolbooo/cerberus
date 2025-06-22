use std::path::Path;

use ed25519_dalek::{SigningKey, pkcs8::DecodePrivateKey};

use crate::config::InputConfig;

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
    let key = SigningKey::from_pkcs8_der(&key_der.unwrap());
    if key.is_err() {
        eprintln!("Failed to parse signing key: {}", key.unwrap_err());
        return;
    }

    let input_config_file = std::fs::read_to_string(input_config_path);
    if input_config_file.is_err() {
        eprintln!(
            "Failed to read input config file: {}",
            input_config_file.unwrap_err()
        );
        return;
    }
    let input_config = toml::from_str::<InputConfig>(input_config_file.unwrap().as_str());
    if input_config.is_err() {
        eprintln!(
            "Failed to parse input config: {}",
            input_config.unwrap_err()
        );
        return;
    }

    let signed_config =
        crate::config::prepare_signed_config(input_config.unwrap(), &mut key.unwrap());
    if signed_config.is_err() {
        eprintln!(
            "Failed to prepare signed config: {}",
            signed_config.unwrap_err()
        );
        return;
    }

    let file = std::fs::File::create(output_path);
    if file.is_err() {
        eprintln!("Failed to create output file: {}", file.unwrap_err());
        return;
    }
    if let Err(e) = ciborium::into_writer(&signed_config.unwrap(), file.unwrap()) {
        eprintln!("Failed to write signed configuration: {}", e);
        return;
    }

    println!("Signed configuration written to {}", output_path.display());
}

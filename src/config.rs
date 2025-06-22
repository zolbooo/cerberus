use ed25519_dalek::{SigningKey, ed25519::signature::SignerMut, pkcs8::DecodePrivateKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct InputConfig {
    signing_key_path: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    app_signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedConfig {
    config: Vec<u8>,
    signature: Vec<u8>,
}

pub fn prepare_signed_config(
    input: InputConfig,
) -> Result<SignedConfig, Box<dyn std::error::Error>> {
    let signing_key_der = std::fs::read(input.signing_key_path)?;
    let mut signing_key = SigningKey::from_pkcs8_der(signing_key_der.as_slice())?;

    let executable_path = std::env::current_exe()?;
    let executable_bytes = std::fs::read(executable_path)?;
    let app_signature = signing_key.sign(executable_bytes.as_slice());

    let config = Config {
        app_signature: app_signature.to_bytes().to_vec(),
    };
    let mut config_bytes = Vec::new();
    ciborium::into_writer(&config, &mut config_bytes)?;
    let config_signature = signing_key.sign(config_bytes.as_slice());

    let signed_config = SignedConfig {
        config: config_bytes,
        signature: config_signature.to_bytes().to_vec(),
    };
    Ok(signed_config)
}

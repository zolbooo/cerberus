use std::{fs::File, path::Path};

use ed25519_dalek::{Signature, SigningKey, ed25519::signature::SignerMut};
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

#[derive(Serialize, Deserialize, Debug)]
pub struct SystemState {
    pub shadow_hash: String,
    pub passwd_hash: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InputConfig {
    system: SystemState,
    mapper_device_name: String,
}

impl InputConfig {
    pub fn from_string(input: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config: Self = toml::from_str(input)?;
        Ok(config)
    }

    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut config = std::fs::read_to_string(path)?;
        return Self::from_string(&config);
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub system_state: SystemState,
    pub mapper_device_name: String,
    pub app_signature: Vec<u8>,
}

impl Config {
    pub fn from_input_config(
        input: InputConfig,
        signing_key: &mut SigningKey,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let executable_path = std::env::current_exe()?;
        let executable_bytes = std::fs::read(executable_path)?;
        let app_signature = signing_key.sign(executable_bytes.as_slice());
        Ok(Config {
            system_state: input.system,
            mapper_device_name: input.mapper_device_name,
            app_signature: app_signature.to_bytes().to_vec(),
        })
    }

    pub fn sign(&self, signing_key: &mut SigningKey) -> SignedConfig {
        let mut config_bytes = Vec::new();
        ciborium::into_writer(self, &mut config_bytes).expect("Failed to serialize config");
        let signature = signing_key.sign(config_bytes.as_slice());
        SignedConfig {
            config_bytes,
            signature: signature.to_bytes().to_vec(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedConfig {
    config_bytes: Vec<u8>,
    signature: Vec<u8>,
}

impl SignedConfig {
    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let signed_config: SignedConfig = ciborium::from_reader(file)?;
        Ok(signed_config)
    }

    #[instrument(skip_all)]
    pub fn get_verified_config(&self) -> Result<Config, Box<dyn std::error::Error>> {
        let signature = Signature::try_from(self.signature.as_slice())?;
        crate::integrity::APP_PUBLIC_KEY.verify_strict(self.config_bytes.as_slice(), &signature)?;
        debug!("Config signature verified successfully");

        let config: Config = ciborium::from_reader(self.config_bytes.as_slice())?;
        config.verify_executable_signature()?;
        return Ok(config);
    }
}

mod test {
    use super::*;
    use ed25519_dalek::{
        SigningKey, VerifyingKey,
        pkcs8::{DecodePrivateKey, DecodePublicKey},
    };

    fn get_private_key() -> SigningKey {
        SigningKey::from_pkcs8_der(include_bytes!("test/signing-key")).unwrap()
    }
    fn get_public_key() -> VerifyingKey {
        VerifyingKey::from_public_key_der(include_bytes!("test/signing-key.pub")).unwrap()
    }

    #[test]
    fn test_sign_config() {
        let input_config = InputConfig::from_string(include_str!("test/example-config.toml"));
        assert!(input_config.is_ok());
        let input_config = input_config.unwrap();

        let mut signing_key = get_private_key();
        let config = Config::from_input_config(input_config, &mut signing_key);
        assert!(config.is_ok());
        let config = config.unwrap();
        let signed_config = config.sign(&mut signing_key);
        assert!(!signed_config.config_bytes.is_empty());
        assert!(!signed_config.signature.is_empty());
    }

    #[test]
    fn test_signed_config() {
        let input_config = InputConfig {
            system: SystemState {
                shadow_hash: "test_shadow_hash".to_string(),
                passwd_hash: "test_passwd_hash".to_string(),
            },
            mapper_device_name: "test_mapper_device".to_string(),
        };
        let config = Config::from_input_config(input_config, &mut get_private_key());
        assert!(config.is_ok());
        let config = config.unwrap();
        let signed_config = config.sign(&mut get_private_key());
        assert!(!signed_config.config_bytes.is_empty());
        assert!(!signed_config.signature.is_empty());

        let signature = Signature::try_from(signed_config.signature.as_slice());
        assert!(signature.is_ok());
        let signature = signature.unwrap();
        assert!(
            get_public_key()
                .verify_strict(signed_config.config_bytes.as_slice(), &signature)
                .is_ok()
        );
    }
}

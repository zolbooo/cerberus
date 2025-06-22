use std::path::Path;

use ed25519_dalek::{Signature, SigningKey, ed25519::signature::SignerMut};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct InputConfig {}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub app_signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedConfig {
    config_bytes: Vec<u8>,
    signature: Vec<u8>,
}

pub fn prepare_signed_config(
    input: InputConfig,
    signing_key: &mut SigningKey,
) -> Result<SignedConfig, Box<dyn std::error::Error>> {
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
        config_bytes,
        signature: config_signature.to_bytes().to_vec(),
    };
    Ok(signed_config)
}

pub fn load_verified_config(config_path: &Path) -> Result<Config, Box<dyn std::error::Error>> {
    let signed_config_bytes = std::fs::read(config_path)?;
    let signed_config: SignedConfig = ciborium::from_reader(signed_config_bytes.as_slice())?;

    let config_signature = Signature::try_from(signed_config.signature.as_slice())?;
    crate::integrity::APP_PUBLIC_KEY
        .verify_strict(signed_config.config_bytes.as_slice(), &config_signature)?;

    let config: Config = ciborium::from_reader(signed_config.config_bytes.as_slice())?;
    config.verify_executable_signature()?;
    return Ok(config);
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
    fn test_prepare_signed_config() {
        let input_config = InputConfig {};
        let signed_config = prepare_signed_config(input_config, &mut get_private_key());
        assert!(signed_config.is_ok());
    }

    #[test]
    fn test_signed_config_signature() {
        let input_config = InputConfig {};
        let signed_config = prepare_signed_config(input_config, &mut get_private_key());
        assert!(signed_config.is_ok());
        let signed_config = signed_config.unwrap();

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

use ed25519_dalek::{Signature, VerifyingKey, pkcs8::DecodePublicKey};
use std::sync::LazyLock;
use tracing::{debug, instrument, trace};

pub static APP_PUBLIC_KEY: LazyLock<VerifyingKey> = LazyLock::new(|| {
    return VerifyingKey::from_public_key_der(include_bytes!("signing-key")).unwrap();
});

impl crate::config::Config {
    #[instrument(skip_all)]
    pub fn verify_executable_signature(&self) -> Result<(), Box<dyn std::error::Error>> {
        let executable_path = std::env::current_exe()?;
        trace!("Current executable path: {}", executable_path.display());
        let self_bytes = std::fs::read(executable_path)?;

        let app_signature = Signature::try_from(self.app_signature.as_slice())?;
        if !APP_PUBLIC_KEY
            .verify_strict(&self_bytes, &app_signature)
            .is_ok()
        {
            return Err("Executable signature verification failed".into());
        }
        debug!("Executable signature verified successfully");
        Ok(())
    }
}

use ed25519_dalek::{Signature, VerifyingKey, pkcs8::DecodePublicKey};

fn verify_executable_signature(signature: Signature) -> Result<(), Box<dyn std::error::Error>> {
    let app_public_key = include_bytes!("signing-key");
    let key = VerifyingKey::from_public_key_der(app_public_key).unwrap();

    let executable_path = std::env::current_exe()?;
    let self_bytes = std::fs::read(executable_path)?;

    if !key.verify_strict(&self_bytes, &signature).is_ok() {
        return Err("Executable signature verification failed".into());
    }
    Ok(())
}

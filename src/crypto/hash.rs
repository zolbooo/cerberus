use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::Path;

pub fn sha256_file(file_path: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut hasher = Sha256::new();
    let mut file = fs::File::open(file_path)?;
    io::copy(&mut file, &mut hasher)?;
    return Ok(hasher.finalize().into());
}

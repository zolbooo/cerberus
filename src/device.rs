use std::path::Path;

pub fn close_luks_device(path: &Path) {
    let device = cryptsetup_rs::open(path)?;
    Ok(())
}

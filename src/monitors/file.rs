use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use std::error::Error;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, atomic::Ordering};
use std::{io, thread};

#[derive(Debug)]
pub struct FileIntegrityEvent {
    pub hash: [u8; 32],
}

fn create_file_integrity_event(
    file_path: &Path,
) -> Result<FileIntegrityEvent, Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};
    use std::fs;

    let mut hasher = Sha256::new();
    let mut file = fs::File::open(file_path)?;
    io::copy(&mut file, &mut hasher)?;
    let hash = hasher.finalize();

    Ok(FileIntegrityEvent { hash: hash.into() })
}

/**
 * Monitors a file for integrity changes and sends events when the file is modified.
 *
 * Creates a thread that watches the specified file for modifications. When a modification is detected,
 * it computes the SHA-256 hash of the file and sends a `FileIntegrityEvent` to the provided channel.
 */
pub fn monitor_file_integrity(
    path: &str,
    integrity_event_tx: std::sync::mpsc::Sender<FileIntegrityEvent>,
) -> Result<(thread::JoinHandle<()>, Arc<AtomicBool>), Box<dyn Error>> {
    /*
     * This might look intimidating, but it's actually simple.
     * stop_signal is an atomic boolean that allows us to stop the thread gracefully.
     * init_result is a channel used to send the result of the initialization back to the main thread.
     */
    let stop_signal = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (init_result_tx, init_result_rx) = std::sync::mpsc::channel();

    let file_path = Path::new(path).to_owned(); // Copy borrowed path to owned PathBuf
    let thread_stop_signal = stop_signal.clone();
    let thread_handle = thread::spawn(move || {
        let (file_event_tx, file_event_rx) = std::sync::mpsc::channel();
        let mut watcher: RecommendedWatcher = match Watcher::new(file_event_tx, Config::default()) {
            Ok(w) => w,
            Err(e) => {
                init_result_tx.send(Err(Box::new(e))).unwrap();
                return;
            }
        };
        if let Err(e) = watcher.watch(&file_path, RecursiveMode::NonRecursive) {
            init_result_tx.send(Err(Box::new(e))).unwrap();
            return;
        }

        let handle_file_event = || -> Result<(), Box<dyn Error>> {
            let file_event = file_event_rx.recv()??;
            if file_event.kind.is_modify() {
                let integrity_event = create_file_integrity_event(&file_path)?;
                integrity_event_tx.send(integrity_event)?;
            }
            Ok(())
        };

        init_result_tx.send(Ok(())).unwrap();
        while thread_stop_signal.load(Ordering::Acquire) == false {
            let _ = handle_file_event();
        }
    });

    match init_result_rx.recv()? {
        Ok(()) => {}
        Err(e) => return Err(e),
    }
    if thread_handle.is_finished() {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::Other,
            "Thread has already finished",
        )));
    }
    return Ok((thread_handle, stop_signal));
}

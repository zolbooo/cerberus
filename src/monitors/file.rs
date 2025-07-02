use crate::crypto::hash::sha256_file;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use tokio::sync::mpsc::Receiver;
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};

pub enum FileIntegrityEvent {
    FileModification(FileModificationDetails),
    WatchError,
    HashError,
}
#[derive(Debug)]
pub struct FileModificationDetails {
    pub hash: [u8; 32],
}

/**
 * Monitors a file for integrity changes and sends events when the file is modified.
 * Creates a thread that watches the specified file for modifications.
 * When a modification is detected, it computes the SHA-256 hash of the file and sends a `FileIntegrityEvent` to the provided channel.
 */
pub fn monitor_file_integrity(
    path: &Path,
    cancellation_token: &CancellationToken,
) -> Receiver<FileIntegrityEvent> {
    let (tx, rx) = tokio::sync::mpsc::channel::<FileIntegrityEvent>(1);
    let file_path = path.to_owned();
    let mut last_known_hash: [u8; 32] = [0; 32];
    let token = cancellation_token.clone();
    tokio::spawn(async move {
        let watch_path = file_path.clone();
        let watcher = RecommendedWatcher::new(
            move |result| {
                if let Err(e) = result {
                    error!("Error receiving file watch event: {}", e);
                    let _ = tx.blocking_send(FileIntegrityEvent::WatchError);
                    return;
                }
                let event: Event = result.unwrap();
                if !event.kind.is_modify() {
                    return;
                }

                let hash = sha256_file(&file_path);
                if let Err(e) = hash {
                    error!("Error computing file hash: {}", e);
                    let _ = tx.blocking_send(FileIntegrityEvent::HashError);
                    return;
                }
                let file_hash = hash.unwrap();
                if file_hash != last_known_hash {
                    last_known_hash = file_hash;
                    if let Err(e) = tx.blocking_send(FileIntegrityEvent::FileModification(
                        FileModificationDetails { hash: file_hash },
                    )) {
                        warn!("Error sending file integrity event: {}", e);
                    }
                }
            },
            Config::default(),
        );
        if let Err(e) = watcher {
            error!("Error watching file: {}", e);
            return;
        }
        let mut watcher = watcher.unwrap();
        if let Err(e) = watcher.watch(&watch_path, RecursiveMode::NonRecursive) {
            error!("Error watching file: {}", e);
            return;
        }
        token.cancelled().await;
        if let Err(e) = watcher.unwatch(&watch_path) {
            error!("Error unwatching file: {}", e);
        }
    });
    return rx;
}

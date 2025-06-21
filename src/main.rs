mod crypto;
mod monitors;

const WATCH_FILE: &str = "watch.txt";

fn hex_encode(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn watch_file() -> Result<(), Box<dyn std::error::Error>> {
    let mut err_counter = 0;

    let (event_tx, event_rx) = std::sync::mpsc::channel();
    let (thread_handle, stop_signal) =
        monitors::file::monitor_file_integrity(WATCH_FILE, event_tx)?;
    println!("Watching file: {}", WATCH_FILE);

    loop {
        match event_rx.recv() {
            Ok(event) => {
                println!("Received file integrity event: {}", hex_encode(event.hash));
            }
            Err(e) => {
                eprintln!("Error receiving file integrity event: {}", e);
                err_counter += 1;
                if err_counter >= 3 {
                    eprintln!("Too many errors, stopping file monitoring.");
                    stop_signal.store(true, std::sync::atomic::Ordering::SeqCst);
                    thread_handle.join().expect("Thread panicked");
                    break;
                }
            }
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = watch_file() {
        eprintln!("Error watching file: {}", e);
    }
}

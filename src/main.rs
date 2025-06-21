use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;

const WATCH_FILE: &str = "watch.txt";

fn watch_file() -> Result<(), Box<dyn std::error::Error>> {
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher: RecommendedWatcher = Watcher::new(tx, Config::default())?;
    watcher.watch(Path::new(WATCH_FILE), RecursiveMode::NonRecursive)?;

    loop {
        match rx.recv() {
            Ok(event) => println!("Received event: {:?}", event),
            Err(e) => eprintln!("Error receiving event: {}", e),
        }
    }
}

fn main() {
    if let Err(e) = watch_file() {
        eprintln!("Error watching file: {}", e);
    }
}

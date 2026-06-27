use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const FRAMES: &[&str] =
    &["|", "/", "-", "\\", "|", "/", "-", "\\"];

pub struct Spinner {
    running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Spinner {
    pub fn start(message: &str) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        let msg = message.to_string();

        let handle = thread::spawn(move || {
            let mut i = 0;
            while running_clone.load(Ordering::Relaxed) {
                let frame = FRAMES[i % FRAMES.len()];
                print!("\r[{}] {}", frame, msg);
                let _ = io::stdout().flush();
                i += 1;
                thread::sleep(Duration::from_millis(100));
            }
            print!("\r{}\r", " ".repeat(msg.len() + 5));
            let _ = io::stdout().flush();
        });

        Spinner {
            running,
            handle: Some(handle),
        }
    }

    pub fn stop(mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

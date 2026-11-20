use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use lumenic::Waker;

pub struct SingleInstanceGuard {
    listener: TcpListener,
    port_file: PathBuf,
}

impl SingleInstanceGuard {
    /// Acquires a single-instance lock in `lock_dir`.
    /// Returns `None` if another instance is already running (after signaling it to focus).
    pub fn acquire(lock_dir: &Path) -> Option<Self> {
        let _ = std::fs::create_dir_all(lock_dir);
        let port_file = lock_dir.join("deltadrop.instance");
        if let Ok(raw) = std::fs::read_to_string(&port_file) {
            if let Ok(port) = raw.trim().parse::<u16>() {
                if let Ok(mut stream) = TcpStream::connect_timeout(
                    &([127, 0, 0, 1], port).into(),
                    std::time::Duration::from_millis(250),
                ) {
                    let _ = stream.write_all(b"FOCUS\n");
                    return None;
                }
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").ok()?;
        let port = listener.local_addr().ok()?.port();
        let _ = std::fs::write(&port_file, port.to_string());
        Some(Self {
            listener,
            port_file,
        })
    }

    pub fn spawn_focus_listener(self, waker: Waker, focus_flag: Arc<AtomicBool>) {
        std::thread::spawn(move || {
            for stream in self.listener.incoming().flatten() {
                let mut s = stream;
                let mut buf = [0u8; 16];
                if let Ok(n) = s.read(&mut buf) {
                    if &buf[..n] == b"FOCUS\n" {
                        focus_flag.store(true, Ordering::SeqCst);
                        waker.wake();
                    }
                }
            }
            let _ = std::fs::remove_file(&self.port_file);
        });
    }
}

pub fn is_autostart_enabled() -> bool {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("reg")
            .args([
                "query",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "DeltaDrop",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        autostart_desktop_path().is_file()
    }
    #[cfg(target_os = "macos")]
    {
        autostart_plist_path().is_file()
    }
}

pub fn set_autostart(enabled: bool) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let exe_str = exe.to_string_lossy();

    #[cfg(target_os = "windows")]
    {
        if enabled {
            let val = format!("\"{exe_str}\" --minimized");
            let status = std::process::Command::new("reg")
                .args([
                    "add",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "/v",
                    "DeltaDrop",
                    "/t",
                    "REG_SZ",
                    "/d",
                    &val,
                    "/f",
                ])
                .status()?;
            if !status.success() {
                anyhow::bail!("Failed to register startup entry");
            }
        } else {
            let _ = std::process::Command::new("reg")
                .args([
                    "delete",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "/v",
                    "DeltaDrop",
                    "/f",
                ])
                .status();
        }
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let path = autostart_desktop_path();
        if enabled {
            if let Some(p) = path.parent() {
                std::fs::create_dir_all(p)?;
            }
            let desktop = format!(
                "[Desktop Entry]\nType=Application\nName=DeltaDrop\nExec=\"{exe_str}\" --minimized\nX-GNOME-Autostart-enabled=true\n"
            );
            std::fs::write(&path, desktop)?;
        } else if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let path = autostart_plist_path();
        if enabled {
            if let Some(p) = path.parent() {
                std::fs::create_dir_all(p)?;
            }
            let plist = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key><string>com.deltadrop.client</string>\n  <key>ProgramArguments</key><array><string>{exe_str}</string><string>--minimized</string></array>\n  <key>RunAtLoad</key><true/>\n</dict>\n</plist>\n"
            );
            std::fs::write(&path, plist)?;
        } else if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        Ok(())
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn autostart_desktop_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".config")
        });
    base.join("autostart").join("deltadrop.desktop")
}

#[cfg(target_os = "macos")]
fn autostart_plist_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Library")
        .join("LaunchAgents")
        .join("com.deltadrop.client.plist")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_instance_guard_blocks_second_instance() {
        let dir = tempfile::tempdir().unwrap();
        let g1 = SingleInstanceGuard::acquire(dir.path());
        assert!(g1.is_some(), "first instance must acquire lock");
        let g2 = SingleInstanceGuard::acquire(dir.path());
        assert!(
            g2.is_none(),
            "second instance must detect existing listener"
        );
    }
}

//! Configuration hot reload driven by filesystem events.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::gateway::Gateway;

const DEBOUNCE: Duration = Duration::from_millis(200);

/// Re-reads `path` and applies it. Invalid configs are logged and counted;
/// the running configuration stays in place.
pub fn reload(path: &Path, gateway: &Gateway) -> bool {
    let result = Config::from_path(path)
        .map_err(|e| e.to_string())
        .and_then(|cfg| gateway.apply(cfg).map_err(|e| e.to_string()));
    let label = if result.is_ok() { "success" } else { "error" };
    gateway
        .metrics()
        .config_reloads
        .with_label_values(&[label])
        .inc();
    match result {
        Ok(()) => {
            tracing::info!(path = %path.display(), "configuration reloaded");
            true
        }
        Err(e) => {
            tracing::error!(path = %path.display(), error = %e, "configuration rejected; keeping previous");
            false
        }
    }
}

/// Watches the config file's directory (editors and Kubernetes ConfigMaps
/// replace files rather than writing in place) and reloads on change. The
/// returned watcher must be kept alive.
pub fn watch(
    path: PathBuf,
    gateway: Arc<Gateway>,
    cancel: CancellationToken,
) -> notify::Result<RecommendedWatcher> {
    let path = std::fs::canonicalize(&path).unwrap_or(path);
    let dir = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let file_name = path.file_name().map(|n| n.to_os_string());

    let (tx, mut rx) = mpsc::unbounded_channel::<()>();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        let Ok(event) = res else { return };
        if event.kind.is_access() {
            return;
        }
        // ConfigMap updates swap a `..data` symlink, so any change in the
        // directory is treated as relevant when the file name does not match.
        let relevant = event.paths.iter().any(|p| {
            p.file_name().map(|n| n.to_os_string()) == file_name
                || p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(".."))
        });
        if relevant {
            let _ = tx.send(());
        }
    })?;
    watcher.watch(&dir, RecursiveMode::NonRecursive)?;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                msg = rx.recv() => if msg.is_none() { break },
            }
            tokio::time::sleep(DEBOUNCE).await;
            while rx.try_recv().is_ok() {}
            reload(&path, &gateway);
        }
    });
    Ok(watcher)
}

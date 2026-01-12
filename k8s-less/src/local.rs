// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use inotify::{Event, EventMask, Inotify, WatchMask};
use k8s_intf::gateway_agent_crd::GatewayAgent;
use k8s_intf::utils::load_crd_from_file;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use tokio::fs::create_dir_all;
use tokio::io::unix::AsyncFd;

#[allow(unused)]
use tracing::{debug, error, trace, warn};

/// Tell if an event reported by `Inotify` is worth checking according
/// to our configuration. This function is somewhat heuristic to accommodate
/// for changes done by text editors, which may create temporary files when
/// editing them instead of modifying them in-place. This helper returns
/// the name of the file to process or `None` if the event should be ignored.
fn check_event(event: &Event<&OsStr>, dir: &str) -> Option<PathBuf> {
    // trace!("event: {:?}, name: {:?}", event.mask, event.name);

    // we watch a directory; so `Inotify` should report the name of a file.
    let filename = event.name?;

    // OsStr should be valid Unicode
    let filename = filename.to_str()?;

    // some editors create '.swp/.swx' (e.g. nano) files or temporary hidden files (vi)
    if filename.contains(".sw") || filename.starts_with('.') {
        return None;
    }

    // This is sanity
    if event.mask != EventMask::CLOSE_WRITE {
        return None;
    }

    // name of file to read a crd spec from
    Some(Path::new(dir).join(filename))
}

/// Watch for changes in the directory named `path`. If the directory does not exist,
/// it gets created. When files are created or modified in the watched directory:
///    - read their contents (assumed to contain a crd spec in yaml or json)
///    - deserialize them into a `GatewayAgentSpec`
///    - build a GatewayAgent object
///    - call the caller-specified callback.
///
/// The generation id of the GatewayAgent is automatically set by this function and
/// monotonically increases every time a `GatewayAgentSpec` is successfully deserialized
/// from a file.
///
/// # Errors
/// Returns an error if the directory or the corresponding watch cannot be created.
pub async fn kubeless_watch_gateway_agent_crd(
    gwname: &str,
    path: &str,
    callback: impl AsyncFn(&GatewayAgent),
) -> Result<(), String> {
    create_dir_all(path)
        .await
        .map_err(|e| format!("Failed to create directory '{path}': {e}"))?;

    let mut inotify = Inotify::init().map_err(|e| format!("Failed to initialize inotify: {e}"))?;
    inotify
        .watches()
        .add(Path::new(path), WatchMask::CLOSE_WRITE)
        .map_err(|e| format!("Failed to add watch for path {path}: {e}"))?;

    // generation id is automatically set and will monotonically increase
    let mut generation: i64 = 1;

    let async_fd = AsyncFd::new(inotify.as_raw_fd())
        .map_err(|e| format!("Failed to create async fd for inotify: {e}"))?;

    debug!("Starting kubeless watcher for directory '{path}'...");
    loop {
        trace!("Waiting for changes...");
        let Ok(mut guard) = async_fd.readable().await else {
            error!("Failure checking async fd readiness");
            continue;
        };

        let mut buffer = [0u8; 4096];
        match inotify.read_events(&mut buffer) {
            Ok(events) => {
                // collapse all events by filename: `check_event` will filter out unwanted events.
                let files: BTreeSet<PathBuf> =
                    events.filter_map(|e| check_event(&e, path)).collect();

                // iterate over the set of files. Deserialize their contents and call user callback.
                for file in files.iter() {
                    debug!("Processing file {file:#?}...");
                    match load_crd_from_file(file.to_str().unwrap()) {
                        Ok(crd_spec) => {
                            let mut crd = GatewayAgent::new(gwname, crd_spec);
                            crd.metadata.generation = Some(generation);
                            crd.metadata.namespace = Some("fab".to_string());
                            generation += 1;
                            callback(&crd).await;
                        }
                        Err(e) => error!("Failed to load crd spec from file: {e}"),
                    };
                }
            }
            Err(e) => error!("Failed to read events from file: {e}"),
        }
        guard.clear_ready();
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::kubeless_watch_gateway_agent_crd;
    use tracing::debug;
    use tracing_test::traced_test;

    #[tokio::test]
    #[traced_test]
    async fn test_kubeless() {
        let path = "/tmp/kubeless-dir";
        let gwname = "test-gw";

        // spawn a task to create a config file in the directory watched by kubeless
        tokio::spawn(async move {
            // wait 2 seconds before creating config
            tokio::time::sleep(Duration::from_secs(2)).await;

            // build minimal config for us to know that it was deserialized successfully
            let yaml = "
agentVersion: MINIMAL
gateway:
  asn: 65000
";
            let mut filepath = PathBuf::from(path).join("minimal-config");
            filepath.add_extension("yaml");
            let mut file = File::create(filepath.to_str().unwrap()).unwrap();
            file.write_all(yaml.as_bytes()).unwrap();
        });

        // start watcher. Watcher will exit as soon as a config is detected and successfully
        // deserialized into a GatewayAgent object
        kubeless_watch_gateway_agent_crd(gwname, path, async move |crd| {
            let generation = crd.metadata.generation.unwrap();
            let name = crd.metadata.name.as_ref().unwrap();
            let asn = crd.spec.gateway.as_ref().unwrap().asn.unwrap();
            let agent_version = crd.spec.agent_version.as_ref().unwrap();
            debug!("Got CRD to chew:\n generation: {generation}\n name: {name}\n agentVersion: {agent_version}\n asn: {asn}");
            assert_eq!(generation, 1);
            assert_eq!(name, "test-gw");
            assert_eq!(agent_version, "MINIMAL");
            assert_eq!(asn, 65000);
            std::process::exit(0);
        })
        .await
        .unwrap();
    }
}

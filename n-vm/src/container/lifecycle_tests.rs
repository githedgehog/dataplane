// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::time::Duration;

const IMAGE_ID: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Request {
    method: String,
    url: String,
    body: Vec<u8>,
}

// A separate thread lets Drop finish cleanup while the test runtime is blocked.
fn daemon(
    responses: Vec<(u16, String)>,
) -> (bollard::Docker, std::thread::JoinHandle<Vec<Request>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let client =
        bollard::Docker::connect_with_http(&address, 5, bollard::API_DEFAULT_VERSION).unwrap();
    let server = std::thread::spawn(move || {
        responses
            .into_iter()
            .map(|(status, body)| {
                let (stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).unwrap();
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap().to_owned();
                let url = parts.next().unwrap().to_owned();
                let mut length = 0;
                loop {
                    line.clear();
                    assert_ne!(stream.read_line(&mut line).unwrap(), 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap();
                    }
                }
                let mut request_body = vec![0; length];
                stream.read_exact(&mut request_body).unwrap();
                write!(
                    stream.get_mut(),
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                )
                .unwrap();
                Request { method, url, body: request_body }
            })
            .collect()
    });
    (client, server)
}

fn imported() -> (u16, String) {
    (200, format!("{{\"status\":\"{IMAGE_ID}\"}}\n"))
}

fn created() -> (u16, String) {
    (201, r#"{"Id":"test-container","Warnings":[]}"#.into())
}

fn empty() -> (u16, String) {
    (204, String::new())
}

fn removed_image() -> (u16, String) {
    (200, "[]".into())
}

fn failed() -> (u16, String) {
    (500, r#"{"message":"injected failure"}"#.into())
}

fn assert_cleanup(requests: &[Request], container: bool) {
    let paths: Vec<_> = requests
        .iter()
        .map(|request| {
            assert_eq!(request.method, "DELETE");
            assert!(!request.url.contains("force=true") || request.url.contains("/containers/"));
            request
                .url
                .split('?')
                .next()
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap()
        })
        .collect();
    if container {
        assert_eq!(paths, ["test-container", IMAGE_ID]);
    } else {
        assert_eq!(paths, [IMAGE_ID]);
    }
}

#[tokio::test]
async fn containers_use_private_image_ids_and_remove_them_after_exit() {
    let (client, server) = daemon(vec![
        imported(),
        created(),
        empty(),
        (200, r#"{"State":{"ExitCode":17}}"#.into()),
        empty(),
        removed_image(),
    ]);
    let guard = ContainerGuard::create_and_start(&client, ContainerCreateBody::default())
        .await
        .unwrap();
    assert_eq!(guard.into_result().await.unwrap().exit_code, Some(17));
    let requests = server.join().unwrap();
    assert!(requests[0].url.contains("/images/create?"));
    assert!(requests[0].url.contains("fromSrc=-"));
    assert!(!requests[0].url.contains("repo="));
    assert!(!requests[0].url.contains("tag="));
    assert_eq!(requests[0].body, vec![0; 1024]);
    let config: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(config["Image"], IMAGE_ID);
    assert_cleanup(&requests[4..], true);
}

#[tokio::test]
async fn failed_container_creation_removes_the_image() {
    let (client, server) = daemon(vec![imported(), failed(), removed_image()]);
    let result = ContainerGuard::create_and_start(&client, ContainerCreateBody::default()).await;
    assert!(matches!(result, Err(ContainerError::ContainerCreate(_))));
    assert_cleanup(&server.join().unwrap()[2..], false);
}

#[tokio::test]
async fn failed_container_start_removes_the_container_and_image() {
    let (client, server) = daemon(vec![
        imported(),
        created(),
        failed(),
        empty(),
        removed_image(),
    ]);
    let result = ContainerGuard::create_and_start(&client, ContainerCreateBody::default()).await;
    assert!(matches!(result, Err(ContainerError::ContainerStart(_))));
    assert_cleanup(&server.join().unwrap()[3..], true);
}

#[tokio::test]
async fn dropping_a_guard_finishes_cleanup_before_returning() {
    let (client, server) = daemon(vec![
        imported(),
        created(),
        empty(),
        empty(),
        removed_image(),
    ]);
    let guard = ContainerGuard::create_and_start(&client, ContainerCreateBody::default())
        .await
        .unwrap();
    drop(guard);
    assert_cleanup(&server.join().unwrap()[3..], true);
}

#[tokio::test]
async fn failed_image_cleanup_is_retried_without_removing_the_container_twice() {
    let (client, server) = daemon(vec![
        imported(),
        created(),
        empty(),
        (200, r#"{"State":{"ExitCode":0}}"#.into()),
        empty(),
        failed(),
        removed_image(),
    ]);
    let guard = ContainerGuard::create_and_start(&client, ContainerCreateBody::default())
        .await
        .unwrap();
    assert!(matches!(
        guard.into_result().await,
        Err(ContainerError::ScratchImageRemove(_))
    ));
    let requests = server.join().unwrap();
    assert_cleanup(&requests[4..6], true);
    assert_cleanup(&requests[6..], false);
}

#[tokio::test]
async fn import_errors_and_missing_ids_prevent_container_creation() {
    for response in [
        failed(),
        (
            200,
            "{\"errorDetail\":{\"message\":\"import failed\"}}\n".into(),
        ),
        (200, "{\"status\":\"unpacking\"}\n".into()),
        (200, "{\"status\":\"sha256:invalid\"}\n".into()),
    ] {
        let (client, server) = daemon(vec![response]);
        let result =
            ContainerGuard::create_and_start(&client, ContainerCreateBody::default()).await;
        assert!(matches!(result, Err(ContainerError::ScratchImageCreate(_))));
        assert_eq!(server.join().unwrap().len(), 1);
    }
}

#[tokio::test]
#[ignore = "requires Docker and a shared /nix/store"]
async fn concurrent_containers_keep_their_images_until_cleanup() {
    let client = bollard::Docker::connect_with_unix_defaults().unwrap();
    let command = find_on_path("sh").expect("shell executable");
    let results = futures::future::join_all((0..16).map(|_| async {
        let config = ContainerCreateBody {
            cmd: Some(vec![command.clone(), "-c".into(), "exit 0".into()]),
            host_config: Some(HostConfig {
                network_mode: Some("none".into()),
                mounts: Some(vec![ContainerParams::read_only_bind_mount(
                    "/nix/store",
                    "/nix/store".into(),
                )]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let guard = ContainerGuard::create_and_start(&client, config).await?;
        let image_id = guard.resources.as_ref().unwrap().image_id.clone();
        let image = client.inspect_image(&image_id).await.unwrap();
        assert!(image.repo_tags.unwrap_or_default().is_empty());
        guard.stream_logs().await?;
        let outcome = guard.into_result().await?;
        assert_eq!(outcome.exit_code, Some(0));
        assert!(matches!(
            client.inspect_image(&image_id).await,
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404,
                ..
            })
        ));
        Ok::<_, ContainerError>(image_id)
    }))
    .await;
    let ids: std::collections::HashSet<_> = results.into_iter().map(Result::unwrap).collect();
    assert_eq!(ids.len(), 16);
}

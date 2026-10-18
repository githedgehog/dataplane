// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Fetching a gateway's Prometheus exposition over plain HTTP, as a scraper would.
//!
//! Plain `HTTP/1.0` over a `TcpStream`: the endpoint is on the fabric's management network, serves
//! one small text document, and a client library would be more code than the request.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// How long a scrape may take, connecting and reading.
const TIMEOUT: Duration = Duration::from_secs(2);

/// The body behind `url`, `http://host:port/path`.
///
/// # Errors
///
/// A description of what went wrong: a URL that is not `http://`, a connection refused or timed
/// out, or a status other than 200.
pub fn fetch(url: &str) -> Result<String, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("{url} is not an http:// URL"))?;
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let path = if path.is_empty() { "/" } else { path };
    let address = authority
        .to_socket_addrs()
        .map_err(|e| format!("{authority}: {e}"))?
        .next()
        .ok_or_else(|| format!("{authority} resolves to nothing"))?;
    let mut stream =
        TcpStream::connect_timeout(&address, TIMEOUT).map_err(|e| format!("{address}: {e}"))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    // One write, so the request arrives whole.
    let request = format!("GET {path} HTTP/1.0\r\nHost: {authority}\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("{url}: {e}"))?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("{url}: no end to the response headers"))?;
    let status = head.lines().next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("200") {
        return Err(format!("{url}: {status}"));
    }
    Ok(body.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::net::TcpListener;

    #[test]
    fn a_body_is_fetched_and_a_bad_status_refused() {
        for (status, want) in [
            ("200 OK", Ok("a 1\n".to_string())),
            ("404 Not Found", Err(())),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}/metrics", listener.local_addr().unwrap());
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                assert!(String::from_utf8_lossy(&request).starts_with("GET /metrics HTTP/1.0"));
                let response =
                    format!("HTTP/1.0 {status}\r\nContent-Type: text/plain\r\n\r\na 1\n");
                stream.write_all(response.as_bytes()).unwrap();
            });
            let got = fetch(&url);
            server.join().unwrap();
            match want {
                Ok(body) => assert_eq!(got.unwrap(), body),
                Err(()) => assert!(got.is_err()),
            }
        }
        assert!(fetch("https://example.invalid/").is_err());
    }
}

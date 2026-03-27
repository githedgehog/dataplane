// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::VecDeque;
use std::os::unix::net::{SocketAddr, UnixDatagram};

pub(crate) struct IoChunk {
    addr: SocketAddr,
    data: Box<[u8]>,
}
#[derive(Default)]
pub(crate) struct IoCache(VecDeque<IoChunk>);

impl IoCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push(&mut self, addr: SocketAddr, data: &[u8]) {
        let chunk = IoChunk {
            addr,
            data: Box::from(data),
        };
        self.0.push_back(chunk);
    }
    pub fn drain(&mut self, sock: &UnixDatagram) {
        while let Some(chunk) = self.0.pop_front() {
            if let Err(e) = sock.send_to_addr(&chunk.data, &chunk.addr) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    self.0.push_front(chunk);
                } else {
                    self.clear();
                }
                return;
            }
        }
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn clear(&mut self) {
        self.0.clear();
    }
}

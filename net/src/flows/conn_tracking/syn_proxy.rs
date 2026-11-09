// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! State of a TCP connection set up through a SYN proxy.
//!
//! The proxy answers the client's SYN itself, with a SYN cookie as its initial sequence number,
//! and opens the connection to the server only once the client has echoed the cookie. The server
//! picks another initial sequence number, so the proxy shifts the sequence numbers of the server
//! for the whole connection. Both flows of the pair share this state.

use crate::tcp::TcpMss;
use concurrency::sync::OnceLock;

/// The shift between the sequence numbers that the server uses and the ones the client expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeqOffset(u32);

impl SeqOffset {
    /// The offset for a connection where the proxy picked `cookie` as its initial sequence number
    /// towards the client, and the server picked `server_isn`.
    #[must_use]
    pub fn new(cookie: u32, server_isn: u32) -> Self {
        SeqOffset(cookie.wrapping_sub(server_isn))
    }

    /// Translate a sequence number of the server, on a segment going to the client.
    #[must_use]
    pub fn server_to_client(self, seq: u32) -> u32 {
        seq.wrapping_add(self.0)
    }

    /// Translate an acknowledgment number of the client, on a segment going to the server.
    #[must_use]
    pub fn client_to_server(self, ack: u32) -> u32 {
        ack.wrapping_sub(self.0)
    }
}

/// State of a connection set up through the SYN proxy, shared by the two flows of its pair.
#[derive(Debug)]
pub struct SynProxyState {
    client_isn: u32,
    cookie: u32,
    mss: TcpMss,
    window: u16,
    // Set once the server answers: until then, the proxy is still opening the connection
    offset: OnceLock<SeqOffset>,
}

impl SynProxyState {
    /// The state of a connection for which the client echoed `cookie` after a SYN with initial
    /// sequence number `client_isn`, with the MSS `mss` recovered from the cookie, and the window
    /// `window` that the client advertised when echoing the cookie.
    #[must_use]
    pub fn new(client_isn: u32, cookie: u32, mss: TcpMss, window: u16) -> Self {
        Self {
            client_isn,
            cookie,
            mss,
            window,
            offset: OnceLock::new(),
        }
    }

    /// The initial sequence number of the client.
    #[must_use]
    pub fn client_isn(&self) -> u32 {
        self.client_isn
    }

    /// The initial sequence number of the proxy towards the client.
    #[must_use]
    pub fn cookie(&self) -> u32 {
        self.cookie
    }

    /// The MSS of the client, as the cookie recorded it.
    #[must_use]
    pub fn mss(&self) -> TcpMss {
        self.mss
    }

    /// The window that the client advertised when echoing the cookie, without scaling: the proxy
    /// negotiates no window scaling.
    #[must_use]
    pub fn window(&self) -> u16 {
        self.window
    }

    /// The offset to apply to the sequence numbers of the server, once it has answered.
    #[must_use]
    pub fn offset(&self) -> Option<SeqOffset> {
        self.offset.get().copied()
    }

    /// Record the initial sequence number of the server, and return the resulting offset. If
    /// another packet recorded one first, keep it and return it.
    pub fn set_server_isn(&self, server_isn: u32) -> SeqOffset {
        *self
            .offset
            .get_or_init(|| SeqOffset::new(self.cookie, server_isn))
    }
}

#[cfg(test)]
mod test {
    use super::{SeqOffset, SynProxyState};
    use crate::tcp::TcpMss;

    // The server's sequence numbers land where the client expects them, and the client's
    // acknowledgments where the server expects them, across wrap-arounds.
    #[test]
    fn offset_translates_both_ways() {
        bolero::check!()
            .with_type()
            .for_each(|(cookie, server_isn, n): &(u32, u32, u32)| {
                let offset = SeqOffset::new(*cookie, *server_isn);
                let server_seq = server_isn.wrapping_add(*n);
                let client_seq = cookie.wrapping_add(*n);
                assert_eq!(offset.server_to_client(server_seq), client_seq);
                assert_eq!(offset.client_to_server(client_seq), server_seq);
            });
    }

    #[test]
    fn first_server_isn_wins() {
        let mss = TcpMss::new(1460).unwrap();
        let state = SynProxyState::new(100, 1000, mss, 1024);
        assert_eq!(state.offset(), None);
        let offset = state.set_server_isn(5000);
        assert_eq!(state.set_server_isn(7000), offset);
        assert_eq!(state.offset(), Some(offset));
        assert_eq!(offset.server_to_client(5001), 1001);
    }
}

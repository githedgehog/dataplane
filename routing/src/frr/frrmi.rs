// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use chrono::{DateTime, Local};
use mio::net::UnixStream;
use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::str::from_utf8;
use std::time::Instant;
use std::{collections::VecDeque, time::Duration};
use thiserror::Error;

use crate::config::FrrConfig;
use crate::revent::{ROUTER_EVENTS, RouterEvent, revent};
use config::GenId;

#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

#[derive(Error, Debug)]
pub(crate) enum FrrErr {
    #[error("No connection to frr-agent exists")]
    NotConnected,

    #[error("Peer left")]
    PeerLeft,

    #[error("Decoding error")]
    DecodeFailure,

    #[error("IO failure: {0}")]
    IOFailure(String),

    #[error("Busy")]
    IOBusy,
}

///////////////////////////////////////////////////////////////////////////////////////////////////
/// FRR management interface (FrrMi):
///   * Interface to frr-agent based on unix stream sockets.
///   * The `Frrmi` accepts requests that get queued into it and attempts to send them to the
///     to the frr-agent, dealing with connections and the reception of responses.
///////////////////////////////////////////////////////////////////////////////////////////////////
#[derive(Default)]
pub(crate) struct Frrmi {
    sock: Option<UnixStream>,         /* socket to frr-agent (non-blocking) */
    remote: String,                   /* address of frr-agent */
    writeb: IoBuffer,                 /* write buffer for tx */
    readb: IoBuffer,                  /* read buffer for rx */
    inservice: Option<FrrmiRequest>,  /* the request currently being serviced */
    timeout: Option<Instant>,         /* timeout for the current request in service */
    requests: VecDeque<FrrmiRequest>, /* queue of other requests to frr-agent */
    stats: FrrmiStats,                /* stats */
    applied_cfg: Option<FrrAppliedConfig>, /* last successfully applied config */
}

#[derive(Clone, Debug)]
pub struct FrrAppliedConfig {
    pub genid: GenId,
    pub cfg: FrrConfig,
}
impl FrrAppliedConfig {
    fn new(genid: GenId, cfg: FrrConfig) -> Self {
        Self { genid, cfg }
    }
}

/// Stats for the `Frrmi`
#[derive(Default)]
pub(crate) struct FrrmiStats {
    pub(crate) last_conn_time: Option<DateTime<Local>>, /* the last time that connecting to frr-agent succeeded */
    pub(crate) last_disconn_time: Option<DateTime<Local>>, /* the time when the last disconnect happened */
    pub(crate) last_ok_genid: Option<GenId>,               /* genid of the last applied config */
    pub(crate) last_fail_genid: Option<GenId>, /* genid of the most recent config that failed (excluding communication errors) */
    pub(crate) last_ok_time: Option<DateTime<Local>>, /* time when last config succeeded */
    pub(crate) last_fail_time: Option<DateTime<Local>>, /* time when last config failed */
    pub(crate) apply_oks: u64,                 /* number of configs applied successfully */
    pub(crate) apply_failures: u64,            /* number of times applying a config failed */
}

pub(crate) struct FrrmiRequest {
    genid: GenId,    /* gen id this frr-config corresponds to */
    cfg: FrrConfig,  /* confif to frr-agent is a string */
    max_retries: u8, /* max number of times to retry configuration on failure */
}

const CLEAN_CONFIG: &'static str = "! Empty config";

impl FrrmiRequest {
    pub(crate) fn new(genid: GenId, cfg: String, max_retries: u8) -> Self {
        Self {
            genid,
            cfg,
            max_retries,
        }
    }
    pub(crate) fn blank() -> Self {
        FrrmiRequest::new(0, CLEAN_CONFIG.to_string(), 0)
    }
}

pub(crate) struct FrrmiResponse {
    genid: GenId, /* gen id the response corresponds to */
    data: String, /* frr-agent response is a string */
}
impl FrrmiResponse {
    fn get_response_data(&self) -> &String {
        &self.data
    }
    fn is_success(&self) -> bool {
        match self.data.as_str() {
            "Ok" => true,
            _ => false,
        }
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////
/// Methods to create the `Frrmi`, (dis)connect it and getters
///////////////////////////////////////////////////////////////////////////////////////////////////
impl Frrmi {
    const TIMEOUT: Duration = Duration::from_secs(5);

    #[must_use]
    pub(crate) fn new(remote: &str) -> Self {
        Self {
            remote: remote.to_owned(),
            ..Self::default()
        }
    }
    pub(crate) fn connect(&mut self) {
        self.sock = UnixStream::connect(&self.remote).ok();
        if self.sock.is_some() {
            self.stats.last_conn_time = Some(Local::now());
            info!("Successfully connected to frr-agent at {}", self.remote);
            revent!(RouterEvent::FrrmiConnectSucceeded);
        }
    }
    pub(crate) fn disconnect(&mut self) {
        if let Some(ref mut sock) = self.sock {
            let _ = sock.shutdown(std::net::Shutdown::Both);
        }
        self.sock.take();
        self.writeb.clear();
        self.readb.clear();
        self.timeout.take();
        if let Some(req) = self.inservice.take() {
            if self.requests.is_empty() {
                self.requests.push_front(req);
            }
        }
        debug!("Frrmi is now disconnected");
        self.stats.last_disconn_time = Some(Local::now());
        revent!(RouterEvent::FrrmiDisconnected);
    }
    pub(crate) fn timeout(&mut self) {
        if self.timeout.take_if(|t| *t < Instant::now()).is_some() {
            warn!("Request sent to frr-agent timed out! Will reconnect...");
            self.disconnect();
        }
    }
    #[must_use]
    pub(crate) fn get_sock_fd(&self) -> Option<i32> {
        self.sock.as_ref().map(|sock| sock.as_raw_fd())
    }
    #[must_use]
    pub(crate) fn has_sock(&self) -> bool {
        self.sock.is_some()
    }
    #[must_use]
    pub(crate) fn get_remote(&self) -> &String {
        &self.remote
    }
    #[must_use]
    pub(crate) fn get_stats(&self) -> &FrrmiStats {
        &self.stats
    }
    pub fn clear_applied_cfg(&mut self) {
        self.applied_cfg.take();
    }
    #[must_use]
    #[allow(unused)]
    pub fn get_applied_cfg(&self) -> &Option<FrrAppliedConfig> {
        &self.applied_cfg
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////
/// Methods to add requests
///////////////////////////////////////////////////////////////////////////////////////////////////
impl Frrmi {
    ///////////////////////////////////////////////////////////////////////////////////////////////////
    /// Queue a request (tail) to be serviced by the frr-agent
    ///////////////////////////////////////////////////////////////////////////////////////////////////
    pub(crate) fn queue_request(&mut self, req: FrrmiRequest) {
        debug!("Queued request to configure FRR (gen: {})", req.genid);
        self.requests.clear();
        self.requests.push_back(req);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////
    /// Issue a request to the frr-agent, provided that none is in service and there are requests to
    /// be sent. Note: an `Ok` result from this function does not necessarily mean that a message was
    /// sent at all. There may be no messages to send or, if there are, they might only be sent partially.
    ///////////////////////////////////////////////////////////////////////////////////////////////////
    pub(crate) fn service_request(&mut self) -> Result<(), FrrErr> {
        if self.inservice.is_some() {
            return Ok(());
        }
        self.sock.as_mut().ok_or_else(|| FrrErr::NotConnected)?;
        if let Some(req) = self.requests.pop_front() {
            debug!("Initiating new FRR reconfiguration (gen: {})", req.genid);
            let genid = req.genid;
            self.send_msg(req)?;
            revent!(RouterEvent::FrrConfigApplyRequested(genid));
        }
        Ok(())
    }
    ///////////////////////////////////////////////////////////////////////////////////////////////////
    /// Schedule a retry to attempt reconfiguring FRR again. This only makes sense if, prior to
    /// retrying a config, we clean-up the current config with a simpler one. For this reason,
    /// all requests are currently set with a max-retries of 0.
    ///////////////////////////////////////////////////////////////////////////////////////////////////
    pub(crate) fn config_retry(&mut self, mut request: FrrmiRequest) {
        let genid = request.genid;

        // give up after exhausting number of attempts
        if request.max_retries == 0 {
            warn!("Ran out of attempts to config FRR for gen {genid}");
            return;
        }
        // if new configs have arrived, don't try to reapply a config
        if !self.requests.is_empty() {
            warn!("Skipping config of FRR for gen {genid}: newer configs exist");
            return;
        }
        warn!("Will retry FRR config for gen {genid}...");
        request.max_retries -= 1;
        self.requests.push_front(request);

        // Attempt to clean-up the config before re-applying the actual config.
        // This is disabled as the blank config is unsuitable for us and providing a suitable
        //  one requires the ability to build frr configs, which we don't have here.
        if false {
            self.requests.push_front(FrrmiRequest::blank());
        }
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////
/// IO over the frrmi
///////////////////////////////////////////////////////////////////////////////////////////////////
impl Frrmi {
    ///////////////////////////////////////////////////////////////////////////////////////////////////
    /// Send a message over the `Frrmi`. This method takes ownership of the provided request, serializes
    /// it on the write buffer and tries to write the buffer on the socket. The buffer may be sent completely,
    /// partially (in which case pending data will be sent later on) or at all; e.g. if the agent is not
    /// reachable. If the request is sent, this method sets a timeout after which the config request is
    /// considered failed and should be re-attempted.
    ///////////////////////////////////////////////////////////////////////////////////////////////////
    pub(crate) fn send_msg(&mut self, req: FrrmiRequest) -> Result<(), FrrErr> {
        let genid = req.genid;
        let data = req.cfg.as_bytes();
        self.readb.clear();
        self.writeb.clear();
        self.writeb.serialize(genid, data);
        self.inservice = Some(req);

        // fixme
        let sock = self.sock.as_mut().ok_or_else(|| FrrErr::NotConnected)?;

        debug!("Sending config request to frr-agent for gen {genid}...");
        Self::send(sock, &mut self.writeb)?;
        debug!("FRR config request for gen {genid} successfully sent");
        self.timeout = Instant::now().checked_add(Self::TIMEOUT);
        Ok(())
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////
    /// Similar to `send_msg`, this method tries to send any pending data on the write buffer.
    ///////////////////////////////////////////////////////////////////////////////////////////////////
    pub(crate) fn send_msg_resume(&mut self) -> Result<(), FrrErr> {
        if self.inservice.is_none() || !self.has_sock() {
            return Ok(());
        }
        let sock = self.sock.as_mut().unwrap_or_else(|| unreachable!());
        Self::send(sock, &mut self.writeb)?;
        Ok(())
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////
    /// Send the contents of the frrmi write buffer. This request may fail completely (e.g. if frr-agent
    /// is down, or there is an issue with the socket), partially (e.g. some data could not be sent) or succeed.
    ///////////////////////////////////////////////////////////////////////////////////////////////////
    fn send(sock: &mut UnixStream, writeb: &mut IoBuffer) -> Result<(), FrrErr> {
        while writeb.used < writeb.len() {
            match sock.write(&writeb.buffer[writeb.used..]) {
                Ok(0) => return Err(FrrErr::IOFailure("Frr-agent might be down".to_string())),
                Ok(n) => writeb.used += n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Err(FrrErr::IOBusy),
                Err(e) => return Err(FrrErr::IOFailure(e.to_string())),
            }
        }
        writeb.clear();
        Ok(())
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////
    /// Attempt to receive len octets from the socket. On success, less than len octets may have
    /// been received, but anything received will be stored in the read buffer.
    ///////////////////////////////////////////////////////////////////////////////////////////////////
    fn recv(sock: &mut UnixStream, readb: &mut IoBuffer, len: usize) -> io::Result<usize> {
        readb.buffer.resize(readb.used + len, 0);
        let buf = &mut readb.buffer[readb.used..readb.used + len];
        let result = sock.read(buf);
        if let Ok(n) = result {
            readb.used += n;
        }
        result
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////
    /// Attempt to receive a full message
    ///////////////////////////////////////////////////////////////////////////////////////////////////
    pub(crate) fn recv_msg(&mut self) -> Result<Option<FrrmiResponse>, FrrErr> {
        let Some(sock) = self.sock.as_mut() else {
            return Err(FrrErr::NotConnected);
        };
        loop {
            let pending = self.readb.next_read_len();
            trace!("Recv data (read:{} pending:{pending})", self.readb.used);
            match Self::recv(sock, &mut self.readb, pending) {
                Ok(0) => {
                    revent!(RouterEvent::FrrmiPeerLeft);
                    return Err(FrrErr::PeerLeft);
                }
                Ok(_) => {
                    if self.readb.next_read_len() == 0 {
                        match self.readb.deserialize() {
                            Ok(response) => return Ok(Some(response)),
                            Err(e) => return Err(e),
                        }
                    } else {
                        // did not receive the complete message and need to read more
                    }
                }
                // we must wait. Can't provide a message yet
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => return Ok(None),
                // recv failed due to unrecoverable reason. Will restart
                Err(e) => return Err(FrrErr::IOFailure(e.to_string())),
            }
        }
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////
/// Handling of responses
///////////////////////////////////////////////////////////////////////////////////////////////////
impl Frrmi {
    pub fn process_response(&mut self, response: FrrmiResponse) {
        let Some(request) = self.inservice.take() else {
            error!("Got response over frrmi to unsolicited request!. Ignoring it...");
            self.timeout.take();
            return;
        };
        let reqgen = request.genid;
        let respgen = response.genid;
        if respgen != reqgen {
            warn!("Response genid {respgen} does not match the expected {reqgen}");
        }

        if response.is_success() {
            info!("Frr configuration successfully applied for gen {respgen}");
            self.stats.last_ok_time = Some(Local::now());
            self.stats.last_ok_genid = Some(response.genid);
            self.stats.apply_oks += 1;
            self.applied_cfg = Some(FrrAppliedConfig::new(request.genid, request.cfg));
            revent!(RouterEvent::FrrConfigApplySuccess(response.genid));
        } else {
            self.stats.last_fail_time = Some(Local::now());
            self.stats.last_fail_genid = Some(response.genid);
            self.stats.apply_failures += 1;
            let out = response.get_response_data();
            error!("Failed to apply FRR configuration for gen {respgen}: {out}");
            revent!(RouterEvent::FrrConfigApplyFailure(response.genid));
            self.config_retry(request);
        }
        // cancel timeout
        self.timeout.take();
    }
}

#[derive(Default)]
/// Buffer structure to deal with partial writes / reads on stream socket.
/// The same type is used for both write and read.
/// The used member indicates:
///    * in rx buffers: the amount of valid data that has been received. I.e. the octets in buffer that are valid,
///    * in tx buffers: the number of octets in the buffer that have been successfully sent.
struct IoBuffer {
    buffer: Vec<u8>,
    used: usize,
}
impl IoBuffer {
    #[must_use]
    #[allow(unused)]
    pub fn new() -> Self {
        Self::default()
    }
    fn extend(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }
    fn clear(&mut self) {
        self.buffer.clear();
        self.used = 0;
    }
    #[must_use]
    fn len(&self) -> usize {
        self.buffer.len()
    }

    /// serialize a msg to send over frrmi in this write buffer so we can handle partial writes
    fn serialize(&mut self, genid: i64, msg: &[u8]) {
        let length = msg.len() as u64;
        /* assemble wire message in write buffer as |length|genid|data| */
        self.extend(&length.to_ne_bytes());
        self.extend(&genid.to_ne_bytes());
        self.extend(msg);
    }

    /// Tell the length that a message (encoded as |length|genid|data|) must have.
    /// If less than 8 octets have been read it is not possible to know how big the message is yet.
    #[must_use]
    fn msg_len(&self) -> Option<usize> {
        if self.buffer.len() < 8 {
            return None;
        } else {
            let len_buf = &self.buffer[0..8]
                .try_into()
                .unwrap_or_else(|_| unreachable!());
            let msg_len = u64::from_ne_bytes(*len_buf) as usize;
            Some(msg_len)
        }
    }
    /// Tell the number of octets that should be read next according to the contents of the read buffer
    /// to get a message or be able to determine its length.
    /// If less than 16 octets have been received, this returns the number needed to have exactly 16.
    /// Else, we return the number of octets that are pending to have the complete message.
    #[must_use]
    fn next_read_len(&self) -> usize {
        if self.len() < 16 {
            16 - self.len()
        } else {
            let msg_len = self.msg_len().unwrap_or_else(|| unreachable!());
            if msg_len > (self.len() - 16) {
                msg_len - (self.len() - 16)
            } else {
                0
            }
        }
    }

    /// Tell if a recv buffer can be deserialized. I.e. if it contains all the data for a message.
    #[must_use]
    fn is_ready(&self) -> bool {
        match self.msg_len() {
            Some(m) => self.len() == m + 16,
            None => false,
        }
    }
    fn deserialize(&mut self) -> Result<FrrmiResponse, FrrErr> {
        debug!("Deserializing message from frr-agent...");
        debug_assert!(self.is_ready());
        // decode genid
        let genid_buff = &self.buffer[8..16]
            .try_into()
            .unwrap_or_else(|_| unreachable!());
        let genid = i64::from_ne_bytes(*genid_buff);

        // decode message as string
        let Ok(data) = from_utf8(&self.buffer[16..self.used]) else {
            self.clear();
            error!("Failed to decode response rx over frrmi!");
            return Err(FrrErr::DecodeFailure);
        };
        let data = data.to_string();
        self.clear();
        Ok(FrrmiResponse { genid, data })
    }
}

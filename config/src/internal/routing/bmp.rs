// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: BMP (BGP Monitoring Protocol)

#![allow(unused)]

use std::net::IpAddr;
use std::time::Duration;

use net::tcp::TcpPort;

#[must_use]
fn default_bmp_port() -> TcpPort {
    match TcpPort::new_checked(5000) {
        Ok(p) => p,
        #[allow(clippy::panic)]
        Err(e) => panic!("default BMP port must be valid: {e}"),
    }
}

#[derive(Clone, Debug)]
pub enum BmpSource {
    Address(IpAddr),
    Interface(String),
}

#[derive(Clone, Debug)]
pub struct BmpOptions {
    /// Name for `bmp targets <name>`
    pub target_name: String,
    /// Collector host/IP in `bmp connect`
    pub connect_host: String,
    /// Collector TCP port
    pub port: TcpPort,
    /// Optional local source (address or interface)
    pub source: Option<BmpSource>,
    /// Optional reconnect backoff
    pub min_retry: Option<Duration>,
    pub max_retry: Option<Duration>,
    /// `bmp stats interval`
    pub stats_interval: Duration,
    /// Monitoring toggles
    pub monitor_ipv4_pre: bool,
    pub monitor_ipv4_post: bool,
    pub monitor_ipv6_pre: bool,
    pub monitor_ipv6_post: bool,

    /// VRFs/views to import into the default BMP instance:
    /// renders as multiple `bmp import-vrf-view <vrf>`
    pub import_vrf_views: Vec<String>,
}

impl Default for BmpOptions {
    fn default() -> Self {
        Self {
            target_name: "bmp1".to_string(),
            connect_host: "127.0.0.1".to_string(),
            port: default_bmp_port(),
            source: None,
            min_retry: Some(Duration::from_millis(1_000)),
            max_retry: Some(Duration::from_millis(20_000)),
            stats_interval: Duration::from_millis(60_000),
            monitor_ipv4_pre: true,
            monitor_ipv4_post: true,
            monitor_ipv6_pre: false,
            monitor_ipv6_post: false,
            import_vrf_views: Vec::new(),
        }
    }
}

impl BmpOptions {
    #[must_use]
    pub fn new<T: Into<String>, H: Into<String>>(
        target_name: T,
        connect_host: H,
        port: TcpPort,
    ) -> Self {
        Self {
            target_name: target_name.into(),
            connect_host: connect_host.into(),
            port,
            ..Default::default()
        }
    }

    #[must_use]
    pub fn set_source_addr(mut self, ip: IpAddr) -> Self {
        self.source = Some(BmpSource::Address(ip));
        self
    }

    #[must_use]
    pub fn set_source_interface<S: Into<String>>(mut self, ifname: S) -> Self {
        self.source = Some(BmpSource::Interface(ifname.into()));
        self
    }

    #[must_use]
    pub fn set_retry(mut self, min: Duration, max: Duration) -> Self {
        self.min_retry = Some(min);
        self.max_retry = Some(max);
        self
    }

    #[must_use]
    pub fn set_stats_interval(mut self, interval: Duration) -> Self {
        self.stats_interval = interval;
        self
    }

    #[must_use]
    pub fn monitor_ipv4(mut self, pre: bool, post: bool) -> Self {
        self.monitor_ipv4_pre = pre;
        self.monitor_ipv4_post = post;
        self
    }

    #[must_use]
    pub fn monitor_ipv6(mut self, pre: bool, post: bool) -> Self {
        self.monitor_ipv6_pre = pre;
        self.monitor_ipv6_post = post;
        self
    }

    #[must_use]
    pub fn add_import_vrf_view<S: Into<String>>(mut self, vrf: S) -> Self {
        self.import_vrf_views.push(vrf.into());
        self
    }

    pub fn push_import_vrf_view<S: Into<String>>(&mut self, vrf: S) {
        self.import_vrf_views.push(vrf.into());
    }

    #[must_use]
    pub fn set_import_vrf_views<I, S>(mut self, vrfs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.import_vrf_views = vrfs.into_iter().map(Into::into).collect();
        self
    }
}

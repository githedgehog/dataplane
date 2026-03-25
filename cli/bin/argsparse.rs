// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Adds main parser for command arguments

use dataplane_cli::cliproto::{RequestArgs, RouteProtocol};
use log::Level;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;

/// Errors when parsing arguments
#[derive(Error, Debug)]
pub enum ArgsError {
    #[error("Parse failure: {0}")]
    ParseFailure(String),
    #[error("Bad address: {0}")]
    BadAddress(String),
    #[error("Bad prefix: {0}")]
    BadPrefix(String),
    #[error("Wrong prefix length {0}")]
    BadPrefixLength(u8),
    #[error("Bad prefix format: {0}")]
    BadPrefixFormat(String),
    #[error("Unrecognized arguments")]
    UnrecognizedArgs(HashMap<String, String>),
    #[error("Missing value for {0}")]
    MissingValue(&'static str),
    #[error("Unknown loglevel {0}")]
    UnknownLogLevel(String),
    #[error("Bad value {0}")]
    BadValue(String),
    #[error("Unknown protocol '{0}'")]
    UnknownProtocol(String),
}

/// Remove `key` from `map`, rejecting empty values.
///
/// Returns `Ok(None)` when the key is absent, `Err(MissingValue)` when the
/// key is present but its value is the empty string, and `Ok(Some(value))`
/// otherwise.  This standardises the remove-and-validate step that every
/// argument parser needs and prevents the class of bugs where an empty
/// value silently slips through to a downstream parser.
fn take_arg(
    map: &mut HashMap<String, String>,
    key: &'static str,
) -> Result<Option<String>, ArgsError> {
    match map.remove(key) {
        None => Ok(None),
        Some(v) if v.is_empty() => Err(ArgsError::MissingValue(key)),
        Some(v) => Ok(Some(v)),
    }
}

#[derive(Default, Debug)]
pub struct CliArgs {
    pub connpath: Option<String>,     /* connection path; this is local */
    pub bind_address: Option<String>, /* address to bind unix sock to */
    pub remote: RequestArgs,          /* args to send to remote */
}

impl CliArgs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_args_map(mut args_map: HashMap<String, String>) -> Result<CliArgs, ArgsError> {
        let mut args = CliArgs::new();

        if let Some(addr) = take_arg(&mut args_map, "address")? {
            args.remote.address = Some(
                IpAddr::from_str(&addr).map_err(|_| ArgsError::BadAddress(addr))?,
            );
        }

        if let Some(prefix) = take_arg(&mut args_map, "prefix")? {
            let (addr, len) = prefix
                .split_once('/')
                .ok_or_else(|| ArgsError::BadPrefixFormat(prefix.clone()))?;
            let pfx = IpAddr::from_str(addr).map_err(|_| ArgsError::BadPrefix(addr.to_owned()))?;
            let max_len: u8 = match pfx {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            let pfx_len: u8 = len
                .parse()
                .map_err(|_| ArgsError::ParseFailure(len.to_owned()))?;
            if pfx_len > max_len {
                return Err(ArgsError::BadPrefixLength(pfx_len));
            }
            args.remote.prefix = Some((pfx, pfx_len));
        }

        // `path`, `bind-address`, and `ifname` are plain strings —
        // `take_arg` already returns the right type.
        args.connpath = take_arg(&mut args_map, "path")?;
        args.bind_address = take_arg(&mut args_map, "bind-address")?;
        args.remote.ifname = take_arg(&mut args_map, "ifname")?;

        if let Some(vrfid) = take_arg(&mut args_map, "vrfid")? {
            args.remote.vrfid =
                Some(vrfid.parse().map_err(|_| ArgsError::BadValue(vrfid))?);
        }

        if let Some(vni) = take_arg(&mut args_map, "vni")? {
            args.remote.vni = Some(vni.parse().map_err(|_| ArgsError::BadValue(vni))?);
        }

        if let Some(level) = take_arg(&mut args_map, "level")? {
            let level = level.to_uppercase();
            args.remote.loglevel = Some(
                Level::from_str(&level)
                    .map_err(|_| ArgsError::UnknownLogLevel(level))?
                    .into(),
            );
        }

        if let Some(protocol) = take_arg(&mut args_map, "protocol")? {
            args.remote.protocol = Some(
                RouteProtocol::from_str(&protocol)
                    .map_err(|_| ArgsError::UnknownProtocol(protocol))?,
            );
        }

        if args_map.is_empty() {
            Ok(args)
        } else {
            Err(ArgsError::UnrecognizedArgs(args_map))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Build a `HashMap` from a slice of `(&str, &str)` pairs.
    fn map_from(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    // ── empty map ───────────────────────────────────────────────────

    #[test]
    fn empty_map_yields_defaults() {
        let args = CliArgs::from_args_map(HashMap::new()).unwrap();
        assert!(args.connpath.is_none());
        assert!(args.bind_address.is_none());
        assert!(args.remote.address.is_none());
        assert!(args.remote.prefix.is_none());
        assert!(args.remote.vrfid.is_none());
        assert!(args.remote.vni.is_none());
        assert!(args.remote.ifname.is_none());
        assert!(args.remote.loglevel.is_none());
        assert!(args.remote.protocol.is_none());
    }

    // ── valid values ────────────────────────────────────────────────

    #[test]
    fn valid_ipv4_address() {
        let args = CliArgs::from_args_map(map_from(&[("address", "10.0.0.1")])).unwrap();
        assert_eq!(args.remote.address, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn valid_ipv6_address() {
        let args = CliArgs::from_args_map(map_from(&[("address", "::1")])).unwrap();
        assert_eq!(args.remote.address, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn valid_ipv4_prefix() {
        let args = CliArgs::from_args_map(map_from(&[("prefix", "192.168.0.0/24")])).unwrap();
        let (addr, len) = args.remote.prefix.unwrap();
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)));
        assert_eq!(len, 24);
    }

    #[test]
    fn valid_ipv6_prefix() {
        let args = CliArgs::from_args_map(map_from(&[("prefix", "fd00::/64")])).unwrap();
        let (addr, len) = args.remote.prefix.unwrap();
        assert_eq!(addr, IpAddr::V6("fd00::".parse().unwrap()));
        assert_eq!(len, 64);
    }

    #[test]
    fn valid_path() {
        let args = CliArgs::from_args_map(map_from(&[("path", "/tmp/dp.sock")])).unwrap();
        assert_eq!(args.connpath.as_deref(), Some("/tmp/dp.sock"));
    }

    #[test]
    fn valid_bind_address() {
        let args =
            CliArgs::from_args_map(map_from(&[("bind-address", "/tmp/cli.sock")])).unwrap();
        assert_eq!(args.bind_address.as_deref(), Some("/tmp/cli.sock"));
    }

    #[test]
    fn valid_ifname() {
        let args = CliArgs::from_args_map(map_from(&[("ifname", "eth0")])).unwrap();
        assert_eq!(args.remote.ifname.as_deref(), Some("eth0"));
    }

    #[test]
    fn valid_vrfid() {
        let args = CliArgs::from_args_map(map_from(&[("vrfid", "42")])).unwrap();
        assert_eq!(args.remote.vrfid, Some(42));
    }

    #[test]
    fn valid_vni() {
        let args = CliArgs::from_args_map(map_from(&[("vni", "5000")])).unwrap();
        assert_eq!(args.remote.vni, Some(5000));
    }

    #[test]
    fn valid_loglevel_case_insensitive() {
        for (input, expected) in [("trace", Level::Trace), ("DEBUG", Level::Debug), ("Info", Level::Info)] {
            let args = CliArgs::from_args_map(map_from(&[("level", input)])).unwrap();
            let got: Level = args.remote.loglevel.unwrap().into();
            assert_eq!(got, expected, "input was {input:?}");
        }
    }

    #[test]
    fn valid_protocol() {
        let args = CliArgs::from_args_map(map_from(&[("protocol", "bgp")])).unwrap();
        assert!(args.remote.protocol.is_some());
    }

    #[test]
    fn multiple_args_at_once() {
        let args = CliArgs::from_args_map(map_from(&[
            ("address", "10.0.0.1"),
            ("vrfid", "7"),
            ("ifname", "swp1"),
        ]))
        .unwrap();
        assert_eq!(args.remote.address, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(args.remote.vrfid, Some(7));
        assert_eq!(args.remote.ifname.as_deref(), Some("swp1"));
    }

    // ── empty values (all must return MissingValue) ─────────────────

    #[test]
    fn empty_address_is_missing_value() {
        let err = CliArgs::from_args_map(map_from(&[("address", "")])).unwrap_err();
        assert!(matches!(err, ArgsError::MissingValue("address")), "got: {err}");
    }

    #[test]
    fn empty_prefix_is_missing_value() {
        let err = CliArgs::from_args_map(map_from(&[("prefix", "")])).unwrap_err();
        assert!(matches!(err, ArgsError::MissingValue("prefix")), "got: {err}");
    }

    #[test]
    fn empty_path_is_missing_value() {
        let err = CliArgs::from_args_map(map_from(&[("path", "")])).unwrap_err();
        assert!(matches!(err, ArgsError::MissingValue("path")), "got: {err}");
    }

    #[test]
    fn empty_bind_address_is_missing_value() {
        let err = CliArgs::from_args_map(map_from(&[("bind-address", "")])).unwrap_err();
        assert!(matches!(err, ArgsError::MissingValue("bind-address")), "got: {err}");
    }

    #[test]
    fn empty_vrfid_is_missing_value() {
        let err = CliArgs::from_args_map(map_from(&[("vrfid", "")])).unwrap_err();
        assert!(matches!(err, ArgsError::MissingValue("vrfid")), "got: {err}");
    }

    #[test]
    fn empty_vni_is_missing_value() {
        let err = CliArgs::from_args_map(map_from(&[("vni", "")])).unwrap_err();
        assert!(matches!(err, ArgsError::MissingValue("vni")), "got: {err}");
    }

    #[test]
    fn empty_ifname_is_missing_value() {
        let err = CliArgs::from_args_map(map_from(&[("ifname", "")])).unwrap_err();
        assert!(matches!(err, ArgsError::MissingValue("ifname")), "got: {err}");
    }

    #[test]
    fn empty_level_is_missing_value() {
        let err = CliArgs::from_args_map(map_from(&[("level", "")])).unwrap_err();
        assert!(matches!(err, ArgsError::MissingValue("level")), "got: {err}");
    }

    #[test]
    fn empty_protocol_is_missing_value() {
        let err = CliArgs::from_args_map(map_from(&[("protocol", "")])).unwrap_err();
        assert!(matches!(err, ArgsError::MissingValue("protocol")), "got: {err}");
    }

    // ── bad values ──────────────────────────────────────────────────

    #[test]
    fn bad_address_returns_bad_address() {
        let err = CliArgs::from_args_map(map_from(&[("address", "not-an-ip")])).unwrap_err();
        assert!(matches!(err, ArgsError::BadAddress(_)), "got: {err}");
    }

    #[test]
    fn prefix_missing_slash_returns_bad_format() {
        let err = CliArgs::from_args_map(map_from(&[("prefix", "10.0.0.0")])).unwrap_err();
        assert!(matches!(err, ArgsError::BadPrefixFormat(_)), "got: {err}");
    }

    #[test]
    fn prefix_bad_address_returns_bad_prefix() {
        let err = CliArgs::from_args_map(map_from(&[("prefix", "nope/24")])).unwrap_err();
        assert!(matches!(err, ArgsError::BadPrefix(_)), "got: {err}");
    }

    #[test]
    fn prefix_bad_length_returns_parse_failure() {
        let err = CliArgs::from_args_map(map_from(&[("prefix", "10.0.0.0/abc")])).unwrap_err();
        assert!(matches!(err, ArgsError::ParseFailure(_)), "got: {err}");
    }

    #[test]
    fn ipv4_prefix_length_too_large() {
        let err = CliArgs::from_args_map(map_from(&[("prefix", "10.0.0.0/33")])).unwrap_err();
        assert!(matches!(err, ArgsError::BadPrefixLength(33)), "got: {err}");
    }

    #[test]
    fn ipv6_prefix_length_too_large() {
        let err = CliArgs::from_args_map(map_from(&[("prefix", "fd00::/129")])).unwrap_err();
        assert!(matches!(err, ArgsError::BadPrefixLength(129)), "got: {err}");
    }

    #[test]
    fn bad_vrfid_returns_bad_value() {
        let err = CliArgs::from_args_map(map_from(&[("vrfid", "xyz")])).unwrap_err();
        assert!(matches!(err, ArgsError::BadValue(_)), "got: {err}");
    }

    #[test]
    fn bad_vni_returns_bad_value() {
        let err = CliArgs::from_args_map(map_from(&[("vni", "-1")])).unwrap_err();
        assert!(matches!(err, ArgsError::BadValue(_)), "got: {err}");
    }

    #[test]
    fn bad_loglevel_returns_unknown() {
        let err = CliArgs::from_args_map(map_from(&[("level", "verbose")])).unwrap_err();
        assert!(matches!(err, ArgsError::UnknownLogLevel(_)), "got: {err}");
    }

    #[test]
    fn bad_protocol_returns_unknown() {
        let err = CliArgs::from_args_map(map_from(&[("protocol", "rip")])).unwrap_err();
        assert!(matches!(err, ArgsError::UnknownProtocol(_)), "got: {err}");
    }

    // ── unrecognized arguments ──────────────────────────────────────

    #[test]
    fn unrecognized_arg_is_rejected() {
        let err = CliArgs::from_args_map(map_from(&[("bogus", "value")])).unwrap_err();
        assert!(matches!(err, ArgsError::UnrecognizedArgs(_)), "got: {err}");
    }

    #[test]
    fn mix_of_valid_and_unrecognized_is_rejected() {
        let err = CliArgs::from_args_map(map_from(&[
            ("address", "10.0.0.1"),
            ("bogus", "value"),
        ]))
        .unwrap_err();
        assert!(matches!(err, ArgsError::UnrecognizedArgs(ref m) if m.contains_key("bogus")),
            "got: {err}");
    }

    // ── edge cases ──────────────────────────────────────────────────

    #[test]
    fn ipv4_prefix_length_zero_is_valid() {
        let args = CliArgs::from_args_map(map_from(&[("prefix", "0.0.0.0/0")])).unwrap();
        let (_, len) = args.remote.prefix.unwrap();
        assert_eq!(len, 0);
    }

    #[test]
    fn ipv4_prefix_length_32_is_valid() {
        let args = CliArgs::from_args_map(map_from(&[("prefix", "10.0.0.1/32")])).unwrap();
        let (_, len) = args.remote.prefix.unwrap();
        assert_eq!(len, 32);
    }

    #[test]
    fn ipv6_prefix_length_128_is_valid() {
        let args = CliArgs::from_args_map(map_from(&[("prefix", "::1/128")])).unwrap();
        let (_, len) = args.remote.prefix.unwrap();
        assert_eq!(len, 128);
    }
}

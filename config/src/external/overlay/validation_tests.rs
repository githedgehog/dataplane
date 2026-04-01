// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Validation tests for `VpcExpose` / `VpcPeering` / Overlay
//!
//! These tests cover the expected semantics and restrictions for Expose objects in VPC peerings.
//!
//! Reference: <https://github.com/githedgehog/dataplane/issues/1150>

#[cfg(test)]
mod test {
    use crate::ConfigError;
    use crate::external::overlay::Overlay;
    use crate::external::overlay::vpc::{Vpc, VpcTable};
    use crate::external::overlay::vpcpeering::{
        VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable,
    };

    use lpm::prefix::{PortRange, Prefix, PrefixWithOptionalPorts, ppsize_from};

    // Helper: create a PrefixWithOptionalPorts with a port range
    fn prefix_with_ports(prefix_str: &str, start: u16, end: u16) -> PrefixWithOptionalPorts {
        PrefixWithOptionalPorts::new(
            Prefix::from(prefix_str),
            Some(PortRange::new(start, end).unwrap()),
        )
    }

    // Helper: build an Overlay from two VPCs and a single peering, then validate it
    fn validate_overlay_with_peering(peering: VpcPeering) -> Result<(), ConfigError> {
        let vpc1 = Vpc::new("VPC-1", "VPC01", 1).unwrap();
        let vpc2 = Vpc::new("VPC-2", "VPC02", 2).unwrap();
        let mut vpc_table = VpcTable::new();
        vpc_table.add(vpc1).unwrap();
        vpc_table.add(vpc2).unwrap();

        let mut peering_table = VpcPeeringTable::new();
        peering_table.add(peering).unwrap();

        let mut overlay = Overlay::new(vpc_table, peering_table);
        overlay.validate()
    }

    // Helper: build an Overlay from three VPCs and two peerings, then validate it
    fn validate_overlay_3vpc(
        peering1: VpcPeering,
        peering2: VpcPeering,
    ) -> Result<(), ConfigError> {
        let vpc1 = Vpc::new("VPC-1", "VPC01", 1).unwrap();
        let vpc2 = Vpc::new("VPC-2", "VPC02", 2).unwrap();
        let vpc3 = Vpc::new("VPC-3", "VPC03", 3).unwrap();
        let mut vpc_table = VpcTable::new();
        vpc_table.add(vpc1).unwrap();
        vpc_table.add(vpc2).unwrap();
        vpc_table.add(vpc3).unwrap();

        let mut peering_table = VpcPeeringTable::new();
        peering_table.add(peering1).unwrap();
        peering_table.add(peering2).unwrap();

        let mut overlay: Overlay = Overlay::new(vpc_table, peering_table);
        overlay.validate()
    }

    // ==================================================================================
    // VpcExpose validation
    // ==================================================================================

    // --- Lists validation ---

    // Empty expose: no lists is illegal
    #[test]
    fn test_empty_expose_rejected() {
        let expose = VpcExpose::empty();
        let result = expose.validate();
        assert!(
            matches!(result, Err(ConfigError::Forbidden(_))),
            "{result:?}"
        );
    }

    // Empty ips with non-empty nots is illegal
    #[test]
    fn test_empty_ips_with_nonempty_nots_rejected() {
        let expose = VpcExpose::empty().not("10.0.1.0/24".into());
        let result = expose.validate();
        assert!(
            matches!(result, Err(ConfigError::Forbidden(_))),
            "{result:?}"
        );
    }

    // Empty as_range with non-empty not_as is illegal
    #[test]
    fn test_empty_as_range_with_nonempty_not_as_rejected() {
        let expose = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("10.0.0.0/16".into())
            .not_as("2.0.1.0/24".into())
            .unwrap();
        let result = expose.validate();
        assert!(
            matches!(result, Err(ConfigError::Forbidden(_))),
            "{result:?}"
        );
    }

    // NAT requires non-empty as_range
    #[test]
    fn test_nat_without_as_range_rejected() {
        let expose = VpcExpose::empty()
            .make_stateless_nat()
            .unwrap()
            .ip("10.0.0.0/24".into());
        let result = expose.validate();
        assert!(
            matches!(result, Err(ConfigError::Forbidden(_))),
            "{result:?}"
        );
    }

    // --- Special prefixes and port ranges ---

    // Reserved IP 0.0.0.0/32 in ips should be rejected
    #[test]
    #[ignore = "TODO: validation for reserved IPs not yet implemented"]
    fn test_reserved_ipv4_zero_rejected() {
        let expose = VpcExpose::empty().ip("0.0.0.0/32".into());
        assert!(expose.validate().is_err());
    }

    // Reserved IP ::/128 in ips should be rejected
    #[test]
    #[ignore = "TODO: validation for reserved IPs not yet implemented"]
    fn test_reserved_ipv6_zero_rejected() {
        let expose = VpcExpose::empty().ip("::/128".into());
        assert!(expose.validate().is_err());
    }

    // Reserved IP 255.255.255.255/32 in as_range should be rejected
    #[test]
    #[ignore = "TODO: validation for reserved IPs not yet implemented"]
    fn test_reserved_ipv4_broadcast_rejected() {
        let expose = VpcExpose::empty()
            .ip("10.0.0.1/32".into())
            .as_range("255.255.255.255/32".into())
            .unwrap();
        assert!(expose.validate().is_err());
    }

    // Multicast prefix 224.0.0.0/4 in ips should be rejected
    #[test]
    #[ignore = "TODO: validation for multicast prefixes not yet implemented"]
    fn test_multicast_prefix_rejected() {
        let expose = VpcExpose::empty().ip("224.0.0.0/4".into());
        assert!(expose.validate().is_err());
    }

    // Loopback prefix 127.0.0.0/8 in ips should be rejected
    #[test]
    #[ignore = "TODO: validation for loopback prefixes not yet implemented"]
    fn test_loopback_prefix_rejected() {
        let expose = VpcExpose::empty().ip("127.0.0.0/8".into());
        assert!(expose.validate().is_err());
    }

    // Port 0 in port range should be rejected
    #[test]
    #[ignore = "TODO: validation for port 0 not yet implemented"]
    fn test_port_zero_rejected() {
        let expose = VpcExpose::empty().ip(prefix_with_ports("10.0.0.0/24", 0, 80));
        assert!(expose.validate().is_err());
    }

    // --- 0.0.0.0/0 and ::/0 prefixes ---

    // Note that it's not clear yet whether these prefixes should be allowed once we reject 0.0.0.0
    // (and possibly prefixes containing it).

    // Root prefix 0.0.0.0/0 in ips is legal (but semantically different from a "default" expose)
    #[test]
    fn test_root_v4_in_ips_passes() {
        let expose = VpcExpose::empty().ip("0.0.0.0/0".into());
        assert_eq!(expose.validate(), Ok(()));
    }

    // Root prefix ::/0 in ips is legal (IPv6 variant)
    #[test]
    fn test_root_v6_in_ips_passes() {
        let expose = VpcExpose::empty().ip("::/0".into());
        assert_eq!(expose.validate(), Ok(()));
    }

    // Root prefix 0.0.0.0/0 in as_range is legal
    #[test]
    fn test_root_v4_in_as_range_passes() {
        let expose = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("10.0.0.0/8".into())
            .as_range("0.0.0.0/0".into())
            .unwrap();
        assert_eq!(expose.validate(), Ok(()));
    }

    // Root prefix 0.0.0.0/0 in nots is rejected - not illegal per-se, but excludes all available
    // prefixes
    #[test]
    fn test_root_v4_in_nots_rejected() {
        let expose = VpcExpose::empty()
            .ip("10.0.0.0/8".into())
            .not("0.0.0.0/0".into());
        let result = expose.validate();
        assert!(
            matches!(result, Err(ConfigError::ExcludedAllPrefixes(_))),
            "{result:?}"
        );
    }

    // Root prefix 0.0.0.0/0 in not_as is rejected
    #[test]
    fn test_root_v4_in_not_as_rejected() {
        let expose = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("10.0.0.0/8".into())
            .as_range("2.0.0.0/8".into())
            .unwrap()
            .not_as("0.0.0.0/0".into())
            .unwrap();
        let result = expose.validate();
        assert!(
            matches!(result, Err(ConfigError::ExcludedAllPrefixes(_))),
            "{result:?}"
        );
    }

    // --- IP version consistency ---

    // Mixed IPv4/IPv6 within ips is rejected
    #[test]
    fn test_mixed_ip_versions_within_ips_rejected() {
        let expose = VpcExpose::empty()
            .ip("10.0.0.0/16".into())
            .ip("1::/64".into());
        let result = expose.validate();
        assert!(
            matches!(result, Err(ConfigError::InconsistentIpVersion(_))),
            "{result:?}"
        );
    }

    // Mixed IPv4/IPv6 across ips and as_range is rejected
    // This may change in the future for NAT46 or NAT64
    #[test]
    fn test_mixed_ip_versions_across_ips_and_as_range_rejected() {
        let expose = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("10.0.0.0/16".into())
            .as_range("1::/112".into())
            .unwrap();
        let result = expose.validate();
        assert!(
            matches!(result, Err(ConfigError::InconsistentIpVersion(_))),
            "{result:?}"
        );
    }

    // --- Overlapping prefixes within VpcExpose ---

    // Overlapping prefixes within ips are allowed, should be merged internally
    #[test]
    #[ignore = "TODO: Currently not allowed"]
    fn test_overlapping_prefixes_within_ips_passes() {
        let expose = VpcExpose::empty()
            .ip("10.0.0.0/16".into())
            .ip("10.0.0.0/17".into());
        assert_eq!(expose.validate(), Ok(()));
    }

    // Overlapping prefixes within as_range are allowed, should be merged internally
    #[test]
    #[ignore = "TODO: Currently not allowed"]
    fn test_overlapping_prefixes_within_as_range_passes() {
        let expose = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("1.0.0.0/16".into())
            .as_range("10.0.0.0/16".into())
            .unwrap()
            .as_range("10.0.0.0/17".into())
            .unwrap();
        assert_eq!(expose.validate(), Ok(()));
        // TODO: Can we merge the two overlapping prefixes?
    }

    // Overlapping prefixes within nots are allowed, should be merged internally
    #[test]
    #[ignore = "TODO: Currently not allowed"]
    fn test_overlapping_prefixes_within_nots_passes() {
        let expose = VpcExpose::empty()
            .ip("10.0.0.0/8".into())
            .not("10.0.0.0/16".into())
            .not("10.0.0.0/17".into());
        assert_eq!(expose.validate(), Ok(()));
    }

    // Overlapping prefixes within not_as are allowed, should be merged internally
    #[test]
    #[ignore = "TODO: Currently not allowed"]
    fn test_overlapping_prefixes_within_not_as_passes() {
        let expose = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("1.0.0.0/8".into())
            .as_range("10.0.0.0/8".into())
            .unwrap()
            .not_as("10.0.0.0/16".into())
            .unwrap()
            .not_as("10.0.0.0/17".into())
            .unwrap();
        assert_eq!(expose.validate(), Ok(()));
    }

    // Overlapping prefixes in ips with distinct port ranges passes
    #[test]
    fn test_overlapping_prefixes_distinct_port_ranges_passes() {
        let expose = VpcExpose::empty()
            .ip(prefix_with_ports("10.0.0.0/24", 80, 80))
            .ip(prefix_with_ports("10.0.0.0/24", 443, 443));
        assert_eq!(expose.validate(), Ok(()));
    }

    // Overlapping prefixes in ips with overlapping port ranges passes
    #[test]
    fn test_overlapping_prefixes_overlapping_port_ranges_passes() {
        let expose = VpcExpose::empty()
            .ip(prefix_with_ports("10.0.0.0/24", 80, 80))
            .ip(prefix_with_ports("10.0.0.0/24", 80, 80));
        assert_eq!(expose.validate(), Ok(()));
    }

    // --- Exclusion prefixes ---

    // Out-of-range exclusion prefix for ips is legal (but we should warn about it)
    #[test]
    fn test_out_of_range_exclusion_prefix_within_ips_passes() {
        let expose = VpcExpose::empty()
            .ip("10.0.0.0/16".into())
            .not("8.0.0.0/24".into());
        assert_eq!(expose.validate(), Ok(()));
    }

    // Out-of-range exclusion prefix for as_range is legal (but we should warn about it)
    #[test]
    fn test_out_of_range_exclusion_prefix_within_as_range_passes() {
        let expose = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("1.0.0.0/16".into())
            .as_range("10.0.0.0/16".into())
            .unwrap()
            .not_as("8.0.0.0/24".into())
            .unwrap();
        assert_eq!(expose.validate(), Ok(()));
    }

    // Exclusion prefix for ips with partial overlap (not fully contained) is valid (but we should
    // warn about it)
    #[test]
    // Currently, we reject the configuration if at least one allowed prefix is fully covered by at
    // least one exclusion prefix. This means we cannot have partial overlap when not using port
    // ranges (CIDR prefixes do not partially overlap, they are always disjoint or one contains the
    // other). We need to enable this test once we check each exclusion prefix against the whole set
    // of allowed prefixes; this will probably require splitting prefixes, which we do not do at the
    // moment at the validation stage.
    #[ignore = "TODO: Not applicable at the moment"]
    fn test_exclusion_prefix_partial_overlap_within_ips_passes() {
        // 10.0.0.0/8 is larger than 10.0.0.0/16 and thus not contained within it
        let expose = VpcExpose::empty()
            .ip("20.0.0.0/16".into())
            .ip("10.0.0.0/16".into())
            .not("10.0.0.0/8".into());
        assert_eq!(expose.validate(), Ok(()));
    }

    // Exclusion prefix for ips with partial overlap (not fully contained), when using port ranges,
    // is valid (but we should warn about it)
    #[test]
    #[ignore = "TODO: Currently not allowed"]
    fn test_exclusion_prefix_with_port_ranges_partial_overlap_within_ips_passes() {
        let expose = VpcExpose::empty()
            .ip(PrefixWithOptionalPorts::new(
                "10.0.0.0/16".into(),
                Some(PortRange::new(1000, 2000).unwrap()),
            ))
            .not(PrefixWithOptionalPorts::new(
                "10.0.0.0/16".into(),
                Some(PortRange::new(1500, 2500).unwrap()),
            ));
        assert_eq!(expose.validate(), Ok(()));
    }

    // Exclusion prefix for as_range with partial overlap (not fully contained) is valid (but we
    // should warn about it)
    #[test]
    // Currently, we reject the configuration if at least one allowed prefix is fully covered by at
    // least one exclusion prefix. This means we cannot have partial overlap when not using port
    // ranges (CIDR prefixes do not partially overlap, they are always disjoint or one contains the
    // other). We need to enable this test once we check each exclusion prefix against the whole set
    // of allowed prefixes; this will probably require splitting prefixes, which we do not do at the
    // moment at the validation stage.
    #[ignore = "TODO: Not applicable at the moment"]
    fn test_exclusion_prefix_partial_overlap_within_as_range_passes() {
        // 10.0.0.0/8 is larger than 10.0.0.0/16 and thus not contained within it
        let expose = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("1.0.0.0/16".into())
            .as_range("20.0.0.0/16".into())
            .unwrap()
            .as_range("10.0.0.0/16".into())
            .unwrap()
            .not_as("10.0.0.0/8".into())
            .unwrap();
        assert_eq!(expose.validate(), Ok(()));
    }

    // Exclusion prefix for as_range with partial overlap (not fully contained) is valid (but we
    // should warn about it)
    #[test]
    #[ignore = "TODO: Currently not allowed"]
    fn test_exclusion_prefix_with_port_ranges_partial_overlap_within_as_range_passes() {
        let expose = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("1.0.0.0/16".into())
            .as_range(PrefixWithOptionalPorts::new(
                "10.0.0.0/16".into(),
                Some(PortRange::new(1000, 2000).unwrap()),
            ))
            .unwrap()
            .not_as(PrefixWithOptionalPorts::new(
                "10.0.0.0/16".into(),
                Some(PortRange::new(1500, 2500).unwrap()),
            ))
            .unwrap();
        assert_eq!(expose.validate(), Ok(()));
    }

    // Excluding all prefixes in ips is rejected
    #[test]
    fn test_excluding_all_prefixes_in_ips_rejected() {
        let expose = VpcExpose::empty()
            .ip("10.0.0.0/16".into())
            .not("10.0.0.0/17".into())
            .not("10.0.128.0/17".into());
        let result = expose.validate();
        assert_eq!(
            result,
            Err(ConfigError::ExcludedAllPrefixes(Box::new(expose.clone()))),
            "{result:?}",
        );
    }

    // Excluding all prefixes in as_range is rejected
    #[test]
    fn test_excluding_all_prefixes_in_as_range_rejected() {
        let expose = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("1.0.0.0/16".into())
            .as_range("10.0.0.0/16".into())
            .unwrap()
            .not_as("10.0.0.0/17".into())
            .unwrap()
            .not_as("10.0.128.0/17".into())
            .unwrap();
        let result = expose.validate();
        assert_eq!(
            result,
            Err(ConfigError::ExcludedAllPrefixes(Box::new(expose.clone()))),
            "{result:?}",
        );
    }

    // --- NAT-specific constraints ---

    // Stateless NAT: mismatched sizes rejected
    #[test]
    fn test_stateless_nat_mismatched_sizes_rejected() {
        let expose = VpcExpose::empty()
            .make_stateless_nat()
            .unwrap()
            .ip("10.0.0.0/16".into())
            .not("10.0.1.0/24".into())
            .as_range("2.0.0.0/24".into())
            .unwrap();
        let result = expose.validate();
        assert_eq!(
            result,
            Err(ConfigError::MismatchedPrefixSizes(
                ppsize_from((65536 - 256u32) * (u32::from(u16::MAX) + 1)),
                ppsize_from(256u32 * (u32::from(u16::MAX) + 1)),
            )),
            "{result:?}",
        );
    }

    // Port forwarding: single prefix per side required
    #[test]
    fn test_port_forwarding_single_prefix_required() {
        // Two prefixes on ips side
        let expose = VpcExpose::empty()
            .make_port_forwarding(None, None)
            .unwrap()
            .ip(prefix_with_ports("10.0.0.1/32", 80, 80))
            .ip(prefix_with_ports("10.0.0.2/32", 80, 80))
            .as_range(prefix_with_ports("2.0.0.1/32", 8080, 8080))
            .unwrap();
        let result = expose.validate();
        assert!(
            matches!(result, Err(ConfigError::Forbidden(_))),
            "{result:?}"
        );
    }

    // Port forwarding: no exclusion prefixes allowed
    #[test]
    fn test_port_forwarding_no_exclusion_prefixes() {
        let expose = VpcExpose::empty()
            .make_port_forwarding(None, None)
            .unwrap()
            .ip(prefix_with_ports("10.0.0.0/31", 80, 80))
            .not(prefix_with_ports("10.0.0.1/32", 80, 80))
            .as_range(prefix_with_ports("2.0.0.0/31", 8080, 8080))
            .unwrap();
        let result = expose.validate();
        assert!(
            matches!(result, Err(ConfigError::Forbidden(_))),
            "{result:?}",
        );
    }

    // Port forwarding: mismatched sizes rejected
    #[test]
    fn test_port_forwarding_mismatched_sizes_rejected() {
        let expose = VpcExpose::empty()
            .make_port_forwarding(None, None)
            .unwrap()
            .ip(prefix_with_ports("10.0.0.0/24", 80, 80))
            .as_range(prefix_with_ports("2.0.0.0/25", 8080, 8080))
            .unwrap();
        let result = expose.validate();
        assert!(
            matches!(result, Err(ConfigError::MismatchedPrefixSizes(_, _))),
            "{result:?}",
        );
    }

    // Stateful NAT: port ranges rejected
    #[test]
    fn test_stateful_nat_port_ranges_rejected() {
        let expose = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip(prefix_with_ports("10.0.0.0/24", 80, 80))
            .as_range("2.0.0.0/24".into())
            .unwrap();
        let result = expose.validate();
        assert!(
            matches!(result, Err(ConfigError::Forbidden(_))),
            "{result:?}"
        );
    }

    // Default expose rules: default expose with ips/nots/nat is rejected
    #[test]
    fn test_default_expose_with_ips_rejected() {
        let expose = VpcExpose::empty().set_default().ip("10.0.0.0/16".into());
        let result = expose.validate();
        assert!(matches!(result, Err(ConfigError::Invalid(_))), "{result:?}",);

        let expose = VpcExpose::empty()
            .set_default()
            .make_stateful_nat(None)
            .unwrap()
            .as_range("10.0.0.0/16".into())
            .unwrap();
        let result = expose.validate();
        assert!(matches!(result, Err(ConfigError::Invalid(_))), "{result:?}");

        let expose = VpcExpose::empty().set_default().not("10.0.0.0/16".into());
        let result = expose.validate();
        assert!(matches!(result, Err(ConfigError::Invalid(_))), "{result:?}");

        let expose = VpcExpose::empty()
            .set_default()
            .make_stateful_nat(None)
            .unwrap()
            .not_as("10.0.0.0/16".into())
            .unwrap();
        let result = expose.validate();
        assert!(matches!(result, Err(ConfigError::Invalid(_))), "{result:?}");
    }

    // Valid expose with ips only (no NAT) passes
    #[test]
    fn test_valid_expose_ips_only_passes() {
        let expose = VpcExpose::empty()
            .ip("10.0.0.0/16".into())
            .ip("10.1.0.0/16".into());
        assert_eq!(expose.validate(), Ok(()));
    }

    // Valid expose with ips + as_range + nots + not_as passes
    #[test]
    fn test_valid_expose_all_lists_passes() {
        let expose = VpcExpose::empty()
            .make_stateless_nat()
            .unwrap()
            .ip("10.0.0.0/16".into())
            .not("10.0.1.0/24".into())
            .as_range("2.0.0.0/16".into())
            .unwrap()
            .not_as("2.0.1.0/24".into())
            .unwrap();
        assert_eq!(expose.validate(), Ok(()));
    }

    // ==================================================================================
    // VpcManifest validation, overlap and NAT checks
    // ==================================================================================

    // Two no-NAT exposes with disjoint ips passes
    #[test]
    fn test_no_nat_disjoint_ips_passes() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(VpcExpose::empty().ip("10.0.0.0/16".into()));
        manifest.add_expose(VpcExpose::empty().ip("10.1.0.0/16".into()));
        assert_eq!(manifest.validate(), Ok(()));
    }

    // Two no-NAT exposes with overlapping ips rejected
    #[test]
    fn test_no_nat_overlapping_ips_rejected() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(VpcExpose::empty().ip("10.0.0.0/16".into()));
        manifest.add_expose(VpcExpose::empty().ip("10.0.1.0/24".into()));
        let result = manifest.validate();
        assert!(
            matches!(result, Err(ConfigError::OverlappingPrefixes(_, _))),
            "{result:?}",
        );
    }

    // Stateless + no-NAT private prefixes overlap rejected
    #[test]
    fn test_stateless_plus_no_nat_private_prefixes_overlap_rejected() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(VpcExpose::empty().ip("10.0.0.0/16".into()));
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateless_nat()
                .unwrap()
                .ip("10.0.0.0/16".into())
                .as_range("2.0.0.0/16".into())
                .unwrap(),
        );
        let result = manifest.validate();
        assert!(
            matches!(result, Err(ConfigError::OverlappingPrefixes(_, _))),
            "{result:?}",
        );
    }

    // Stateless + no-NAT public prefixes overlap rejected
    #[test]
    fn test_stateless_plus_no_nat_public_prefixes_overlap_rejected() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(VpcExpose::empty().ip("2.0.0.0/16".into()));
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateless_nat()
                .unwrap()
                .ip("10.0.0.0/16".into())
                .as_range("2.0.0.0/16".into())
                .unwrap(),
        );
        let result = manifest.validate();
        assert!(
            matches!(result, Err(ConfigError::OverlappingPrefixes(_, _))),
            "{result:?}",
        );
    }

    // Stateful + no-NAT private prefixes overlap rejected
    #[test]
    fn test_stateful_plus_no_nat_private_prefixes_overlap_rejected() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(VpcExpose::empty().ip("10.0.0.0/16".into()));
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateful_nat(None)
                .unwrap()
                .ip("10.0.0.0/16".into())
                .as_range("2.0.0.0/16".into())
                .unwrap(),
        );
        let result = manifest.validate();
        assert!(
            matches!(result, Err(ConfigError::OverlappingPrefixes(_, _))),
            "{result:?}",
        );
    }

    // Stateful + no-NAT public prefixes overlap rejected
    #[test]
    fn test_stateful_plus_no_nat_public_prefixes_overlap_rejected() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(VpcExpose::empty().ip("2.0.0.0/16".into()));
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateful_nat(None)
                .unwrap()
                .ip("10.0.0.0/16".into())
                .as_range("2.0.0.0/16".into())
                .unwrap(),
        );
        let result = manifest.validate();
        assert!(
            matches!(result, Err(ConfigError::OverlappingPrefixes(_, _))),
            "{result:?}",
        );
    }

    // Port forwarding + no-NAT private prefixes overlap rejected
    #[test]
    fn test_port_forwarding_plus_no_nat_private_prefixes_overlap_rejected() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(VpcExpose::empty().ip("10.0.0.0/16".into()));
        manifest.add_expose(
            VpcExpose::empty()
                .make_port_forwarding(None, None)
                .unwrap()
                .ip(prefix_with_ports("10.0.0.1/32", 80, 80))
                .as_range(prefix_with_ports("2.0.0.1/32", 8080, 8080))
                .unwrap(),
        );
        let result = manifest.validate();
        assert!(
            matches!(result, Err(ConfigError::OverlappingPrefixes(_, _))),
            "{result:?}",
        );
    }

    // Port forwarding + no-NAT public prefixes overlap rejected
    #[test]
    fn test_port_forwarding_plus_no_nat_public_prefixes_overlap_rejected() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(VpcExpose::empty().ip("2.0.0.0/16".into()));
        manifest.add_expose(
            VpcExpose::empty()
                .make_port_forwarding(None, None)
                .unwrap()
                .ip(prefix_with_ports("10.0.0.1/32", 80, 80))
                .as_range(prefix_with_ports("2.0.0.1/32", 8080, 8080))
                .unwrap(),
        );
        let result = manifest.validate();
        assert!(
            matches!(result, Err(ConfigError::OverlappingPrefixes(_, _))),
            "{result:?}",
        );
    }

    // Two NAT exposes with disjoint ips and as_range passes
    #[test]
    fn test_nat_disjoint_ips_and_as_range_passes() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateless_nat()
                .unwrap()
                .ip("10.0.0.0/16".into())
                .as_range("2.0.0.0/16".into())
                .unwrap(),
        );
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateless_nat()
                .unwrap()
                .ip("10.1.0.0/16".into())
                .as_range("2.1.0.0/16".into())
                .unwrap(),
        );
        assert_eq!(manifest.validate(), Ok(()));
    }

    // Two stateless NAT exposes with overlapping ips rejected
    #[test]
    fn test_stateless_nat_overlapping_ips_rejected() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateless_nat()
                .unwrap()
                .ip("10.0.0.0/16".into())
                .as_range("2.0.0.0/16".into())
                .unwrap(),
        );
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateless_nat()
                .unwrap()
                .ip("10.0.0.0/16".into())
                .as_range("3.0.0.0/16".into())
                .unwrap(),
        );
        let result = manifest.validate();
        assert!(
            matches!(result, Err(ConfigError::OverlappingPrefixes(_, _))),
            "{result:?}",
        );
    }

    // Two stateless NAT exposes with overlapping as_range rejected
    #[test]
    fn test_stateless_nat_overlapping_as_range_rejected() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateless_nat()
                .unwrap()
                .ip("10.0.0.0/16".into())
                .as_range("2.0.0.0/16".into())
                .unwrap(),
        );
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateless_nat()
                .unwrap()
                .ip("10.1.0.0/16".into())
                .as_range("2.0.0.0/16".into())
                .unwrap(),
        );
        let result = manifest.validate();
        assert!(
            matches!(result, Err(ConfigError::OverlappingPrefixes(_, _))),
            "{result:?}",
        );
    }

    // Stateless NAT + stateful NAT ips overlap rejected
    #[test]
    fn test_stateless_nat_plus_stateful_ips_overlap_rejected() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateless_nat()
                .unwrap()
                .ip("10.0.0.0/16".into())
                .as_range("2.0.0.0/16".into())
                .unwrap(),
        );
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateful_nat(None)
                .unwrap()
                .ip("10.0.0.0/16".into())
                .as_range("3.0.0.0/16".into())
                .unwrap(),
        );
        let result = manifest.validate();
        assert!(
            matches!(result, Err(ConfigError::OverlappingPrefixes(_, _))),
            "{result:?}",
        );
    }

    // Stateless NAT + stateful NAT as_range overlap rejected
    #[test]
    fn test_stateless_nat_plus_stateful_as_range_overlap_rejected() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateless_nat()
                .unwrap()
                .ip("10.0.0.0/16".into())
                .as_range("2.0.0.0/16".into())
                .unwrap(),
        );
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateful_nat(None)
                .unwrap()
                .ip("10.1.0.0/16".into())
                .as_range("2.0.0.0/16".into())
                .unwrap(),
        );
        let result = manifest.validate();
        assert!(
            matches!(result, Err(ConfigError::OverlappingPrefixes(_, _))),
            "{result:?}",
        );
    }

    // Stateless NAT + port forwarding ips overlap rejected
    #[test]
    fn test_stateless_nat_plus_port_forwarding_ips_overlap_rejected() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateless_nat()
                .unwrap()
                .ip("10.0.0.0/16".into())
                .as_range("2.0.0.0/16".into())
                .unwrap(),
        );
        manifest.add_expose(
            VpcExpose::empty()
                .make_port_forwarding(None, None)
                .unwrap()
                .ip(prefix_with_ports("10.0.0.1/32", 80, 80))
                .as_range(prefix_with_ports("3.0.0.1/32", 8080, 8080))
                .unwrap(),
        );
        let result = manifest.validate();
        assert!(
            matches!(result, Err(ConfigError::OverlappingPrefixes(_, _))),
            "{result:?}",
        );
    }

    // Stateless NAT + port forwarding as_range overlap rejected
    #[test]
    fn test_stateless_nat_plus_port_forwarding_as_range_overlap_rejected() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateless_nat()
                .unwrap()
                .ip("10.0.0.0/16".into())
                .as_range("2.0.0.0/16".into())
                .unwrap(),
        );
        manifest.add_expose(
            VpcExpose::empty()
                .make_port_forwarding(None, None)
                .unwrap()
                .ip(prefix_with_ports("10.1.0.1/32", 80, 80))
                .as_range(prefix_with_ports("2.0.0.1/32", 8080, 8080))
                .unwrap(),
        );
        let result = manifest.validate();
        assert!(
            matches!(result, Err(ConfigError::OverlappingPrefixes(_, _))),
            "{result:?}",
        );
    }

    // Two stateful NAT exposes with overlapping ips rejected
    #[test]
    fn test_stateful_nat_overlapping_ips_rejected() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateful_nat(None)
                .unwrap()
                .ip("10.0.0.0/16".into())
                .as_range("2.0.0.0/24".into())
                .unwrap(),
        );
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateful_nat(None)
                .unwrap()
                .ip("10.0.0.0/16".into())
                .as_range("3.0.0.0/24".into())
                .unwrap(),
        );
        let result = manifest.validate();
        assert!(
            matches!(result, Err(ConfigError::OverlappingPrefixes(_, _))),
            "{result:?}",
        );
    }

    // Two stateful NAT exposes with overlapping as_range rejected
    #[test]
    fn test_stateful_nat_overlapping_as_range_rejected() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateful_nat(None)
                .unwrap()
                .ip("10.0.0.0/16".into())
                .as_range("2.0.0.0/16".into())
                .unwrap(),
        );
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateful_nat(None)
                .unwrap()
                .ip("10.1.0.0/16".into())
                .as_range("2.0.1.0/24".into())
                .unwrap(),
        );
        let result = manifest.validate();
        assert!(
            matches!(result, Err(ConfigError::OverlappingPrefixes(_, _))),
            "{result:?}",
        );
    }

    // Two port forwarding exposes with overlapping ips rejected
    #[test]
    fn test_two_port_forwarding_overlapping_ips_rejected() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(
            VpcExpose::empty()
                .make_port_forwarding(None, None)
                .unwrap()
                .ip(prefix_with_ports("10.0.0.1/32", 80, 80))
                .as_range(prefix_with_ports("2.0.0.1/32", 8080, 8080))
                .unwrap(),
        );
        manifest.add_expose(
            VpcExpose::empty()
                .make_port_forwarding(None, None)
                .unwrap()
                .ip(prefix_with_ports("10.0.0.1/32", 80, 80))
                .as_range(prefix_with_ports("3.0.0.1/32", 8080, 8080))
                .unwrap(),
        );
        let result = manifest.validate();
        assert!(
            matches!(result, Err(ConfigError::OverlappingPrefixes(_, _))),
            "{result:?}",
        );
    }

    // Two port forwarding exposes with overlapping as_range rejected
    #[test]
    fn test_two_port_forwarding_overlapping_as_range_rejected() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(
            VpcExpose::empty()
                .make_port_forwarding(None, None)
                .unwrap()
                .ip(prefix_with_ports("10.0.0.1/32", 80, 80))
                .as_range(prefix_with_ports("2.0.0.1/32", 8080, 8080))
                .unwrap(),
        );
        manifest.add_expose(
            VpcExpose::empty()
                .make_port_forwarding(None, None)
                .unwrap()
                .ip(prefix_with_ports("10.1.0.1/32", 80, 80))
                .as_range(prefix_with_ports("2.0.0.1/32", 8080, 8080))
                .unwrap(),
        );
        let result = manifest.validate();
        assert!(
            matches!(result, Err(ConfigError::OverlappingPrefixes(_, _))),
            "{result:?}",
        );
    }

    // Two port forwarding exposes with overlapping as_range IP prefixes but different ports passes
    #[test]
    fn test_two_port_forwarding_overlapping_as_range_with_different_ports_passes() {
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(
            VpcExpose::empty()
                .make_port_forwarding(None, None)
                .unwrap()
                .ip(prefix_with_ports("10.0.0.1/32", 80, 80))
                .as_range(prefix_with_ports("2.0.0.1/32", 8080, 8080))
                .unwrap(),
        );
        manifest.add_expose(
            VpcExpose::empty()
                .make_port_forwarding(None, None)
                .unwrap()
                .ip(prefix_with_ports("10.1.0.1/32", 90, 90))
                .as_range(prefix_with_ports("2.0.0.1/32", 9090, 9090))
                .unwrap(),
        );
        assert_eq!(manifest.validate(), Ok(()));
    }

    // Stateful + port forwarding overlap where stateful NAT contains port forwarding passes
    #[test]
    fn test_stateful_plus_port_forwarding_left_contains_right_passes() {
        let mut manifest = VpcManifest::new("VPC-1");
        // Stateful NAT covers the broader range
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateful_nat(None)
                .unwrap()
                .ip("10.0.0.0/24".into())
                .as_range("2.0.0.0/24".into())
                .unwrap(),
        );
        // Port forwarding covers a subset
        manifest.add_expose(
            VpcExpose::empty()
                .make_port_forwarding(None, None)
                .unwrap()
                .ip(prefix_with_ports("10.0.0.1/32", 80, 80))
                .as_range(prefix_with_ports("2.0.0.1/32", 8080, 8080))
                .unwrap(),
        );
        assert_eq!(manifest.validate(), Ok(()));
    }

    // Stateful + port forwarding partial overlap passes
    #[test]
    fn test_stateful_plus_port_forwarding_partial_overlap_passes() {
        let mut manifest = VpcManifest::new("VPC-1");
        // Stateful NAT has a narrow range (10.0.0.0/25 = .0-.127)
        manifest.add_expose(
            VpcExpose::empty()
                .make_stateful_nat(None)
                .unwrap()
                .ip("10.0.0.0/25".into())
                .as_range("2.0.0.0/25".into())
                .unwrap(),
        );
        // Port forwarding uses a broader prefix (10.0.0.0/24 = .0-.255), not fully contained
        manifest.add_expose(
            VpcExpose::empty()
                .make_port_forwarding(None, None)
                .unwrap()
                .ip(prefix_with_ports("10.0.0.0/24", 80, 80))
                .as_range(prefix_with_ports("3.0.0.0/24", 8080, 8080))
                .unwrap(),
        );
        assert_eq!(manifest.validate(), Ok(()));
    }

    // ==================================================================================
    // Peering-level NAT combination validation
    // ==================================================================================

    // No NAT + no NAT passes
    #[test]
    fn test_no_nat_plus_no_nat_passes() {
        let peering = VpcPeering::with_default_group(
            "Peering-1",
            VpcManifest::with_exposes("VPC-1", vec![VpcExpose::empty().ip("10.0.0.0/16".into())]),
            VpcManifest::with_exposes("VPC-2", vec![VpcExpose::empty().ip("10.1.0.0/16".into())]),
        );
        assert!(validate_overlay_with_peering(peering).is_ok());
    }

    // No NAT + any NAT on remote passes
    #[test]
    fn test_no_nat_plus_any_nat_on_remote_passes() {
        // No NAT on left, stateful NAT on right
        let peering = VpcPeering::with_default_group(
            "Peering-1",
            VpcManifest::with_exposes("VPC-1", vec![VpcExpose::empty().ip("10.0.0.0/16".into())]),
            VpcManifest::with_exposes(
                "VPC-2",
                vec![
                    VpcExpose::empty()
                        .make_stateful_nat(None)
                        .unwrap()
                        .ip("1.0.0.0/8".into())
                        .as_range("2.0.0.0/8".into())
                        .unwrap(),
                ],
            ),
        );
        assert!(validate_overlay_with_peering(peering).is_ok());
    }

    // Stateless + stateless passes
    #[test]
    fn test_stateless_plus_stateless_passes() {
        let peering = VpcPeering::with_default_group(
            "Peering-1",
            VpcManifest::with_exposes(
                "VPC-1",
                vec![
                    VpcExpose::empty()
                        .make_stateless_nat()
                        .unwrap()
                        .ip("1.0.0.0/8".into())
                        .as_range("2.0.0.0/8".into())
                        .unwrap(),
                ],
            ),
            VpcManifest::with_exposes(
                "VPC-2",
                vec![
                    VpcExpose::empty()
                        .make_stateless_nat()
                        .unwrap()
                        .ip("3.0.0.0/8".into())
                        .as_range("4.0.0.0/8".into())
                        .unwrap(),
                ],
            ),
        );
        assert!(validate_overlay_with_peering(peering).is_ok());
    }

    // Stateless + stateful rejected
    #[test]
    fn test_stateless_plus_stateful_rejected() {
        let peering = VpcPeering::with_default_group(
            "Peering-1",
            VpcManifest::with_exposes(
                "VPC-1",
                vec![
                    VpcExpose::empty()
                        .make_stateful_nat(None)
                        .unwrap()
                        .ip("1.0.0.0/8".into())
                        .as_range("2.0.0.0/8".into())
                        .unwrap(),
                ],
            ),
            VpcManifest::with_exposes(
                "VPC-2",
                vec![
                    VpcExpose::empty()
                        .make_stateless_nat()
                        .unwrap()
                        .ip("3.0.0.0/8".into())
                        .as_range("4.0.0.0/8".into())
                        .unwrap(),
                ],
            ),
        );
        let result = validate_overlay_with_peering(peering);
        assert_eq!(
            result,
            Err(ConfigError::IncompatibleNatModes("Peering-1".to_owned())),
            "{result:?}",
        );
    }

    // Stateless + port forwarding rejected
    #[test]
    fn test_stateless_plus_port_forwarding_rejected() {
        let peering = VpcPeering::with_default_group(
            "Peering-1",
            VpcManifest::with_exposes(
                "VPC-1",
                vec![
                    VpcExpose::empty()
                        .make_port_forwarding(None, None)
                        .unwrap()
                        .ip(prefix_with_ports("1.0.0.1/32", 80, 80))
                        .as_range(prefix_with_ports("2.0.0.1/32", 8080, 8080))
                        .unwrap(),
                ],
            ),
            VpcManifest::with_exposes(
                "VPC-2",
                vec![
                    VpcExpose::empty()
                        .make_stateless_nat()
                        .unwrap()
                        .ip("3.0.0.0/8".into())
                        .as_range("4.0.0.0/8".into())
                        .unwrap(),
                ],
            ),
        );
        let result = validate_overlay_with_peering(peering);
        assert_eq!(
            result,
            Err(ConfigError::IncompatibleNatModes("Peering-1".to_owned())),
            "{result:?}",
        );
    }

    // Stateful + stateful rejected (across peering sides)
    #[test]
    fn test_stateful_plus_stateful_rejected() {
        let peering = VpcPeering::with_default_group(
            "Peering-1",
            VpcManifest::with_exposes(
                "VPC-1",
                vec![
                    VpcExpose::empty()
                        .make_stateful_nat(None)
                        .unwrap()
                        .ip("1.0.0.0/8".into())
                        .as_range("2.0.0.0/8".into())
                        .unwrap(),
                ],
            ),
            VpcManifest::with_exposes(
                "VPC-2",
                vec![
                    VpcExpose::empty()
                        .make_stateful_nat(None)
                        .unwrap()
                        .ip("3.0.0.0/8".into())
                        .as_range("4.0.0.0/8".into())
                        .unwrap(),
                ],
            ),
        );
        let result = validate_overlay_with_peering(peering);
        assert_eq!(
            result,
            Err(ConfigError::IncompatibleNatModes("Peering-1".to_owned())),
            "{result:?}",
        );
    }

    // Stateful + port forwarding rejected (across peering sides)
    #[test]
    fn test_stateful_plus_port_forwarding_rejected() {
        let peering = VpcPeering::with_default_group(
            "Peering-1",
            VpcManifest::with_exposes(
                "VPC-1",
                vec![
                    VpcExpose::empty()
                        .make_stateful_nat(None)
                        .unwrap()
                        .ip("1.0.0.0/8".into())
                        .as_range("2.0.0.0/8".into())
                        .unwrap(),
                ],
            ),
            VpcManifest::with_exposes(
                "VPC-2",
                vec![
                    VpcExpose::empty()
                        .make_port_forwarding(None, None)
                        .unwrap()
                        .ip(prefix_with_ports("3.0.0.1/32", 80, 80))
                        .as_range(prefix_with_ports("4.0.0.1/32", 8080, 8080))
                        .unwrap(),
                ],
            ),
        );
        let result = validate_overlay_with_peering(peering);
        assert_eq!(
            result,
            Err(ConfigError::IncompatibleNatModes("Peering-1".to_owned())),
            "{result:?}",
        );
    }

    // Port forwarding + port forwarding rejected (across peering sides)
    #[test]
    fn test_port_forwarding_plus_port_forwarding_rejected() {
        let peering = VpcPeering::with_default_group(
            "Peering-1",
            VpcManifest::with_exposes(
                "VPC-1",
                vec![
                    VpcExpose::empty()
                        .make_port_forwarding(None, None)
                        .unwrap()
                        .ip(prefix_with_ports("1.0.0.1/32", 80, 80))
                        .as_range(prefix_with_ports("2.0.0.1/32", 8080, 8080))
                        .unwrap(),
                ],
            ),
            VpcManifest::with_exposes(
                "VPC-2",
                vec![
                    VpcExpose::empty()
                        .make_port_forwarding(None, None)
                        .unwrap()
                        .ip(prefix_with_ports("3.0.0.1/32", 80, 80))
                        .as_range(prefix_with_ports("4.0.0.1/32", 8080, 8080))
                        .unwrap(),
                ],
            ),
        );
        let result = validate_overlay_with_peering(peering);
        assert_eq!(
            result,
            Err(ConfigError::IncompatibleNatModes("Peering-1".to_owned())),
            "{result:?}",
        );
    }

    // ==================================================================================
    // Overlay-level tests (cross-peering)
    // ==================================================================================

    // Multiple peerings between same VPCs rejected
    #[test]
    fn test_multiple_peerings_same_vpcs_rejected() {
        let peering1 = VpcPeering::with_default_group(
            "Peering-1",
            VpcManifest::new("VPC-1"),
            VpcManifest::new("VPC-2"),
        );
        let peering2 = VpcPeering::with_default_group(
            "Peering-2",
            VpcManifest::new("VPC-1"),
            VpcManifest::new("VPC-2"),
        );

        let vpc1 = Vpc::new("VPC-1", "VPC01", 1).unwrap();
        let vpc2 = Vpc::new("VPC-2", "VPC02", 2).unwrap();
        let mut vpc_table = VpcTable::new();
        vpc_table.add(vpc1).unwrap();
        vpc_table.add(vpc2).unwrap();

        let mut peering_table = VpcPeeringTable::new();
        peering_table.add(peering1).unwrap();
        peering_table.add(peering2).unwrap();

        let mut overlay = Overlay::new(vpc_table, peering_table);
        let result = overlay.validate();
        assert!(
            matches!(result, Err(ConfigError::DuplicateVpcPeerings(_))),
            "{result:?}",
        );
    }

    // Cross-peering overlapping public prefixes rejected
    #[test]
    fn test_cross_peering_overlapping_public_prefixes_rejected() {
        // VPC-2 and VPC-3 both expose overlapping prefixes to VPC-1
        let peering1 = VpcPeering::with_default_group(
            "Peering-1",
            VpcManifest::with_exposes("VPC-1", vec![VpcExpose::empty().ip("8.0.0.0/16".into())]),
            VpcManifest::with_exposes("VPC-2", vec![VpcExpose::empty().ip("10.0.0.0/16".into())]),
        );
        let peering2 = VpcPeering::with_default_group(
            "Peering-2",
            VpcManifest::with_exposes("VPC-1", vec![VpcExpose::empty().ip("9.0.0.0/16".into())]),
            VpcManifest::with_exposes("VPC-3", vec![VpcExpose::empty().ip("10.0.1.0/24".into())]),
        );
        let result = validate_overlay_3vpc(peering1, peering2);
        assert!(
            matches!(result, Err(ConfigError::OverlappingPrefixes(_, _))),
            "{result:?}",
        );
    }

    // Cross-peering overlapping public prefixes with both stateful NAT passes
    #[test]
    fn test_cross_peering_overlapping_both_stateful_nat_passes() {
        let peering1 = VpcPeering::with_default_group(
            "Peering-1",
            VpcManifest::with_exposes("VPC-1", vec![VpcExpose::empty().ip("8.0.0.0/16".into())]),
            VpcManifest::with_exposes(
                "VPC-2",
                vec![
                    VpcExpose::empty()
                        .make_stateful_nat(None)
                        .unwrap()
                        .ip("10.0.0.0/16".into())
                        .as_range("1.0.0.0/16".into())
                        .unwrap(),
                ],
            ),
        );
        let peering2 = VpcPeering::with_default_group(
            "Peering-2",
            VpcManifest::with_exposes("VPC-1", vec![VpcExpose::empty().ip("9.0.0.0/16".into())]),
            VpcManifest::with_exposes(
                "VPC-3",
                vec![
                    VpcExpose::empty()
                        .make_stateful_nat(None)
                        .unwrap()
                        .ip("20.0.0.0/16".into())
                        .as_range("1.0.0.0/16".into())
                        .unwrap(),
                ],
            ),
        );
        assert!(validate_overlay_3vpc(peering1, peering2).is_ok());
    }

    // Cross-peering overlapping private prefixes only passes
    #[test]
    fn test_cross_peering_private_prefixes_overlapping_passes() {
        let peering1 = VpcPeering::with_default_group(
            "Peering-1",
            VpcManifest::with_exposes("VPC-1", vec![VpcExpose::empty().ip("8.0.0.0/16".into())]),
            VpcManifest::with_exposes(
                "VPC-2",
                vec![
                    VpcExpose::empty()
                        .make_stateless_nat()
                        .unwrap()
                        .ip("10.0.0.0/16".into())
                        .as_range("1.0.0.0/16".into())
                        .unwrap(),
                ],
            ),
        );
        let peering2 = VpcPeering::with_default_group(
            "Peering-2",
            VpcManifest::with_exposes("VPC-1", vec![VpcExpose::empty().ip("9.0.0.0/16".into())]),
            VpcManifest::with_exposes(
                "VPC-3",
                vec![
                    VpcExpose::empty()
                        .make_stateless_nat()
                        .unwrap()
                        .ip("10.0.0.0/16".into())
                        .as_range("2.0.0.0/16".into())
                        .unwrap(),
                ],
            ),
        );
        assert!(validate_overlay_3vpc(peering1, peering2).is_ok());
    }

    // Multiple default destinations exposed to same VPC rejected
    #[test]
    fn test_multiple_default_destinations_to_same_vpc_rejected() {
        let peering1 = VpcPeering::with_default_group(
            "Peering-1",
            VpcManifest::with_exposes("VPC-1", vec![VpcExpose::empty().ip("8.0.0.0/16".into())]),
            VpcManifest::with_exposes("VPC-2", vec![VpcExpose::empty().set_default()]),
        );
        let peering2 = VpcPeering::with_default_group(
            "Peering-2",
            VpcManifest::with_exposes("VPC-1", vec![VpcExpose::empty().ip("9.0.0.0/16".into())]),
            VpcManifest::with_exposes("VPC-3", vec![VpcExpose::empty().set_default()]),
        );
        let result = validate_overlay_3vpc(peering1, peering2);
        assert!(
            matches!(result, Err(ConfigError::Forbidden(_))),
            "{result:?}",
        );
    }

    // Multiple default expose blocks in same peering rejected
    #[test]
    fn test_multiple_default_exposes_same_peering_rejected() {
        let peering = VpcPeering::with_default_group(
            "Peering-1",
            VpcManifest::with_exposes("VPC-1", vec![VpcExpose::empty().ip("8.0.0.0/16".into())]),
            VpcManifest::with_exposes(
                "VPC-2",
                vec![
                    VpcExpose::empty().set_default(),
                    VpcExpose::empty().set_default(),
                ],
            ),
        );
        let result = validate_overlay_with_peering(peering);
        assert!(
            matches!(result, Err(ConfigError::Forbidden(_))),
            "{result:?}",
        );
    }

    // Default expose cannot have NAT
    #[test]
    fn test_default_expose_cannot_have_nat() {
        // A default expose cannot have nat field set at all
        let expose = VpcExpose::empty().set_default();
        // Verify default alone is valid
        assert_eq!(expose.validate(), Ok(()));

        // Default with NAT should fail
        let expose = VpcExpose::empty()
            .set_default()
            .make_stateless_nat()
            .unwrap();

        let result = expose.validate();
        assert!(matches!(result, Err(ConfigError::Invalid(_))), "{result:?}");
    }

    // Default to default is illegal
    // Gut feeling: it doesn't sound good, we forbid it for now and might relax later
    #[test]
    fn test_default_to_default_rejected() {
        let peering = VpcPeering::with_default_group(
            "Peering-1",
            VpcManifest::with_exposes("VPC-1", vec![VpcExpose::empty().set_default()]),
            VpcManifest::with_exposes("VPC-2", vec![VpcExpose::empty().set_default()]),
        );
        let result = validate_overlay_with_peering(peering);
        assert!(
            matches!(result, Err(ConfigError::Forbidden(_))),
            "{result:?}",
        );
    }
}

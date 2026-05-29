// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(feature = "dpdk")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use core::net::Ipv4Addr;
use core::num::NonZero;
use std::error::Error;

use dataplane_acl::dpdk::install::install_table;
use dataplane_acl::dpdk::rule::{Dpdk, RuleSpec};
use dataplane_acl::dpdk_table_alias;
use dpdk::acl::{CategoryMask, Priority};
use lookup::Lookup;
use match_action::{ExactSpec, FixedSize, MatchKey, PrefixSpec, RangeSpec};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct IpProto(u8);

impl IpProto {
    const TCP: Self = IpProto(6);
}

impl FixedSize for IpProto {
    const SIZE: usize = 1;
    fn write_be(&self, out: &mut [u8]) {
        out[0] = self.0;
    }
}

#[derive(MatchKey)]
struct FiveTuple {
    #[exact]
    proto: IpProto,
    #[prefix]
    src_ip: Ipv4Addr,
    #[prefix]
    dst_ip: Ipv4Addr,
    #[range]
    src_port: u16,
    #[range]
    dst_port: u16,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Verdict {
    Allow,
    Drop,
}

dpdk_table_alias!(type FiveTupleTable<A> = FiveTuple);

#[test]
#[dpdk::with_eal]
fn install_one_rule_and_classify() -> Result<(), Box<dyn Error>> {
    let rule_spec = vec![
        RuleSpec::<FiveTuple, Verdict>::new(
            Priority::new(100)?,
            CategoryMask::new(1)?,
            FiveTupleRule {
                proto: ExactSpec::new(IpProto::TCP),
                src_ip: PrefixSpec::new("10.0.0.0".parse()?, 8),
                dst_ip: PrefixSpec::new(Ipv4Addr::UNSPECIFIED, 0),
                src_port: RangeSpec::new(0, u16::MAX),
                dst_port: RangeSpec::exact(22),
            }
            .into_backend_fields::<Dpdk>(),
            Verdict::Drop,
        )
        .expect("invalid RuleSpec"),
        RuleSpec::<FiveTuple, Verdict>::new(
            Priority::new(500)?,
            CategoryMask::new(1)?,
            FiveTupleRule {
                proto: ExactSpec::new(IpProto::TCP),
                src_ip: PrefixSpec::new("10.0.0.0".parse()?, 30),
                dst_ip: PrefixSpec::new(Ipv4Addr::UNSPECIFIED, 0),
                src_port: RangeSpec::new(0, u16::MAX),
                dst_port: RangeSpec::exact(22),
            }
            .into_backend_fields::<Dpdk>(),
            Verdict::Allow,
        )
        .expect("invalid RuleSpec"),
    ];

    let table: FiveTupleTable<Verdict> = install_table(
        "eal_install_classify_smoke",
        NonZero::new(16).expect("max rules"),
        rule_spec,
    )
    .expect("install_table");
    assert_eq!(
        table.lookup(&FiveTuple {
            proto: IpProto::TCP,
            src_ip: "10.0.1.5".parse()?,
            dst_ip: "192.168.1.1".parse()?,
            src_port: 54321,
            dst_port: 22,
        }),
        Some(&Verdict::Drop),
    );
    let batch = [
        FiveTuple {
            proto: IpProto::TCP,
            src_ip: "10.0.0.1".parse()?,
            dst_ip: "192.168.1.1".parse()?,
            src_port: 54321,
            dst_port: 22,
        },
        FiveTuple {
            proto: IpProto::TCP,
            src_ip: "10.0.1.5".parse()?,
            dst_ip: "192.168.1.1".parse()?,
            src_port: 54321,
            dst_port: 22,
        },
        FiveTuple {
            proto: IpProto::TCP,
            src_ip: "192.168.1.5".parse()?,
            dst_ip: "192.168.1.1".parse()?,
            src_port: 54321,
            dst_port: 22,
        },
        FiveTuple {
            proto: IpProto::TCP,
            src_ip: "10.0.1.5".parse()?,
            dst_ip: "192.168.1.1".parse()?,
            src_port: 54321,
            dst_port: 80,
        },
    ];
    let mut out: [Option<&Verdict>; 4] = [None; 4];
    table.lookup_batch(&batch, &mut out).expect("lookup_batch");
    assert_eq!(
        out,
        [Some(&Verdict::Allow), Some(&Verdict::Drop), None, None]
    );
    Ok(())
}

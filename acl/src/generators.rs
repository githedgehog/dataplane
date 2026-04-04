// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Bolero `TypeGenerator` and `ValueGenerator` implementations for
//! ACL types.
//!
//! `TypeGenerator` impls are covering: they will eventually produce
//! every legal value for the type.
//!
//! `ValueGenerator` impls target interesting subsets (boundary
//! conditions, common patterns, known-tricky cases).
//!
//! Generators compose: compound types delegate to their components'
//! generators via `driver.produce::<T>()`.

// ---- Leaf types ----

mod priority_gen {
    use crate::priority::Priority;
    use bolero::TypeGenerator;
    use std::num::NonZero;

    impl TypeGenerator for Priority {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            let nz = driver.produce::<NonZero<u32>>()?;
            Some(Priority::new(nz.get()).unwrap_or_else(|_| {
                // NonZero<u32> is always >= 1, so this can't fail.
                unreachable!()
            }))
        }
    }
}

mod prefix_gen {
    use crate::range::{Ipv4Prefix, Ipv6Prefix};
    use bolero::TypeGenerator;
    use std::net::{Ipv4Addr, Ipv6Addr};

    impl TypeGenerator for Ipv4Prefix {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            let raw = driver.produce::<[u8; 4]>()?;
            let prefix_len = driver.produce::<u8>()? % 33; // 0..=32

            // Mask off host bits to ensure validity.
            let mask = if prefix_len == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix_len)
            };
            let addr_bits = u32::from(Ipv4Addr::from(raw)) & mask;
            let addr = Ipv4Addr::from(addr_bits);

            // This cannot fail — we've already masked host bits.
            #[allow(clippy::unwrap_used)]
            Some(Ipv4Prefix::new(addr, prefix_len).unwrap())
        }
    }

    impl TypeGenerator for Ipv6Prefix {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            let raw = driver.produce::<[u8; 16]>()?;
            let prefix_len = driver.produce::<u8>()? % 129; // 0..=128

            let mask = if prefix_len == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix_len)
            };
            let addr_bits = u128::from(Ipv6Addr::from(raw)) & mask;
            let addr = Ipv6Addr::from(addr_bits);

            #[allow(clippy::unwrap_used)]
            Some(Ipv6Prefix::new(addr, prefix_len).unwrap())
        }
    }
}

mod port_range_gen {
    use crate::range::PortRange;
    use bolero::TypeGenerator;

    impl TypeGenerator for PortRange<u16> {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            let a = driver.produce::<u16>()?;
            let b = driver.produce::<u16>()?;
            let (min, max) = if a <= b { (a, b) } else { (b, a) };
            Some(PortRange { min, max })
        }
    }
}

// ---- FieldMatch<T> ----

mod field_match_gen {
    use crate::match_expr::FieldMatch;
    use bolero::TypeGenerator;

    impl<T: TypeGenerator> TypeGenerator for FieldMatch<T> {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            // ~50% Ignore, ~50% Select — biased toward producing
            // both variants equally.
            if driver.produce::<bool>()? {
                Some(FieldMatch::Select(driver.produce::<T>()?))
            } else {
                Some(FieldMatch::Ignore)
            }
        }
    }
}

// ---- Match field structs ----

mod match_field_gen {
    use crate::match_fields::*;
    use bolero::TypeGenerator;

    impl TypeGenerator for EthMatch {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                src_mac: driver.produce()?,
                dst_mac: driver.produce()?,
                ether_type: driver.produce()?,
            })
        }
    }

    impl TypeGenerator for VlanMatch {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                vid: driver.produce()?,
                pcp: driver.produce()?,
                inner_ether_type: driver.produce()?,
            })
        }
    }

    impl TypeGenerator for Ipv4Match {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                src: driver.produce()?,
                dst: driver.produce()?,
                protocol: driver.produce()?,
            })
        }
    }

    impl TypeGenerator for Ipv6Match {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                src: driver.produce()?,
                dst: driver.produce()?,
                protocol: driver.produce()?,
            })
        }
    }

    impl TypeGenerator for TcpMatch {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                src: driver.produce()?,
                dst: driver.produce()?,
            })
        }
    }

    impl TypeGenerator for UdpMatch {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                src: driver.produce()?,
                dst: driver.produce()?,
            })
        }
    }

    impl TypeGenerator for Icmp4Match {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                icmp_type: driver.produce()?,
                icmp_code: driver.produce()?,
            })
        }
    }
}

// ---- Action types ----

mod action_gen {
    use crate::action::{ActionSequence, Fate, Step, TableId};
    use bolero::TypeGenerator;

    impl TypeGenerator for Step {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            match driver.produce::<u8>()? % 2 {
                0 => Some(Step::Count(driver.produce()?)),
                _ => Some(Step::Mark(driver.produce()?)),
            }
        }
    }

    impl TypeGenerator for Fate {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            match driver.produce::<u8>()? % 4 {
                0 => Some(Fate::Drop),
                1 => Some(Fate::Trap),
                2 => Some(Fate::Forward),
                _ => Some(Fate::Jump(driver.produce::<TableId>()?)),
            }
        }
    }

    impl TypeGenerator for ActionSequence {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            // 0-4 steps, then a fate.
            let step_count = driver.produce::<u8>()? % 5;
            let mut steps = Vec::with_capacity(step_count as usize);
            for _ in 0..step_count {
                steps.push(driver.produce()?);
            }
            let fate = driver.produce()?;
            Some(ActionSequence::new(steps, fate))
        }
    }
}

// ---- AclRule (without builder — direct construction for testing) ----

mod rule_gen {
    use crate::action::ActionSequence;
    use crate::builder::AclRuleBuilder;
    use crate::match_fields::{EthMatch, Ipv4Match, TcpMatch, UdpMatch, Icmp4Match, Ipv6Match};
    use crate::priority::Priority;
    use crate::rule::AclRule;
    use bolero::TypeGenerator;

    impl TypeGenerator for AclRule {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            // Generate via the builder to get valid match field combinations
            // with proper conform() behavior (e.g., adding TCP sets
            // protocol=TCP on the IPv4 match).
            let has_eth = driver.produce::<bool>()?;

            let builder = AclRuleBuilder::new();
            if has_eth {
                let eth: EthMatch = driver.produce()?;
                let builder2 = builder.eth(|e| *e = eth);

                let ip_choice = driver.produce::<u8>()? % 3;
                match ip_choice {
                    0 => {
                        let ipv4: Ipv4Match = driver.produce()?;
                        let builder3 = builder2.ipv4(|ip| *ip = ipv4);
                        let transport = driver.produce::<u8>()? % 4; // AGENT: ideally this number would be derived from the enum size.  Maybe strum can help
                        let pri = driver.produce::<Priority>()?;
                        let actions = driver.produce::<ActionSequence>()?;
                        return Some(match transport {
                            0 => {
                                let tcp: TcpMatch = driver.produce()?;
                                builder3.tcp(|t| *t = tcp).action(actions, pri)
                            }
                            1 => {
                                let udp: UdpMatch = driver.produce()?;
                                builder3.udp(|u| *u = udp).action(actions, pri)
                            }
                            2 => {
                                let icmp: Icmp4Match = driver.produce()?;
                                builder3.icmp4(|i| *i = icmp).action(actions, pri)
                            }
                            _ => builder3.action(actions, pri),
                        });
                    }
                    1 => {
                        let ipv6: Ipv6Match = driver.produce()?;
                        let builder3 = builder2.ipv6(|ip| *ip = ipv6);
                        let transport = driver.produce::<u8>()? % 3;
                        let pri = driver.produce::<Priority>()?;
                        let actions = driver.produce::<ActionSequence>()?;
                        return Some(match transport {
                            0 => {
                                let tcp: TcpMatch = driver.produce()?;
                                builder3.tcp(|t| *t = tcp).action(actions, pri)
                            }
                            1 => {
                                let udp: UdpMatch = driver.produce()?;
                                builder3.udp(|u| *u = udp).action(actions, pri)
                            }
                            _ => builder3.action(actions, pri),
                        });
                    }
                    _ => {
                        let pri = driver.produce::<Priority>()?;
                        let actions = driver.produce::<ActionSequence>()?;
                        return Some(builder2.action(actions, pri));
                    }
                }
            }

            let pri = driver.produce::<Priority>()?;
            let actions = driver.produce::<ActionSequence>()?;
            Some(builder.action(actions, pri))
        }
    }
}

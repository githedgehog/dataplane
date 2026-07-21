// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use core::net::Ipv4Addr;

use dataplane_match_action::{
    ExactSpec, FieldKind, FixedSize, MatchKey, PrefixSpec, RangeSpec, RuleField,
};
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct IpProto(u8);

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

#[test]
fn n_and_key_size_match_field_layout() {
    assert_eq!(FiveTuple::N, 5);
    assert_eq!(FiveTuple::KEY_SIZE, 13);
}

#[test]
fn field_specs_match_declaration_order() {
    let specs = FiveTuple::field_specs();
    assert_eq!(specs.len(), 5);

    assert_eq!(specs[0].name, "proto");
    assert_eq!(specs[0].kind, FieldKind::Exact);
    assert_eq!(specs[0].size, 1);
    assert_eq!(specs[0].offset, 0);

    assert_eq!(specs[1].name, "src_ip");
    assert_eq!(specs[1].kind, FieldKind::Prefix);
    assert_eq!(specs[1].size, 4);
    assert_eq!(specs[1].offset, 1);

    assert_eq!(specs[2].name, "dst_ip");
    assert_eq!(specs[2].kind, FieldKind::Prefix);
    assert_eq!(specs[2].size, 4);
    assert_eq!(specs[2].offset, 5);

    assert_eq!(specs[3].name, "src_port");
    assert_eq!(specs[3].kind, FieldKind::Range);
    assert_eq!(specs[3].size, 2);
    assert_eq!(specs[3].offset, 9);

    assert_eq!(specs[4].name, "dst_port");
    assert_eq!(specs[4].kind, FieldKind::Range);
    assert_eq!(specs[4].size, 2);
    assert_eq!(specs[4].offset, 11);
}

#[test]
fn key_packs_big_endian_at_field_offsets() {
    let key = FiveTuple {
        proto: IpProto(6),
        src_ip: Ipv4Addr::new(10, 0, 1, 2),
        dst_ip: Ipv4Addr::new(192, 168, 5, 7),
        src_port: 54321,
        dst_port: 22,
    };
    let arr: [u8; FiveTuple::KEY_SIZE] = key.as_key();
    let mut buf = [0u8; FiveTuple::KEY_SIZE];
    key.as_key_into(&mut buf);
    assert_eq!(arr, buf);

    assert_eq!(arr[0], 6);
    assert_eq!(&arr[1..5], &[10, 0, 1, 2]);
    assert_eq!(&arr[5..9], &[192, 168, 5, 7]);
    assert_eq!(&arr[9..11], &54321u16.to_be_bytes());
    assert_eq!(&arr[11..13], &22u16.to_be_bytes());
}

#[test]
fn as_key_into_does_not_touch_bytes_past_the_key() {
    let key = FiveTuple {
        proto: IpProto(17),
        src_ip: Ipv4Addr::UNSPECIFIED,
        dst_ip: Ipv4Addr::UNSPECIFIED,
        src_port: 0,
        dst_port: 0,
    };
    let mut buf = [0xFFu8; 64];
    key.as_key_into(&mut buf);
    assert_eq!(buf[0], 17);
    assert_eq!(buf[FiveTuple::KEY_SIZE], 0xFF);
    assert_eq!(buf[63], 0xFF);
}

#[test]
fn derive_emits_parallel_rule_struct() {
    let rule = FiveTupleRule {
        proto: ExactSpec::new(IpProto(6)),
        src_ip: PrefixSpec::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        dst_ip: PrefixSpec::new(Ipv4Addr::UNSPECIFIED, 0),
        src_port: RangeSpec::new(0, u16::MAX),
        dst_port: RangeSpec::exact(80),
    };

    assert_eq!(rule.proto.value, IpProto(6));
    assert_eq!(rule.src_ip.len, 24);
    assert_eq!(rule.dst_ip.len, 0);
    assert_eq!(rule.src_port.min, 0);
    assert_eq!(rule.src_port.max, u16::MAX);
    assert_eq!(rule.dst_port.min, 80);
    assert_eq!(rule.dst_port.max, 80);
}

#[test]
fn rule_field_kinds_match_match_key_attrs() {
    assert_eq!(<ExactSpec<IpProto> as RuleField>::KIND, FieldKind::Exact);
    assert_eq!(<PrefixSpec<Ipv4Addr> as RuleField>::KIND, FieldKind::Prefix);
    assert_eq!(<RangeSpec<u16> as RuleField>::KIND, FieldKind::Range);
}

#[test]
fn single_field_key_works() {
    #[derive(MatchKey)]
    #[allow(dead_code)]
    struct Mono {
        #[exact]
        only: u32,
    }

    assert_eq!(Mono::N, 1);
    assert_eq!(Mono::KEY_SIZE, 4);
    let specs = Mono::field_specs();
    assert_eq!(specs[0].name, "only");
    assert_eq!(specs[0].offset, 0);
    assert_eq!(specs[0].kind, FieldKind::Exact);

    let m = Mono { only: 0xDEAD_BEEF };
    let arr = m.as_key();
    assert_eq!(arr, 0xDEAD_BEEFu32.to_be_bytes());
}

#[test]
fn range_spec_from_inclusive_range() {
    let r: RangeSpec<u16> = (80..=8080).into();
    assert_eq!(r.min, 80);
    assert_eq!(r.max, 8080);

    let single: RangeSpec<u16> = (22..=22).into();
    assert_eq!(single, RangeSpec::exact(22));
}

#[test]
fn fields_without_attribute_default_to_exact() {
    #[derive(MatchKey)]
    #[allow(dead_code)]
    struct AllExact {
        a: u8,
        b: u32,
    }

    let specs = AllExact::field_specs();
    assert_eq!(specs.len(), 2);
    assert_eq!(specs[0].kind, FieldKind::Exact);
    assert_eq!(specs[1].kind, FieldKind::Exact);
    assert_eq!(AllExact::KEY_SIZE, 5);
    let _rule = AllExactRule {
        a: ExactSpec::new(6u8),
        b: ExactSpec::new(0x0A00_0001u32),
    };

    let key = AllExact {
        a: 6,
        b: 0x0A00_0001,
    };
    let bytes = key.as_key();
    assert_eq!(bytes[0], 6);
    assert_eq!(&bytes[1..5], &0x0A00_0001u32.to_be_bytes());
}

#[test]
fn generic_match_key_instantiates_for_v4_and_v6() {
    use core::net::Ipv6Addr;
    #[derive(MatchKey)]
    #[allow(dead_code)]
    struct TwoTuple<Addr: FixedSize> {
        #[prefix]
        src: Addr,
        #[prefix]
        dst: Addr,
    }
    assert_eq!(<TwoTuple<Ipv4Addr>>::N, 2);
    assert_eq!(<TwoTuple<Ipv4Addr>>::KEY_SIZE, 8);
    let v4_specs = <TwoTuple<Ipv4Addr>>::field_specs();
    assert_eq!(v4_specs[0].size, 4);
    assert_eq!(v4_specs[1].offset, 4);
    assert_eq!(v4_specs[0].kind, FieldKind::Prefix);
    assert_eq!(<TwoTuple<Ipv6Addr>>::N, 2);
    assert_eq!(<TwoTuple<Ipv6Addr>>::KEY_SIZE, 32);
    let v6_specs = <TwoTuple<Ipv6Addr>>::field_specs();
    assert_eq!(v6_specs[0].size, 16);
    assert_eq!(v6_specs[1].offset, 16);
    let _v4_rule = TwoTupleRule::<Ipv4Addr> {
        src: PrefixSpec::new(Ipv4Addr::new(10, 0, 0, 0), 8),
        dst: PrefixSpec::new(Ipv4Addr::UNSPECIFIED, 0),
    };
    let v4 = TwoTuple::<Ipv4Addr> {
        src: Ipv4Addr::new(10, 0, 1, 2),
        dst: Ipv4Addr::new(192, 168, 5, 7),
    };
    let mut buf = [0u8; 8];
    v4.as_key_into(&mut buf);
    assert_eq!(&buf[0..4], &[10, 0, 1, 2]);
    assert_eq!(&buf[4..8], &[192, 168, 5, 7]);
}
#[test]
fn derive_accepts_explicit_where_clause() {
    #[derive(MatchKey)]
    #[allow(dead_code)]
    struct WithWhere<Addr>
    where
        Addr: FixedSize,
    {
        #[prefix]
        src: Addr,
    }

    assert_eq!(<WithWhere<Ipv4Addr>>::N, 1);
    assert_eq!(<WithWhere<Ipv4Addr>>::KEY_SIZE, 4);

    let _rule = WithWhereRule::<Ipv4Addr> {
        src: PrefixSpec::new(Ipv4Addr::UNSPECIFIED, 0),
    };
}

// A marker type that deliberately does NOT implement `FixedSize`, used to prove
// that a phantom-only generic parameter is not forced to be `FixedSize`.
#[allow(dead_code)]
struct NotFixed;

#[test]
fn phantom_data_field_is_excluded_from_key_layout() {
    use core::marker::PhantomData;

    // `PhantomData` fields are auto-detected (no attribute required).
    #[derive(MatchKey)]
    #[allow(dead_code)]
    struct Tagged {
        #[exact]
        port: u16,
        _marker: PhantomData<NotFixed>,
    }

    // The phantom field contributes nothing to N, KEY_SIZE, offsets, or specs.
    assert_eq!(Tagged::N, 1);
    assert_eq!(Tagged::KEY_SIZE, 2);
    let specs = Tagged::field_specs();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].name, "port");
    assert_eq!(specs[0].kind, FieldKind::Exact);

    let key = Tagged {
        port: 0x1234,
        _marker: PhantomData,
    };
    assert_eq!(key.as_key(), 0x1234u16.to_be_bytes());

    // The rule still carries the phantom field (constructed trivially) and matches
    // only on the real field.
    let rule = TaggedRule {
        port: ExactSpec::new(0x1234u16),
        _marker: PhantomData,
    };
    assert!(rule.accepts(&key));
    assert!(!rule.accepts(&Tagged {
        port: 9,
        _marker: PhantomData,
    }));
}

#[test]
fn phantom_attribute_marks_non_phantomdata_markers() {
    use core::marker::PhantomData;

    #[derive(MatchKey)]
    #[allow(dead_code)]
    struct Explicit {
        #[phantom]
        _tag: NotFixedTag,
        #[range]
        port: u16,
    }

    #[allow(dead_code)]
    struct NotFixedTag;

    assert_eq!(Explicit::N, 1);
    assert_eq!(Explicit::KEY_SIZE, 2);

    // In the rule the bare marker is represented as `PhantomData`, so it needs no
    // value even though the key struct field holds a real `NotFixedTag`.
    let _rule = ExplicitRule {
        port: RangeSpec::from(1..=10),
        _tag: PhantomData,
    };
}

#[test]
fn phantom_only_generic_param_is_not_bounded_fixed_size() {
    use core::marker::PhantomData;

    // `Addr` is used by a match field, so the derive bounds it `FixedSize`.
    // `M` is used only by the phantom field, so it must be left unbounded --
    // instantiating with `NotFixed` (which is not `FixedSize`) must compile.
    #[derive(MatchKey)]
    #[allow(dead_code)]
    struct Mixed<Addr, M> {
        #[prefix]
        addr: Addr,
        #[phantom]
        _marker: PhantomData<M>,
    }

    assert_eq!(<Mixed<Ipv4Addr, NotFixed>>::N, 1);
    assert_eq!(<Mixed<Ipv4Addr, NotFixed>>::KEY_SIZE, 4);

    let _rule = MixedRule::<Ipv4Addr, NotFixed> {
        addr: PrefixSpec::new(Ipv4Addr::new(10, 0, 0, 0), 8),
        _marker: PhantomData,
    };
}

#[test]
fn wrapper_field_bounds_the_field_type_not_its_parameter() {
    use core::marker::PhantomData;

    // A wrapper that is `FixedSize` for *every* `T`: the parameter is a
    // compile-time tag only, and the payload has a fixed layout.
    struct Tag<T>(u32, PhantomData<T>);

    impl<T> Clone for Tag<T> {
        fn clone(&self) -> Self {
            *self
        }
    }
    impl<T> Copy for Tag<T> {}
    impl<T> core::fmt::Debug for Tag<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "Tag({})", self.0)
        }
    }
    impl<T> FixedSize for Tag<T> {
        const SIZE: usize = 4;
        fn write_be(&self, out: &mut [u8]) {
            out[..Self::SIZE].copy_from_slice(&self.0.to_be_bytes());
        }
    }

    // The derive must require `Tag<T>: FixedSize` (which holds here), not
    // `T: FixedSize` -- so instantiating with `NotFixed` must compile.
    #[derive(MatchKey)]
    #[allow(dead_code)]
    struct Wrapped<T> {
        #[exact]
        tagged: Tag<T>,
    }

    assert_eq!(<Wrapped<NotFixed>>::N, 1);
    assert_eq!(<Wrapped<NotFixed>>::KEY_SIZE, 4);

    let key = Wrapped::<NotFixed> {
        tagged: Tag(0xDEAD_BEEF, PhantomData),
    };
    let mut buf = [0u8; 4];
    key.as_key_into(&mut buf);
    assert_eq!(buf, 0xDEAD_BEEFu32.to_be_bytes());

    let _rule = WrappedRule::<NotFixed> {
        tagged: ExactSpec::new(Tag(0xDEAD_BEEF, PhantomData)),
    };
}

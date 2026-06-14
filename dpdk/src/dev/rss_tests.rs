// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::*;

fn info(key_size: u8, supports_rss: bool) -> DevInfo<'static> {
    DevInfo {
        index: DevIndex(u16::MAX),
        inner: rte_eth_dev_info {
            min_mtu: 68,
            max_mtu: 9000,
            hash_key_size: key_size,
            flow_type_rss_offloads: u64::from(supports_rss),
            ..Default::default()
        },
        eal: PhantomData,
    }
}

fn config(key: Option<Box<[u8]>>) -> DevConfig {
    DevConfig {
        num_rx_queues: 1,
        num_tx_queues: 1,
        num_hairpin_queues: 0,
        tx_offloads: TxOffloadConfig::none(),
        rx_offloads: RxOffload::NONE,
        mtu: None,
        rss: Some(RssConf { key, hf: 1 }),
    }
}

#[test]
fn rss_key_length_is_checked_before_device_configuration() {
    let check = |expected, actual| {
        let mut config = config(Some(vec![42; actual].into_boxed_slice()));
        if actual == usize::from(expected) {
            let rss = config.prepare_rss(&info(expected, true)).unwrap();
            assert_eq!(rss.rss_key_len, expected);
            assert_eq!(
                rss.rss_key.cast_const(),
                config.rss.as_ref().unwrap().key.as_ref().unwrap().as_ptr()
            );
        } else {
            // Reject the length before trying to configure this invalid port.
            assert!(matches!(
                config.configure(&info(expected, true)),
                Err(DevConfigError::RssKeyLength { actual: got, expected: want })
                    if got == actual && want == expected
            ));
        }
    };
    for expected in [0, 40, 52, 255] {
        for actual in [0, 1, 39, 40, 41, 51, 52, 53, 255, 256, 296, 308, 552, 65535] {
            check(expected, actual);
        }
    }
    bolero::check!()
        .with_type::<(u8, u16)>()
        .for_each(|&(expected, actual)| check(expected, usize::from(actual)));
}

#[test]
fn rss_key_survives_source_drop_and_device_transitions() {
    let source = config(Some(vec![42; 52].into_boxed_slice()));
    let mut applied = source.clone();
    let info = info(52, true);
    let rss = applied.prepare_rss(&info).unwrap();
    assert_ne!(
        rss.rss_key.cast_const(),
        source.rss.as_ref().unwrap().key.as_ref().unwrap().as_ptr()
    );
    drop(source);
    let owner = Ownership::unregistered();
    let dev: Dev = Dev {
        lifecycle: PortLifecycle {
            port: info.index(),
            stage: Stage::Configured,
            config: applied,
            owner: &owner,
            live_rules: AtomicUsize::new(0),
        },
        info,
        queues: Mutex::new(Some(QueueStore::new(0, 0))),
        state: PhantomData,
        _thread: PhantomData,
    };
    // Exercise the ownership moves without calling a driver on this synthetic port.
    let dev = dev.transition::<Started>().transition::<Configured>();
    let failure = DevStartFailure {
        error: ErrorCode::parse_i32(errno::NEG_EAGAIN),
        dev,
    };
    let dev = failure.dev;
    let key = dev.config().rss.as_ref().unwrap().key.as_ref().unwrap();
    assert_eq!(rss.rss_key.cast_const(), key.as_ptr());
    let mut copy = dev.config().clone();
    copy.rss.as_mut().unwrap().key.as_mut().unwrap().fill(99);
    drop(copy);
    // SAFETY: the pointer equals the live device-owned allocation checked above.
    assert_eq!(
        unsafe { core::slice::from_raw_parts(rss.rss_key, 52) },
        &[42; 52]
    );
    // The port is synthetic, so there is no driver to stop or close it on drop.
    let mut dev = dev;
    dev.lifecycle.stage = Stage::Closed;
}

#[test]
fn absent_rss_keys_use_a_null_pointer() {
    let mut config = config(None);
    let rss = config.prepare_rss(&info(40, true)).unwrap();
    assert!(rss.rss_key.is_null());
    assert_eq!(rss.rss_key_len, 0);
    assert_eq!(rss.rss_hf, 1);
    assert!(matches!(
        config.prepare_rss(&info(40, false)),
        Err(DevConfigError::RssUnsupported)
    ));
    config.rss = None;
    let rss = config.prepare_rss(&info(40, false)).unwrap();
    assert!(rss.rss_key.is_null());
    assert_eq!(rss.rss_hf, 0);
}

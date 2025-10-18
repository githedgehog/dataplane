// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Fib module tests

#![cfg(test)]
use concurrency::concurrency_mode;

#[concurrency_mode(std)]
mod tests {
    use crate::fib::fibobjects::FibEntry;
    use crate::fib::fibobjects::FibGroup;
    use crate::fib::fibobjects::PktInstruction;
    use crate::fib::fibtable::FibTableWriter;
    use crate::fib::fibtype::FibKey;
    use crate::fib::fibtype::FibWriter;
    use crate::rib::nexthop::NhopKey;

    use net::ip::NextHeader;
    use net::packet::Packet;
    use net::packet::test_utils::build_test_ipv4_packet_with_transport;
    use net::udp::UdpPort;
    use net::{buffer::TestBuffer, interface::InterfaceIndex};

    use lpm::prefix::{IpAddr, Prefix};

    use rand::Rng;
    use rand::rngs::ThreadRng;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU16;
    use std::thread;
    use std::thread::Builder;
    use std::time::{Duration, Instant};
    use std::{collections::HashMap, collections::HashSet, sync::atomic::Ordering};

    use crate::fib::fibgroupstore::tests::build_fib_entry_egress;
    use crate::fib::fibgroupstore::tests::build_fibgroup;

    /// An object that contains a preset collection of entries and fibgroups.
    /// This is shared by fuzzer and workers. Fuzzer uses it to randomly select fibgroups to update the fib.
    /// Workers use it to check what they read.
    struct RandomRouter {
        entries: HashSet<FibEntry>,
        fibgroups: HashMap<usize, FibGroup>,
    }
    impl RandomRouter {
        fn load() -> Self {
            let mut entries = HashSet::new();
            let e1 = build_fib_entry_egress(1, "10.0.1.1", "eth1");
            let e2 = build_fib_entry_egress(2, "10.0.2.1", "eth2");
            let e3 = build_fib_entry_egress(3, "10.0.3.1", "eth3");
            let e4 = build_fib_entry_egress(4, "10.0.3.4", "eth4");
            let e5 = build_fib_entry_egress(5, "10.0.3.5", "eth5");
            let e6 = build_fib_entry_egress(6, "10.0.3.6", "eth6");
            let e7 = build_fib_entry_egress(7, "10.0.3.7", "eth7");
            let e8 = build_fib_entry_egress(8, "10.0.3.8", "eth8");

            entries.insert(e1.clone());
            entries.insert(e2.clone());
            entries.insert(e3.clone());
            entries.insert(e4.clone());
            entries.insert(e5.clone());
            entries.insert(e6.clone());
            entries.insert(e7.clone());
            entries.insert(e8.clone());

            let mut fibgroups = HashMap::new();
            fibgroups.insert(1, build_fibgroup(&[e1.clone(), e2.clone()]));
            fibgroups.insert(2, build_fibgroup(&[e4.clone()]));
            fibgroups.insert(3, build_fibgroup(&[e7.clone()]));
            fibgroups.insert(4, build_fibgroup(&[e8.clone()]));
            fibgroups.insert(5, build_fibgroup(&[e5.clone()]));
            fibgroups.insert(6, build_fibgroup(&[e5.clone(), e6.clone()]));
            fibgroups.insert(7, build_fibgroup(&[e3.clone()]));
            fibgroups.insert(
                8,
                build_fibgroup(&[e3.clone(), e4.clone(), e5.clone(), e6.clone(), e7.clone()]),
            );

            Self { entries, fibgroups }
        }
        fn random_pick_fibgroup(&self, rng: &mut ThreadRng) -> &FibGroup {
            let chosen = rng.random_range(1..=self.fibgroups.len());
            self.fibgroups.get(&chosen).unwrap()
        }
    }

    fn get_entry_interface_index(entry: &FibEntry) -> InterfaceIndex {
        if let PktInstruction::Egress(egress) = &entry.instructions[0] {
            egress.ifindex.unwrap()
        } else {
            unreachable!()
        }
    }
    fn test_packet() -> Packet<TestBuffer> {
        let mut packet = build_test_ipv4_packet_with_transport(64, Some(NextHeader::UDP)).unwrap();
        let destination = IpAddr::from_str("192.168.1.1").expect("Bad dst ip address");
        packet.set_ip_destination(destination).unwrap();
        packet
    }
    fn mutate_packet(rng: &mut ThreadRng, packet: &mut Packet<TestBuffer>) {
        packet
            .set_udp_destination_port(UdpPort::new_checked(rng.random_range(20..=100)).unwrap())
            .unwrap();
    }

    // Test the concurrency of a SINGLE fib. NUM_WORKERS workers perform LPM lookups on a single FIB for
    // a test packet while another thread fuzzes the route to forward the packet, by removing the route
    // or aggressively changing the fibgroup (and fib entries) used for the prefix of that route.

    #[test]
    fn test_concurrency_fib() {
        const NUM_PACKETS: u64 = 1000_00;
        const NUM_WORKERS: u16 = 4;

        // sync main thread - worker thread(s)
        let done = Arc::new(AtomicU16::new(0));

        // create fib with writer and readers
        let (mut fibw, fibr) = FibWriter::new(FibKey::Id(0));

        // the prefix of the route that will be used to process a packet
        let prefix = Prefix::from("192.168.1.0/24");

        // the next-hop - we keep this throughout
        let nhkey = NhopKey::with_address(&IpAddr::from_str("7.0.0.1").unwrap());

        // spawn a reader thread (worker)
        let rfactory = fibr.factory();
        let worker_done = done.clone();

        // build shared database and randomizer
        let randomrouter = Arc::new(RandomRouter::load());

        /*************************/
        /* worker thread closure */
        /*************************/
        let worker_code = Arc::new(move |randomrouter: Arc<RandomRouter>| {
            let fibreader = rfactory.handle();
            let mut prefix_hits = 0u64; // number of times lpm yielded prefix 192.168.1.0/24
            let mut drop_hits = 0u64; // number of times lpm yielded 0.0.0.0/0 - Drop
            let mut stats: HashMap<InterfaceIndex, u64> = HashMap::new();
            let mut rng = rand::rng();

            // The packet each worker will repeatedly try to forward using the fib.
            // The worker mutates the packet (udp dst port) to alter the hash outcome
            // so that distinct fib entries of the route hit get a chance of being selected.
            let mut packet = test_packet();

            loop {
                if let Some(fib) = fibreader.enter() {
                    mutate_packet(&mut rng, &mut packet);

                    // do LPM
                    let (hit, entry) = fib.lpm_entry_prefix(&packet);
                    if hit != prefix {
                        assert_eq!(hit, Prefix::root_v4()); // fuzzer can remove route
                        drop_hits += 1;
                        continue;
                    }
                    assert!(randomrouter.entries.contains(entry));
                    prefix_hits += 1;

                    // get interface from fib entry. This is to keep some stats to see
                    // if the main thread really had a chance to fuzz the fib once the test ends.
                    let ifindex = get_entry_interface_index(entry);
                    stats
                        .entry(ifindex)
                        .and_modify(|counter| *counter += 1)
                        .or_insert(0);

                    // stop after processing NUM_PACKETS with the target route
                    if prefix_hits >= NUM_PACKETS {
                        println!(" -- Worker --");
                        println!("target hits: {prefix_hits} pkts");
                        println!("drop hits  : {drop_hits} pkts");
                        println!("Stats: {stats:#?}");
                        worker_done.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                }
            }
        });

        /* Spawn workers */
        for n in 1..=NUM_WORKERS {
            let rand_router = randomrouter.clone();
            let value = worker_code.clone();
            let _ = Builder::new()
                .name(format!("WORKER-{n}"))
                .spawn(move || value(rand_router.clone()))
                .unwrap();
        }

        /********************************************************/
        /* main thread: loops fuzzing / deleting a single route */
        /********************************************************/
        let mut updates = 0u64;
        let mut route_adds = 0u64;
        let mut route_replaces = 0u64;
        let mut route_deletions = 0u64;
        let mut rng = rand::rng();
        loop {
            // randomly select a fib-group, register it and add the route to the
            // target prefix. Fuzzer changes the fibgroup on every loop.
            let fibgroup = randomrouter.random_pick_fibgroup(&mut rng);
            fibw.register_fibgroup(&nhkey, fibgroup, true);
            if route_adds == 0 {
                fibw.add_fibroute(prefix, vec![nhkey.clone()], true);
                route_adds += 1;
            }

            // every 10 loops replace route and fibgroup
            if updates % 10 == 0 {
                fibw.register_fibgroup(&nhkey, fibgroup, false);
                fibw.add_fibroute(prefix, vec![nhkey.clone()], false);
                route_replaces += 1;
                fibw.publish();
            }
            if updates % 101 == 0 {
                fibw.del_fibroute(prefix);
                fibw.publish();
                route_deletions += 1;
            }

            // iterations
            updates += 1;

            // stop when all workers are done
            if done.load(Ordering::Relaxed) == NUM_WORKERS {
                println!("All workers finished!");
                break;
            }
        }
        println!(" --- Fib fuzzer stats ---");
        println!("fibgroup updates:{updates}");
        println!("route adds:      {route_adds}");
        println!("route replaces:  {route_replaces}");
        println!("route deletions: {route_deletions}");
    }

    // Test the concurrency of a SINGLE fib within a FIBTABLE. NUM_WORKERS workers perform LPM lookups
    // on a single FIB for a test packet while another thread fuzzes the route to forward the packet, by removing the route
    // or aggressively changing the fibgroup (and fib entries) used for the prefix of that route. The fuzzer in this
    // test also removes the FIB and adds it again. The workers use a thread-local cache to access the FIB.
    #[test]
    fn test_concurrency_fibtable() {
        // number of threads looking up fibtable
        const NUM_WORKERS: u16 = 7;
        const NUM_PACKETS: u64 = 1_000_000;
        const TENTH: u64 = NUM_PACKETS / 10;

        // create fibtable (empty, without any fib)
        let (mut fibtw, fibtr) = FibTableWriter::new();
        let fibtrfactory = fibtr.factory();

        // prefix to be hit by packets
        let prefix = Prefix::from("192.168.1.0/24");

        // shared counter of workers that finished
        let done = Arc::new(AtomicU16::new(0));

        let vrfid = 1;

        /* Spawn workers: each has its own reader for the fibtable */
        for n in 1..=NUM_WORKERS {
            let fibtr = fibtrfactory.handle();
            let worker_done = done.clone();

            Builder::new()
                .name(format!("WORKER-{n}"))
                .spawn(move || {
                    let mut rng = rand::rng();
                    let mut packet = test_packet();
                    let mut prefix_hits: u64 = 0;
                    let mut other_hits: u64 = 0;
                    let mut nofibs: u64 = 0;
                    let mut nofib_enter: u64 = 0;
                    loop {
                        mutate_packet(&mut rng, &mut packet);
                        if let Ok(fib) = fibtr.get_fib_reader(FibKey::Id(vrfid)) {
                            if let Some(fib) = fib.enter() {
                                let (hit, _fibentry) = fib.lpm_entry_prefix(&packet);
                                if hit == prefix {
                                    prefix_hits += 1;
                                    if prefix_hits % TENTH == 0 {
                                        println!("Worker {n} is {} % done", prefix_hits * 100 / NUM_PACKETS);
                                    }

                                    if prefix_hits >= NUM_PACKETS {
                                        println!("=== Worker {n} finished ====");
                                        println!("Stats:");
                                        println!("  {prefix_hits:>8} packets hit {prefix}");
                                        println!("  {other_hits:>8} packets hit other prefix (0.0.0.0/0)");
                                        println!("  {nofibs:>8} packets found no fib");
                                        println!("  {nofib_enter:>8} packets found fib but could not enter");
                                        worker_done.fetch_add(1, Ordering::Relaxed);
                                        break;
                                    }
                                } else {
                                    other_hits += 1;
                                }
                            } else {
                                nofib_enter += 1;
                            }
                        } else {
                            nofibs += 1;
                        }
                    }
                })
                .unwrap();
        }

        /*****************************************************************/
        /* main thread (fuzzer): adds / deletes route / fibgroup and fib */
        /*****************************************************************/
        let nhkey = NhopKey::with_address(&IpAddr::from_str("7.0.0.1").unwrap());
        let mut rng = rand::rng();
        let randomrouter = RandomRouter::load();
        let mut updates = 0u64;

        let mut fibw = Some(fibtw.add_fib(vrfid, None));
        let fibgroup = randomrouter.random_pick_fibgroup(&mut rng);
        if let Some(fibw) = &mut fibw {
            fibw.register_fibgroup(&nhkey, fibgroup, true);
            fibw.add_fibroute(prefix, vec![nhkey.clone()], true);
        }
        let start = Instant::now();
        loop {
            if fibw.is_none() {
                fibw = Some(fibtw.add_fib(vrfid, None));
            }
            if let Some(fibw) = &mut fibw {
                if updates % 100 == 0 {
                    let fibgroup = randomrouter.random_pick_fibgroup(&mut rng);
                    fibw.register_fibgroup(&nhkey, fibgroup, true);
                    fibw.add_fibroute(prefix, vec![nhkey.clone()], true);
                }
                if updates % 150 == 0 {
                    fibw.del_fibroute(prefix);
                    fibw.publish();
                }
            }

            if updates % 50 == 0 && fibw.is_some() {
                fibtw.del_fib(1, None);
                thread::sleep(Duration::from_millis(15));
                if true {
                    // fib gets deleted here
                    let fib = fibw.take();
                    fib.unwrap().destroy();
                }
            }

            // iterations
            updates += 1;

            // stop when all workers are done
            if done.load(Ordering::Relaxed) == NUM_WORKERS {
                println!("All workers finished!");
                break;
            }
        }
        let duration = start.elapsed();
        println!("Test duration: {:?}", duration);
    }

    // Tests fib reader utilities returning guards
    #[test]
    fn test_fib_guards() {
        // create fib
        let (mut fibw, fibr) = FibWriter::new(FibKey::Id(0));

        // add a route
        let prefix = Prefix::from("192.168.1.0/24");
        let nhkey = NhopKey::with_address(&IpAddr::from_str("7.0.0.1").unwrap());
        let e1 = build_fib_entry_egress(1, "10.0.1.1", "eth1");
        let fibgroup1 = build_fibgroup(&[e1.clone()]);
        fibw.register_fibgroup(&nhkey, &fibgroup1, false);
        fibw.add_fibroute(prefix, vec![nhkey.clone()], false);
        fibw.publish();

        // use the fib: do lpm for some destination and get a route
        let destination = IpAddr::from_str("192.168.1.1").expect("Bad dst ip address");
        let route = &*fibr.lpm_route(destination).unwrap();
        assert!(route.has_entries());
        assert_eq!(route.len(), fibgroup1.len());
        assert!(route.iter().any(|g| g == &fibgroup1));

        // use again the fib with a packet
        let packet = test_packet();
        let (matched, entry1) = fibr.lpm_entry_prefix(&packet).unwrap();
        assert_eq!(matched, prefix);
        assert!(fibgroup1.entries().contains(&*entry1));

        // attempt to modify the route by modifying the fibgroup
        let e2 = build_fib_entry_egress(2, "10.0.2.1", "eth2");
        let fibgroup2 = build_fibgroup(&[e2.clone()]);
        fibw.register_fibgroup(&nhkey, &fibgroup2, false);
        fibw.add_fibroute(prefix, vec![nhkey.clone()], false);
        fibw.publish();

        // a second query to the fib yields the updated value. This is counter-intuitive but correct,
        // because of the number of readers we have and the fact that the original fib guard was forgotten.
        let (_, entry2) = fibr.lpm_entry_prefix(&packet).unwrap();
        assert_eq!(&*entry2, &e2);

        // ... but the guard to the entry wasn't.
        assert_eq!(&*entry1, &e1);

        // Additional queries while holding the guards would cause the writer to block.
        // We can't test this here since there's a single thread and it would block forever.
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! How big a gateway configuration's planned ACLs get on mlx5 (slice 1 step 5c-2).
//!
//! `acl_size <gateway.yaml> [<pci>]` compiles the configuration's ACLs as installing does (the ACL
//! filter, the flow filter's destinations, [`Program::compile`]), then reports for each planned ACL
//! and protocol: its rules, the rule planner's plan (levels, entries, registers, worst path) and
//! the NIC budget's verdict; then the mlx5 plan's rules and groups by kind. With a PCI address, it
//! also installs the plan on that port (`dv_flow_en=2`, decapsulating, as the gateway runs) and
//! reports how long that took and what the NIC refused. Installing requires DPDK device
//! privileges.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::Instant;

use acl_filter::AclFilterContext;
use config::ExternalConfig;
use dataplane_nic_offload::acl::AclVerdict;
use dataplane_nic_offload::mlx5::{Group, Plan, RESOURCES, Role, with_installed};
use dataplane_nic_offload::program::{Exclusions, Program};
use dpdk::dev::{DevConfig, RxOffload, TxOffloadConfig};
use dpdk::flow::template::{TemplateAction, TemplateFlows};
use dpdk::mem::{PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dpdk::socket;
use k8s_intf::gateway_agent_crd::{GatewayAgent, GatewayAgentSpec};
use net::vxlan::Vni;
use planner::backend::{Backend, Mlx5};
use planner::rfc;
use planner::rules::Table;
use rate_limit::{IngressRules, PeeringRules, RateLimits};

/// The program installing would compile for the configuration at `path`.
fn program(path: &str) -> Program {
    let yaml = std::fs::read_to_string(path).expect("a readable configuration");
    let spec: GatewayAgentSpec = serde_yaml_ng::from_str(&yaml).expect("a gateway agent spec");
    // As the k8s-less watcher makes it.
    let mut agent = GatewayAgent::new("acl-size", spec);
    agent.metadata.generation = Some(1);
    agent.metadata.namespace = Some("default".to_string());
    let external = ExternalConfig::try_from(&agent).expect("a convertible configuration");
    let overlay = external.overlay.validate().expect("a valid overlay");
    let acls = AclFilterContext::reference(&overlay).expect("ACLs the filter takes");
    let destinations = flow_filter::FlowFilterContext::reference(&overlay).destinations();
    // The rate limits don't change what is planned of ACLs: leave them out.
    Program::compile(
        &acls,
        &RateLimits::<PeeringRules>::empty(),
        &RateLimits::<IngressRules>::empty(),
        &destinations,
        &Exclusions::default(),
    )
}

/// The planner's view of one protocol's table.
fn report_table(name: &str, table: &Table<AclVerdict>) {
    let denies = table
        .rules
        .iter()
        .filter(|r| r.action == AclVerdict::Deny)
        .count();
    let start = Instant::now();
    let planned = rfc::plan_within(table, &Mlx5::at(50e6));
    let took = start.elapsed();
    let Ok((plan, _)) = planned else {
        println!(
            "    {name:5}: {} rule(s), no plan: {planned:?}",
            table.rules.len()
        );
        return;
    };
    let levels: Vec<String> = plan
        .levels
        .iter()
        .map(|l| format!("{} {}+1", l.name, l.entries.len()))
        .collect();
    let fit = Mlx5::at(50e6).assess(&plan);
    println!(
        "    {name:5}: {} rule(s) ({denies} deny), planned in {took:.1?}: {} level(s) [{}], {} register(s), budget {}",
        table.rules.len(),
        plan.levels.len(),
        levels.join(", "),
        plan.registers.len(),
        match &fit {
            Ok(cost) => format!(
                "fits (worst path {}, {} entries, largest level {})",
                cost.worst_path, cost.entries, cost.largest_level
            ),
            Err(unfit) => format!("UNFIT {unfit:?}"),
        }
    );
}

/// The NIC rules of `plan`'s VPCs, by kind of group.
fn report_plan(plan: &Plan) {
    let mut by_kind: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for vpc in plan.vpcs.values() {
        let mut groups: BTreeMap<&str, std::collections::BTreeSet<Group>> = BTreeMap::new();
        for table in &vpc.tables {
            let kind = match table.group {
                Group::AclDispatch(_) => "ACL dispatch",
                Group::Acl(..) => "ACL levels",
                Group::Deny(_) => "per-rule denies",
                Group::Police(_) | Group::Color(_) => "rate limits",
                Group::Ingress(_) | Group::IngressColor(..) => "ingress",
                Group::Exit(_) => "exit",
                _ => "other",
            };
            by_kind.entry(kind).or_default().0 += table.rules.len();
            groups.entry(kind).or_default().insert(table.group);
        }
        for (kind, groups) in groups {
            by_kind.entry(kind).or_default().1 += groups.len();
        }
    }
    let acl_rules: usize = plan
        .vpcs
        .values()
        .flat_map(|v| &v.tables)
        .flat_map(|t| &t.rules)
        .filter(|r| matches!(r.role, Role::Acl(_)))
        .count();
    println!("  mlx5 plan, one bank: {acl_rules} rule(s) of planned ACLs");
    for (kind, (rules, groups)) in by_kind {
        println!("    {kind:16} {rules:7} rule(s) in {groups:4} group(s)");
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: acl_size <gateway.yaml> [<pci>]");
    let pci = args.next();
    let program = program(&path);
    println!(
        "{path}: {} planned ACL(s), {} per-rule deny(s), {} refused",
        program.acls.len(),
        program.denies.len(),
        program.refused.len()
    );
    for acl in &program.acls {
        println!("  ACL of VPC {} ({:?}):", acl.src.as_u32(), acl.peering);
        report_table("udp", &acl.udp);
        report_table("tcp", &acl.tcp);
        report_table("other", &acl.other);
    }
    // Any VTEP: nothing is sent.
    let vteps: BTreeMap<Vni, Ipv4Addr> = program
        .acls
        .iter()
        .flat_map(|a| a.peering.vnis())
        .chain(program.denies.iter().map(|d| d.matches.src_vni))
        .map(|vni| (vni, Ipv4Addr::new(192, 0, 2, 2)))
        .collect();
    let fate = TemplateAction::Queue(RxQueueIndex(0));
    let start = Instant::now();
    let plan = Plan::new(&program, &vteps, &fate, true).expect("a plan");
    println!("  lowered in {:.1?}", start.elapsed());
    report_plan(&plan);
    if let Some(pci) = pci {
        install(&pci, &plan);
    }
}

/// Install `plan` on `pci`, and say how long that took and what the NIC refused.
fn install(pci: &str, plan: &Plan) {
    let eal = dpdk::eal::init([
        "--in-memory".to_string(),
        "--lcores".to_string(),
        dpdk::eal::main_lcore_arg(),
        "--no-huge".to_string(),
        "-m".to_string(),
        "2048".to_string(),
        "-a".to_string(),
        format!("{pci},dv_flow_en=2"),
        "--log-level=pmd.net.mlx5:error".to_string(),
    ]);
    let index = eal
        .dev
        .iter()
        .find(|d| d.name().is_ok_and(|name| name == pci))
        .unwrap()
        .index();
    let mut dev = DevConfig {
        num_rx_queues: 1,
        num_tx_queues: 1,
        num_hairpin_queues: 0,
        tx_offloads: TxOffloadConfig::none(),
        rx_offloads: RxOffload::NONE,
        mtu: None,
        rss: None,
        rx_interrupts: false,
    }
    .apply(eal.claim(index).unwrap())
    .map_err(|e| e.error)
    .unwrap();
    dev.isolate().unwrap();
    // `ACL_SIZE_COUNTERS` overrides the counters reserved (each counted rule takes one).
    let counters = std::env::var("ACL_SIZE_COUNTERS")
        .ok()
        .and_then(|c| c.parse().ok())
        .unwrap_or(RESOURCES.counters);
    dev.configure_templates(&dpdk::flow::template::TemplateConfig {
        counters,
        ..RESOURCES
    })
    .unwrap();
    let pool = eal
        .mem
        .new_pkt_pool(
            PoolConfig::new(
                "probe".to_string(),
                PoolParams {
                    size: 1023,
                    cache_size: 0,
                    ..Default::default()
                },
            )
            .unwrap(),
        )
        .unwrap();
    dev.new_rx_queue(RxQueueConfig {
        queue_index: RxQueueIndex(0),
        num_descriptors: 256,
        socket_preference: socket::Preference::Dev(index),
        offloads: RxOffload::NONE,
        pool,
    })
    .unwrap();
    dev.new_tx_queue(TxQueueConfig {
        queue_index: TxQueueIndex(0),
        num_descriptors: 256,
        socket_preference: socket::Preference::Dev(index),
        config: (),
    })
    .unwrap();
    let dev = dev.start().map_err(|e| e.error).unwrap();
    let flows = TemplateFlows::new(&dev).unwrap();
    let start = Instant::now();
    let refused = with_installed(&flows, plan, |installed| {
        let took = start.elapsed();
        let refused: Vec<(Role, String)> = installed
            .refused()
            .iter()
            .map(|(role, why)| (*role, why.to_string()))
            .collect();
        (took, refused)
    });
    match refused {
        Ok((took, refused)) if refused.is_empty() => {
            println!("  installed on {pci} in {took:.1?}, nothing refused");
        }
        Ok((took, refused)) => println!(
            "  installed on {pci} in {took:.1?}; REFUSED {} rule(s), first {:?}",
            refused.len(),
            refused[0]
        ),
        Err(e) => println!("  install on {pci} FAILED: {e}"),
    }
}

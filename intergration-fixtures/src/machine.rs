// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::loopback::{Loopback, LoopbackSpec};
use bollard::Docker;
use bollard::models::{ContainerCreateBody, HostConfig};
use bollard::query_parameters::{
    CreateContainerOptions, InspectContainerOptions, StartContainerOptions, StopContainerOptions,
};
use derive_builder::Builder;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Builder, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[builder(setter(into))]
pub struct MachineSpec {
    pub(crate) name: String,
    pub(crate) loopback: LoopbackSpec,
}

pub struct TestFixture {
    pub(crate) runtime: Runtime,
    collector: Option<JoinHandle<()>>,
    drop_queue: Option<tokio::sync::mpsc::Receiver<JoinHandle<()>>>,
}

impl Drop for TestFixture {
    fn drop(&mut self) {
        let mut drop_queue = self.drop_queue.take().unwrap();
        let collector = self.collector.take().unwrap();
        self.runtime.block_on(async move {
            collector.await.unwrap();
            while let Some(handle) = drop_queue.recv().await {
                handle.await.unwrap();
            }
        });
    }
}

#[derive(Debug, Clone)]
pub struct TestTaskTracker {
    pub logs: tokio::sync::mpsc::Sender<JoinHandle<()>>,
    pub shutdown_queue: tokio::sync::mpsc::Sender<JoinHandle<()>>,
}

impl TestFixture {
    #[tracing::instrument]
    pub fn new() -> (TestFixture, TestTaskTracker) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (shutdown, rx) = tokio::sync::mpsc::channel(1024);
        let (logs, mut log_rx) = tokio::sync::mpsc::channel::<JoinHandle<()>>(1024);
        let collector = runtime.spawn(async move {
            while let Some(handle) = log_rx.recv().await {
                handle.await.unwrap();
            }
        });
        (
            TestFixture {
                runtime,
                drop_queue: Some(rx),
                collector: Some(collector),
            },
            TestTaskTracker {
                logs,
                shutdown_queue: shutdown,
            },
        )
    }
}

#[derive(Debug)]
pub struct Machine {
    pub(crate) spec: MachineSpec,
    pub(crate) container_id: String,
    loopback: Loopback,
    netns_path: PathBuf,
    pub(crate) tracker: TestTaskTracker,
}

impl Machine {
    pub fn container_id(&self) -> String {
        self.container_id.clone()
    }

    pub async fn new(tracker: TestTaskTracker, spec: MachineSpec) -> Machine {
        let docker = Docker::connect_with_defaults().unwrap();
        let response = docker
            .create_container(
                Some(CreateContainerOptions {
                    name: Some(spec.name.clone()),
                    ..Default::default()
                }),
                ContainerCreateBody {
                    hostname: Some(spec.name.clone()),
                    cmd: Some(vec!["sleep".to_string(), "infinity".to_string()]),
                    image: Some("busybox".to_string()),
                    attach_stdin: Some(false),
                    attach_stdout: Some(false),
                    attach_stderr: Some(false),
                    tty: Some(false),
                    host_config: Some(HostConfig {
                        auto_remove: Some(true),
                        sysctls: Some({
                            let mut map = HashMap::new();
                            map.insert("net.ipv4.ip_forward".to_string(), "1".to_string());
                            map.insert("net.ipv6.conf.all.forwarding".to_string(), "1".to_string());
                            map
                        }),
                        network_mode: Some("none".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        docker
            .start_container(
                response.id.as_str(),
                Some(StartContainerOptions { detach_keys: None }),
            )
            .await
            .unwrap();
        let netns_path_str = docker
            .inspect_container(response.id.as_str(), None::<InspectContainerOptions>)
            .await
            .unwrap()
            .network_settings
            .unwrap()
            .sandbox_key
            .unwrap();
        let mut netns_path = PathBuf::new();
        netns_path.push(&netns_path_str);
        let loopback = Loopback::configure(&netns_path, spec.loopback.clone());
        Machine {
            spec,
            container_id: response.id,
            loopback,
            netns_path,
            tracker,
        }
    }

    fn netns(&self) -> &Path {
        self.netns_path.as_path()
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        let container_id = self.container_id.clone();
        let shutdown_task = tokio::spawn(async move {
            let docker = Docker::connect_with_defaults().unwrap();
            docker
                .stop_container(
                    container_id.as_str(),
                    Some(StopContainerOptions {
                        signal: None,
                        t: Some(0),
                    }),
                )
                .await
                .unwrap();
        });
        self.tracker.shutdown_queue.try_send(shutdown_task).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use crate::loopback::LoopbackSpecBuilder;
    use crate::machine::{Machine, MachineSpecBuilder, TestFixture};
    use crate::nic::{NicConnectionBuilder, NicSpecBuilder};
    use caps::Capability;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use test_utils::fixin::wrap;
    use test_utils::with_caps;

    #[test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN, Capability::CAP_SYS_ADMIN]))]
    fn boxen() {
        let (fixture, shutdown_queue) = TestFixture::new();
        fixture.runtime.block_on(async {
            let mut builder = MachineSpecBuilder::default();
            builder.name("biscuits").loopback({
                let mut builder = LoopbackSpecBuilder::default();
                builder.add_ipv4(Ipv4Addr::new(192, 168, 1, 1), 32);
                builder.build().unwrap()
            });
            let machine_spec = builder.build().unwrap();
            let machine = Machine::new(shutdown_queue, machine_spec).await;
            println!("machine: {machine:?}");
        });
    }

    #[test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN, Capability::CAP_SYS_ADMIN]))]
    fn boxen2() {
        let (fixture, shutdown_queue) = TestFixture::new();
        fixture.runtime.block_on(async move {
            let mut builder = MachineSpecBuilder::default();
            builder.name("potato").loopback({
                let mut builder = LoopbackSpecBuilder::default();
                builder.add_ipv4(Ipv4Addr::new(192, 168, 1, 1), 32);
                builder.build().unwrap()
            });
            let machine_spec = builder.build().unwrap();
            let potato = Machine::new(shutdown_queue.clone(), machine_spec).await;

            let mut builder = MachineSpecBuilder::default();
            builder.name("cheese").loopback({
                let mut builder = LoopbackSpecBuilder::default();
                builder.add_ipv4(Ipv4Addr::new(192, 168, 1, 1), 32);
                builder.add_ipv6(Ipv6Addr::new(0xfeed, 0xc0ff, 0xfe, 0, 0, 0, 0, 0), 92);
                builder.build().unwrap()
            });
            let machine_spec = builder.build().unwrap();
            let cheese = Machine::new(shutdown_queue.clone(), machine_spec).await;
            let x1 = NicSpecBuilder::default()
                .name("x1".try_into().unwrap())
                .mtu(9000)
                .ipv4([(Ipv4Addr::new(192, 168, 1, 1), 24)])
                .ipv6([(Ipv6Addr::new(0xdead, 0xbeef, 0, 0, 0, 0, 0, 1), 96)])
                .netns(potato.netns_path.clone())
                .build()
                .unwrap();
            let y1 = NicSpecBuilder::default()
                .name("y1".try_into().unwrap())
                .mtu(9000)
                .ipv4([(Ipv4Addr::new(192, 168, 1, 2), 24)])
                .ipv6([(Ipv6Addr::new(0xcafe, 0xbabe, 0, 0, 0, 0, 0, 2), 96)])
                .netns(cheese.netns_path.clone())
                .build()
                .unwrap();
            let mut connection_builder = NicConnectionBuilder::new();
            connection_builder.from(x1).to(y1);
            connection_builder.build().unwrap();
        });
    }
}

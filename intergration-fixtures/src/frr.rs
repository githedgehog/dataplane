// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::machine::Machine;
use bollard::Docker;
use bollard::container::LogOutput;
use bollard::models::{
    ContainerCreateBody, HostConfig, Mount, MountBindOptions, MountBindOptionsPropagationEnum,
    MountTypeEnum,
};
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, LogsOptions, RemoveContainerOptions, StartContainerOptions,
    StopContainerOptions,
};
use derive_builder::Builder;
use futures_util::TryStreamExt;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{Level, debug, info, span, warn};

#[derive(Debug, Builder)]
#[builder(build_fn(skip))]
pub struct FrrContainer {
    #[builder(setter(into))]
    name: String,
    machine: Arc<Machine>,
    #[builder(
        default = "ghcr.io/githedgehog/dpdk-sys/frr:dirty-_-pr-daniel-noland-frr-rework".into()
    )]
    #[builder(setter(into))]
    image: String,
    #[builder(setter(into))]
    #[builder(
        default = "/tmp/frr".into()
    )]
    etc_frr: PathBuf,
    #[builder(setter(skip))]
    #[builder(default = "".into())]
    container_id: String,
}

impl Drop for FrrContainer {
    #[tracing::instrument(level = "info")]
    fn drop(&mut self) {
        let container_id = self.container_id.clone();
        let container_name = self.name.clone();
        let machine_name = self.machine.spec.name.clone();
        let machine_id = self.machine.container_id.clone();
        let shutdown_task = tokio::spawn(async move {
            let span = span!(
                Level::INFO,
                "container shutdown",
                container_name,
                container_id,
                machine_name,
                machine_id,
            );
            let _enter = span.enter();
            let docker = Docker::connect_with_defaults().unwrap();
            info!("stoping container");
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
            info!("removing container");
            docker
                .remove_container(
                    container_id.as_str(),
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await
                .unwrap();
        });
        self.machine
            .tracker
            .shutdown_queue
            .try_send(shutdown_task)
            .unwrap();
    }
}

trait ContainerDefault<T> {
    fn container_defaults() -> T;
}

impl ContainerDefault<ContainerCreateBody> for FrrContainer {
    fn container_defaults() -> ContainerCreateBody {
        ContainerCreateBody {
            user: Some("0".into()),
            attach_stdin: Some(true),
            attach_stdout: Some(false),
            attach_stderr: Some(false),
            stdin_once: Some(true),
            image: Some(
                "ghcr.io/githedgehog/dpdk-sys/frr:dirty-_-pr-daniel-noland-frr-rework.rust-stable"
                    .into(),
            ),
            network_disabled: Some(false),
            stop_timeout: Some(0),
            host_config: Some(FrrContainer::container_defaults()),
            ..Default::default()
        }
    }
}

impl ContainerDefault<HostConfig> for FrrContainer {
    fn container_defaults() -> HostConfig {
        HostConfig {
            auto_remove: Some(false),
            readonly_rootfs: Some(true),
            privileged: Some(false),
            cap_drop: Some(vec!["ALL".to_string()]),
            cap_add: Some(vec![
                "CHOWN".to_string(),
                "DAC_OVERRIDE".to_string(),
                "NET_ADMIN".to_string(),
                "NET_BIND_SERVICE".to_string(),
                "NET_RAW".to_string(),
                "SETGID".to_string(),
                "SETUID".to_string(),
                "SYS_ADMIN".to_string(),
                "SYS_RAWIO".to_string(),
            ]),
            tmpfs: Some({
                let mut map = HashMap::new();
                map.insert(
                    "/run/frr".to_string(),
                    "rw,nodev,nosuid,noexec,size=65535k".to_string(),
                );
                map.insert(
                    "/var/tmp".to_string(),
                    "rw,nodev,nosuid,noexec,size=65535k".to_string(),
                );
                map.insert(
                    "/var/run/frr".to_string(),
                    "rw,nodev,nosuid,noexec,size=65535k".to_string(),
                );
                map.insert(
                    "/var/run/frr/hh".to_string(),
                    "rw,nodev,nosuid,noexec,size=65535k".to_string(),
                );
                map
            }),
            sysctls: Some({
                let mut map = HashMap::<String, String>::new();
                map.insert("net.ipv4.ip_forward".to_string(), "1".to_string());
                map.insert("net.ipv6.conf.all.forwarding".to_string(), "1".to_string());
                map
            }),
            ..Default::default()
        }
    }
}

impl ContainerDefault<Mount> for FrrContainer {
    fn container_defaults() -> Mount {
        Mount {
            read_only: Some(true),
            typ: Some(MountTypeEnum::BIND),
            bind_options: Some(FrrContainer::container_defaults()),
            ..Default::default()
        }
    }
}

impl ContainerDefault<MountBindOptions> for FrrContainer {
    fn container_defaults() -> MountBindOptions {
        MountBindOptions {
            propagation: Some(MountBindOptionsPropagationEnum::RPRIVATE),
            non_recursive: Some(true),
            create_mountpoint: Some(true),
            read_only_non_recursive: Some(false),
            read_only_force_recursive: Some(true),
        }
    }
}

impl FrrContainerBuilder {
    pub async fn build(self) -> FrrContainer {
        let mut this = FrrContainer {
            name: self.name.expect("name unset"),
            machine: self.machine.expect("machine unset"),
            image: self.image.expect("image unset"),
            etc_frr: self.etc_frr.expect("etc_frr unset"),
            container_id: "".into(),
        };
        let docker = Docker::connect_with_local_defaults().unwrap();
        let response = docker
            .create_container(
                Some(
                    CreateContainerOptionsBuilder::new().name(this.name.as_str()).build()
                ),
                ContainerCreateBody {
                    image: Some(this.image.clone()),
                    // cmd: Some(vec!["cat".to_string(), "/etc/passwd".to_string()]),
                    host_config: Some(HostConfig {
                        network_mode: None,
                        mounts: Some(vec![Mount {
                            source: Some(this.etc_frr.to_str().unwrap().to_string()),
                            target: Some("/etc/frr".to_string()),
                            ..FrrContainer::container_defaults()
                        }, Mount {
                            source: Some("/home/dnoland/storage/dnoland/git/hedgehog/dpdk-sys/nix/frr-config/config/etc/passwd".to_string()),
                            target: Some("/etc/passwd".to_string()),
                            ..FrrContainer::container_defaults()
                        }, Mount {
                            source: Some("/home/dnoland/storage/dnoland/git/hedgehog/dpdk-sys/nix/frr-config/config/etc/group".to_string()),
                            target: Some("/etc/group".to_string()),
                            ..FrrContainer::container_defaults()
                        }]),
                        ..FrrContainer::container_defaults()
                    }),
                    ..FrrContainer::container_defaults()
                },
            )
            .await
            .unwrap();
        this.container_id = response.id;
        debug!("start container");
        docker
            .start_container(this.container_id.as_str(), None::<StartContainerOptions>)
            .await
            .unwrap();
        let container_id = this.container_id.clone();
        let container_name = this.name.clone();
        let machine = this.machine.clone();
        let logging_task = tokio::spawn(async move {
            let span = span!(
                Level::INFO,
                "container log",
                container_name,
                container_id,
                machine_name = machine.spec.name,
                machine_id = machine.container_id,
            );
            let _enter = span.enter();
            let docker = Docker::connect_with_local_defaults().unwrap();
            let mut logs = docker.logs(
                container_id.as_str(),
                Some(LogsOptions {
                    follow: true,
                    stdout: true,
                    stderr: true,
                    timestamps: true,
                    tail: "all".to_string(),
                    ..Default::default()
                }),
            );
            debug!("start container log");
            while let Ok(Some(output)) = logs.try_next().await {
                match output {
                    LogOutput::StdErr { message } => {
                        warn!(file = "stderr", "{}", String::from_utf8_lossy(&message),);
                    }
                    LogOutput::StdOut { message } => {
                        info!(file = "stdout", "{}", String::from_utf8_lossy(&message));
                    }
                    LogOutput::StdIn { message } => {
                        debug!(file = "stdin", "{}", String::from_utf8_lossy(&message));
                    }
                    LogOutput::Console { message } => {
                        warn!(file = "console", "{}", String::from_utf8_lossy(&message));
                    }
                }
            }
            debug!("end container log");
        });
        this.machine.tracker.logs.try_send(logging_task).unwrap();
        this
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loopback::LoopbackSpecBuilder;
    use crate::machine::{MachineSpecBuilder, TestFixture};
    use caps::Capability::*;
    use opentelemetry::KeyValue;
    use opentelemetry_otlp::{MetricExporter, Protocol, WithExportConfig};
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use test_utils::fixin::wrap;
    use test_utils::with_caps;
    use tracing_test::traced_test;

    #[test]
    #[wrap(with_caps([CAP_NET_ADMIN, CAP_SYS_ADMIN]))]
    fn launch_frr_container() {
        tracing_subscriber::fmt()
            .json()
            .with_max_level(Level::TRACE)
            .init();
        let (fixture, tracker) = TestFixture::new();
        info!("science");
        fixture.runtime.block_on(async {
            info!("science");
            let mut builder = MachineSpecBuilder::default();
            builder.name("machine").loopback({
                let mut builder = LoopbackSpecBuilder::default();
                builder.add_ipv4(Ipv4Addr::new(192, 168, 1, 1), 32);
                builder.build().unwrap()
            });
            let machine_spec = builder.build().unwrap();
            let machine = Arc::new(Machine::new(tracker, machine_spec).await);
            let mut frr_builder = FrrContainerBuilder::default();
            frr_builder
                .name("frr")
                .image("ghcr.io/githedgehog/dpdk-sys/frr:dirty-_-pr-daniel-noland-frr-rework.rust-stable")
                .machine(machine.clone())
                .etc_frr("/home/dnoland/storage/dnoland/git/hedgehog/dpdk-sys/nix/frr-config/config/etc/frr");
            let _frr_container = frr_builder.build().await;
            tokio::time::sleep(Duration::from_secs(3)).await;
        });
    }

    #[test]
    #[wrap(with_caps([CAP_NET_ADMIN, CAP_SYS_ADMIN]))]
    fn science() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let (fixture, tracker) = TestFixture::new();
        fixture.runtime.block_on(async {
            // let mut builder = MachineSpecBuilder::default();
            // builder.name("machine").loopback({
            //     let mut builder = LoopbackSpecBuilder::default();
            //     builder.add_ipv4(Ipv4Addr::new(192, 168, 1, 1), 32);
            //     builder.build().unwrap()
            // });
            // let machine_spec = builder.build().unwrap();
            // let machine = Arc::new(Machine::new(tracker, machine_spec).await);
            // tokio::time::sleep(Duration::from_secs(10)).await;
            let exporter = MetricExporter::builder()
                .with_http()
                .with_protocol(Protocol::HttpBinary)
                .with_endpoint("http://localhost:9090/api/v1/otlp/v1/metrics")
                .build()
                .unwrap();

            // Create a meter provider with the OTLP Metric exporter
            let meter_provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
                .with_periodic_exporter(exporter)
                .build();
            opentelemetry::global::set_meter_provider(meter_provider.clone());

            // Get a meter
            let meter = opentelemetry::global::meter("my_meter");

            // Create a metric
            let counter = meter.u64_counter("my_counter").build();
            counter.add(1, &[KeyValue::new("key", "value")]);
            tokio::time::sleep(Duration::from_secs(5)).await;
            meter_provider.shutdown().unwrap();
        });
        // Shutdown the meter provider. This will trigger an export of all metrics.

        Ok(())
    }

    #[test]
    #[traced_test]
    #[wrap(with_caps([CAP_NET_ADMIN, CAP_SYS_ADMIN]))]
    fn launch_two_frr_container() {
        let (fixture, tracker) = TestFixture::new();
        fixture.runtime.block_on(async {
            let mut builder = MachineSpecBuilder::default();
            builder.name("machine1").loopback({
                let mut builder = LoopbackSpecBuilder::default();
                builder.add_ipv4(Ipv4Addr::new(192, 168, 1, 1), 32);
                builder.build().unwrap()
            });
            let machine_spec = builder.build().unwrap();
            let machine1 = Arc::new(Machine::new(tracker.clone(), machine_spec).await);

            let mut builder2 = MachineSpecBuilder::default();
            builder2.name("machine2").loopback({
                let mut builder = LoopbackSpecBuilder::default();
                builder.add_ipv4(Ipv4Addr::new(192, 168, 2, 1), 32);
                builder.build().unwrap()
            });
            let machine_spec = builder2.build().unwrap();
            let machine2 = Arc::new(Machine::new(tracker.clone(), machine_spec).await);

            let mut frr_builder1 = FrrContainerBuilder::default();
            frr_builder1
                .name("frr1")
                .image("ghcr.io/githedgehog/dpdk-sys/frr:dirty-_-pr-daniel-noland-frr-rework.rust-stable")
                .machine(machine1.clone())
                .etc_frr("/home/dnoland/storage/dnoland/git/hedgehog/dpdk-sys/nix/frr-config/config/etc/frr");
            let _frr_container1 = frr_builder1.build().await;

            let mut frr_builder2 = FrrContainerBuilder::default();
            frr_builder2
                .name("frr2")
                .image("ghcr.io/githedgehog/dpdk-sys/frr:dirty-_-pr-daniel-noland-frr-rework.rust-stable")
                .machine(machine2.clone())
                .etc_frr("/home/dnoland/storage/dnoland/git/hedgehog/dpdk-sys/nix/frr-config/config/etc/frr");
            let _frr_container2 = frr_builder2.build().await;
            tokio::time::sleep(Duration::from_secs(3)).await;
        });
    }
}

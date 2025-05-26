// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(private_bounds)]

mod frr;
mod ip;
mod loopback;
mod machine;
mod nic;

#[cfg(test)]
mod tests {
    use bollard::models::{ContainerCreateBody, HostConfig};
    use bollard::query_parameters::{
        CreateContainerOptions, CreateContainerOptionsBuilder, InspectContainerOptions,
        StartContainerOptions,
    };
    use caps::Capability;
    use futures::TryStreamExt;
    use rtnetlink::packet_route::link::{InfoData, InfoKind, InfoVeth, LinkAttribute};
    use rtnetlink::{LinkMessageBuilder, LinkUnspec, LinkVeth};
    use std::collections::HashMap;
    use std::os::fd::AsRawFd;
    use std::path::Path;
    use test_utils::{fixin::wrap, in_netns, with_caps};

    #[test]
    #[wrap(with_caps([Capability::CAP_SYS_ADMIN, Capability::CAP_NET_ADMIN]))]
    fn launch_sleeping_container() {
        use bollard::Docker;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = runtime.enter();
        let _sandbox_key_handle = runtime.spawn(async {
            let docker = Docker::connect_with_local_defaults().unwrap();
            let response1 = docker
                .create_container(
                    Some(CreateContainerOptions {
                        name: Some("machine1".to_string()),
                        ..Default::default()
                    }),
                    ContainerCreateBody {
                        // entrypoint: Some(vec!["gdbserver", "localhost:1234"]),
                        hostname: Some("frr1".to_string()),
                        domainname: Some("frr1.biscuit".to_string()),
                        cmd: Some(vec!["sleep".to_string(), "infinity".to_string()]),
                        image: Some("busybox".to_string()),
                        attach_stdin: Some(false),
                        attach_stdout: Some(false),
                        attach_stderr: Some(false),
                        tty: Some(false),
                        host_config: Some(HostConfig {
                            auto_remove: Some(true),
                            network_mode: Some("none".to_string()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            docker
                .start_container(response1.id.as_str(), None::<StartContainerOptions>)
                .await
                .unwrap();
            let netns_path = docker
                .inspect_container(response1.id.as_str(), Some(InspectContainerOptions { size: false }))
                .await
                .unwrap()
                .network_settings
                .unwrap()
                .sandbox_key
                .unwrap();
            let netns_path1 = Path::new(&netns_path);
            let netns_file1 = std::fs::File::open(netns_path1).unwrap();
            let netns_fd1 = netns_file1.as_raw_fd();
            let response2 = docker
                .create_container(
                    Some(CreateContainerOptions {
                        name: Some("machine2".to_string()),
                        ..Default::default()
                    }),
                    ContainerCreateBody {
                        // entrypoint: Some(vec!["gdbserver", "localhost:1234"]),
                        hostname: Some("frr2".to_string()),
                        domainname: Some("frr2.biscuit".to_string()),
                        cmd: Some(vec!["sleep".to_string(), "infinity".to_string()]),
                        image: Some("busybox".to_string()),
                        attach_stdin: Some(false),
                        attach_stdout: Some(false),
                        attach_stderr: Some(false),
                        tty: Some(false),
                        host_config: Some(HostConfig {
                            auto_remove: Some(true),
                            network_mode: Some("none".to_string()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            docker
                .start_container(response2.id.as_str(), None::<StartContainerOptions>)
                .await
                .unwrap();
            let netns_path = docker
                .inspect_container(response2.id.as_str(), Some(InspectContainerOptions { size: false }))
                .await
                .unwrap()
                .network_settings
                .unwrap()
                .sandbox_key
                .unwrap();
            let netns_path2 = Path::new(&netns_path);
            let netns_file2 = std::fs::File::open(netns_path2).unwrap();
            let netns_fd2 = netns_file2.as_raw_fd();
            let (connection, handle, _) = rtnetlink::new_connection().unwrap();
            tokio::spawn(connection);
            let message = LinkMessageBuilder::<LinkVeth>::new_with_info_kind(InfoKind::Veth)
                .name("a".to_string())
                .up()
                .mtu(9000)
                .setns_by_fd(netns_fd1)
                .set_info_data(InfoData::Veth(InfoVeth::Peer(
                    LinkMessageBuilder::<LinkVeth>::new_with_info_kind(InfoKind::Veth)
                        .name("a".to_string())
                        .mtu(9000)
                        .setns_by_fd(netns_fd2)
                        .build(),
                )))
                .build();

            handle.link().add(message).execute().await.unwrap();

            in_netns(netns_path1, || async {
                let (connection, handle, _) = rtnetlink::new_connection().unwrap();
                tokio::spawn(connection);
                let mut resp = handle.link().get().execute();
                while let Ok(Some(message)) = resp.try_next().await {
                    println!("message: {message:?}");
                }
            });
            in_netns(netns_path2, || async {
                let (connection, handle, _) = rtnetlink::new_connection().unwrap();
                tokio::spawn(connection);
                let mut resp = handle.link().get().execute();
                while let Ok(Some(message)) = resp.try_next().await {
                    println!("message: {message:?}");
                    for attr in &message.attributes {
                        match attr {
                            LinkAttribute::IfName(name) => {
                                if name != "a" {
                                    continue;
                                }
                                handle.link().set(LinkUnspec::new_with_index(message.header.index).up().build()).execute().await.unwrap();
                            }
                            _ => continue,
                        }
                    }
                }
            });

            let frr1 = CreateContainerOptionsBuilder::new();
            let frr1 = frr1.name("frr1").build();

            let frr1 = docker.create_container(
                Some(frr1),
                ContainerCreateBody {
                    user: Some("root".to_string()),
                    attach_stdin: Some(true),
                    attach_stdout: Some(false),
                    attach_stderr: Some(false),
                    stdin_once: Some(true),
                    image: Some("ghcr.io/githedgehog/dpdk-sys/frr:14".to_string()),
                    network_disabled: Some(false),
                    stop_timeout: Some(0),
                    host_config: Some(HostConfig {
                        network_mode: Some(format!("container:{id}", id = response1.id)),
                        auto_remove: Some(true),
                        readonly_rootfs: Some(true),
                        binds: Some(vec![
                            "/tmp/frr1.conf:/etc/frr/frr.conf:ro".to_string()
                        ]),
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
                            map.insert("/run/frr".to_string(), "rw,nodev,nosuid,noexec,size=65535k".to_string());
                            map.insert("/var/tmp".to_string(), "rw,nodev,nosuid,noexec,size=65535k".to_string());
                            map.insert("/var/run/frr".to_string(), "rw,nodev,nosuid,noexec,size=65535k".to_string());
                            map.insert("/var/run/frr/hh".to_string(), "rw,nodev,nosuid,noexec,size=65535k".to_string());
                            map
                        }),
                        sysctls: Some({
                            let mut map = HashMap::<String, String>::new();
                            map.insert("net.ipv4.ip_forward".to_string(), "1".to_string());
                            map.insert("net.ipv6.conf.all.forwarding".to_string(), "1".to_string());
                            map
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ).await.unwrap();

            docker.start_container(frr1.id.as_str(), None::<StartContainerOptions>).await.unwrap();

            let frr2 = CreateContainerOptionsBuilder::new().name("frr2").build();

            let frr2 = docker.create_container(
                Some(frr2),
                ContainerCreateBody {
                    user: Some("root".to_string()),
                    attach_stdin: Some(false),
                    attach_stdout: Some(false),
                    attach_stderr: Some(false),
                    image: Some("ghcr.io/githedgehog/dpdk-sys/frr:dirty-_-pr-daniel-noland-frr-rework.rust-stable".to_string()),
                    network_disabled: Some(false),
                    stop_timeout: Some(0),
                    host_config: Some(HostConfig {
                        init: Some(true),
                        network_mode: Some(format!("container:{id}", id = response2.id)),
                        auto_remove: Some(false),
                        readonly_rootfs: Some(true),
                        binds: Some(vec![
                            "/tmp/frr2.conf:/etc/frr/frr.conf:ro".to_string()
                        ]),
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
                            map.insert("/run/frr".to_string(), "rw,nodev,nosuid,noexec,size=65535k".to_string());
                            map.insert("/var/tmp".to_string(), "rw,nodev,nosuid,noexec,size=65535k".to_string());
                            map.insert("/var/run/frr".to_string(), "rw,nodev,nosuid,noexec,size=65535k".to_string());
                            map.insert("/var/run/frr/hh".to_string(), "rw,nodev,nosuid,noexec,size=65535k".to_string());
                            map
                        }),
                        sysctls: Some({
                            let mut map = HashMap::<String, String>::new();
                            map.insert("net.ipv4.ip_forward".to_string(), "1".to_string());
                            map.insert("net.ipv6.conf.all.forwarding".to_string(), "1".to_string());
                            map
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ).await.unwrap();

            docker.start_container(frr2.id.as_str(), None::<StartContainerOptions>).await.unwrap();
        });

        runtime.block_on(_sandbox_key_handle).unwrap();
    }
}

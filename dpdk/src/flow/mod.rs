// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Safe wrappers over DPDK `rte_flow` (hardware flow offload).
//!
//! # Status
//!
//! This module is being rebuilt. Its previous contents were a non-functional skeleton: a set of
//! hand-transcribed copies of the `rte_flow` C enums, plus home-rolled duplicates of types that
//! already live in the `net` crate (MAC, EtherType, VNI, IPv4/IPv6/TCP/UDP/VLAN headers,
//! big-endian helpers), with the field-setter logic mostly `todo!()` and not a single
//! `rte_flow_create` / `rte_flow_validate` / `rte_flow_destroy` call. None of it was reachable
//! from anywhere, so it has been removed in favor of a clean rebuild.
//!
//! # Design direction
//!
//! This is a standalone, idiomatic safe wrapper over `rte_flow` -- agnostic to the wider
//! match-action framework, exactly as the acl module began as a clean wrapper over `rte_acl`.
//! The shape below was validated empirically against a BlueField-3 (hardware steering / `hmfs`,
//! in both the NIC and switchdev/transfer domains) before being committed to:
//!
//! - A flow rule is an RAII handle that owns its `rte_flow` and borrows the started device, so it
//!   cannot outlive the device and is destroyed (`rte_flow_destroy`) on drop. The device's `stop`
//!   consumes it by value, which the borrow forces to happen only after every rule is gone.
//! - The `ingress` / `egress` / `transfer` attributes are mutually exclusive in the API, so a
//!   rule's domain is a typestate rather than a runtime field.
//! - Match items and actions are expressed over `net` types -- never re-implemented here.
//! - Errors map `rte_flow_error` into a dedicated error enum; the PMD's message is carried as
//!   context, never matched on as a string.
//! - Universal `rte_flow` API rules are encoded in the type system where practical; whether a
//!   given NIC actually supports a given item or action is a runtime concern (validate/create may
//!   reject), consistent with the observed-behavior offload trust model.
//! - The classic synchronous `rte_flow_create` path is built first (it bridges to HWS on mlx5);
//!   the template/async (HWS-native) engine is left as a future seam, revisited only if rule
//!   insertion-rate work demands it.

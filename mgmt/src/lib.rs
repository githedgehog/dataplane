// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane management module

/* gRPC entry point */
pub mod grpc;

/* Configuration processor */
pub mod processor;

/* Frr drivers */
pub mod frr;

/* VPC manager */
pub mod vpc_manager;

mod tests;

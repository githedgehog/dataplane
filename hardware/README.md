# Hardware topology discovery and representation

The `hardware` crate provides a unified interface for discovering and representing
system hardware topology, including CPU architecture, memory hierarchy, PCI devices,
and operating system devices. It builds a hierarchical tree structure representing
the relationships between different hardware components.

## Overview

This crate is designed to provide detailed information about system hardware topology
that is useful for:

- **Performance optimization**: Understanding cache hierarchy and NUMA topology
- **Device management**: Enumerating and identifying PCI devices and OS devices
- **Resource allocation**: Making informed decisions about CPU affinity and memory
  allocation
- **System monitoring**: Gathering hardware configuration information

## Architecture

The crate represents hardware topology as a tree of [`Node`]s, where each node has:

- A unique identifier
- A type and optional subtype
- Optional attributes specific to the hardware component
- Zero or more child nodes

Node types include:

- **NUMA nodes**: Non-Uniform Memory Access regions
- **Caches**: L1, L2, L3 cache levels
- **PCI devices**: Graphics cards, network adapters, etc.
- **Bridges**: PCI bridges connecting different buses
- **Groups**: Logical groupings of hardware components
- **OS devices**: Block devices, network interfaces, etc.

## Features

- `scan`: Enables hardware topology scanning using the `hwlocality` crate.
  This allows runtime discovery of the system's hardware configuration.
- `serde`: Adds serialization support for all types using serde.
- `bolero`: Enables fuzzing support for testing.

# Operating system device representation

This module provides types for representing devices as seen by the operating
system, including storage devices, network interfaces, GPUs, and other
hardware exposed through the OS.

## Device Types

The module supports various OS device types:

- **Storage**: Block devices, disks, SSDs
- **GPU**: Graphics processing units
- **Network**: Network interfaces
- **OpenFabrics**: High-performance fabric devices (InfiniBand, etc.)
- **DMA**: Direct Memory Access engines
- **CoProcessor**: Specialized compute accelerators
- **Memory**: Memory-like devices (e.g., persistent memory)

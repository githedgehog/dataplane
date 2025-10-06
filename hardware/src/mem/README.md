# Memory Subsystem

Models hardware memory topology for performance-critical packet processing.

## Components

### NUMA

Represents Non-Uniform Memory Access nodes where memory access time depends on
processor location.

### Cache Attributes

Models CPU cache hierarchy (L1/L2/L3).

- **Types**: Unified, Data, and Instruction caches
- **Properties**: Size and line size
- Helps avoid false sharing and optimize data layouts

### Page Types

Represents memory page sizes (e.g., 4KB, 2MB, 1GB).

- Enables huge page utilization
- Reduces TLB pressure for large memory pools

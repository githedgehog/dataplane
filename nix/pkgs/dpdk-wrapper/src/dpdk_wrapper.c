// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#include "dpdk_wrapper.h"

int rte_errno_get() { return rte_errno; }

// The `_w` wrappers for DPDK's `static inline` functions used to be hand-written
// here. They are generated now: bindgen's `wrap_static_fns` emits the same
// wrappers from the headers this file includes, and `dpdk-sys/build.rs` compiles
// them. Hand-maintaining them meant they silently drifted behind the headers.

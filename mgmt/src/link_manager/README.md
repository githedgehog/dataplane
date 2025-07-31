# Design notes

## Pipeline threads

Pipeline threads are responsible for processing packets.

Network function logic like routing, NAT, and firewall MUST run on pipeline threads.

* Pipeline threads should typically run on isolated cores.
* Pipeline threads SHOULD NOT run an async runtime.
  Instead, they SHOULD use a library like [`kanal`](https://github.com/fereidani/kanal) to
  tx/rx messages with an async thread (see [trap-thread]) to trap packets to the kernel.
* Pipeline threads SHOULD NOT have any linux capabilities.
* Pipeline threads MUST run in the `link` network namespace OR in a private network namespace with no active network interfaces.


## I/O threads

I/O threads are responsible for writing packets to and receiving packets from network devices.

* These threads MUST run in the `link` network namespace.
* These threads SHOULD exist in a 1:1 mapping with pipeline threads.
* These threads SHOULD be pinned to the SMT sibling of the core the pipeline thread is
  running on.
* I/O threads MAY also run some processing tasks (e.g., parsing) as polling the queue as
  quickly as possible is unlikely to be efficient.
* These threads MUST send and receive `Vec`s of packet buffers to the pipeline threads via a
  sync queue.
* These threads MAY run with higher privileges than pipeline threads.
  Specifically, they MAY need `CAP_NET_RAW` and possibly `CAP_SYS_RAWIO`.
* These threads SHOULD run with only the privileges needed to tx/rx packets to the NIC
  queue(s).

## Trap thread

The trap thread is responsible for receiving packets from and writing packets to the proxy tap devices in the `vpc` network namespace.

* The trap thread MAY run in the `vpc` network namespace.
* The trap-thread MUST be a single thread that holds the rx side of an MPSC queue.
* The tx side(s) of the MPSC queue(s) MUST be held by the pipeline and/or I/O threads.
* The trap-thread SHOULD run with only the privileges required to tx/rx packets to/from the
  tap devices in the `vpc` network namespace.  Specifically, the trap-thread SHOULD not run with `CAP_SYS_ADMIN`.

## vpc-manager thread

The primary job of the `vpc-manager` thread is to configure the `vpc` network namespace as required by the control plane services running there (e.g., FRR).

* The vpc-manager thread SHOULD be a single thread.
* The vpc-manager thread MUST run with the `CAP_NET_ADMIN` capability.
* The vpc-manager thread SHOULD NOT run with the `CAP_SYS_ADMIN` capability.
* The vpc-manager thread MUST run an async runtime.

## Notes

We need to manage network namespaces to make this design work.

Note that the way we must configure a thread in DPDK requires some extra work over and above creating a system thread (mostly to be able to use and free DPDK allocated memory).
However, we want to be able to support the `AF_PACKET` driver in addition to a DPDK-based driver.
In the case of the `AF_PACKET` based driver we won't have DPDK at all, but we will still have the same basic threading structure.
Thus, thread management MUST be done via trait or something that facilitates dependency injection.





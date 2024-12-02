# Traffic workers

This basically comes down to launching (and correctly pinning) rte worker threads.

The major design issue is that we need to be mindful of data exchange patterns between traffic workers (if any) and especially of data exchange between other threads which may need to access kernel functionality.

Generally we would chase all other processes, kthreads, and rcu operations off of rte worker cores in a DPDK application.
The side effect of this is that if you need kernel operations on the same threads they will be either very inefficient or blocking.
Thus we need to move data between the threads, which can have deleterious performance effects.
Mitigating this will require planning.

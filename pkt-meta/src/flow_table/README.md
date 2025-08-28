# Flow Table

The current implementation of flow table uses `dash_map` and per-thread priority queue's (for timeouts) along with `Arc` and `Weak` to get a reasonable flow table with timeouts.
However, it leaves a lot of room for optimizations.

## Flow Table Implementation

The main `DashMap` holds `Weak` references to all the flow entries so that the memory gets automatically deallocated when the entry times out.  

The priority queue's hold `Arc` references to the flow entries to keep them alive when they are not in any packet meta data.
When the entry times-out and is removed from the priority queue and the last packet referencing that flow is dropped, the memory for the entry is freed.

Note that in the current implementation, a flow is not removed from the flow table until the last Arc to the flow_info is dropped or the flow entry is replaced.  This can be changed if needed, or even have it be an option on the flow as to whether timeout removes the flow or not.

## Optimizations

In the current implementation, there has to be periodic or on-timeout reaping the Weak reference in the hash table.  
This is better done by having a version of `DashMap` that can reap the dead `Weak` reference as it walks the table on lookups, instead of waiting for key collisions.
The hope, for now, is that the entries in the hash table array will contain a small pointer and not take up too much extra memory.
Those dead `Weak` pointers will prevent shrinking of the hash table though, if the implementation supports that.

Second, the `priority_queue` crate uses a `HashMap` inside the queue in order to allow fast removal and re-insertion.  
However, this wastes space and requires extra hashes.  
The better way to do this is to have a custom priority queue integrated with the custom weak-reaping hash map so that the same hash table can be used for both operations.
This improves cache locality, reduces memory utlization, and avoids multiple hash table lookups in many cases.

However, in the interest of time to completion for the code, this module currently uses existing data structures instead of full custom implementations of everything.
However, the interface should be able to hide a change from the current to the optimized implementation.

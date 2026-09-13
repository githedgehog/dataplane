# Profile data for PGO and BOLT

`instrumentation=pgo-use` reads `dataplane.profdata` from this directory, and `just bolt` reads
`dataplane.fdata`. Both are build inputs, so changing one correctly rebuilds what depends on it.

The files are not checked in -- they are megabytes of machine-specific counters with a short shelf
life, and a stale profile is worse than none because `-Cprofile-use` will happily consume it and
optimise for a workload you no longer run.

## PGO

```
just profile=release instrument=pgo push-container dataplane   # instrumented
# deploy it, set DATAPLANE_DEV_PROFILE_DUMP=dataplane in the pod, then:
#   kill -USR1 1          (init forwards to the dataplane and does NOT stop it)
#   copy /var/run/dataplane/dataplane.profraw into .pgo/
just pgo-merge                                                 # -> .pgo/dataplane.profdata
just profile=release instrument=pgo-use build dataplane        # optimised
```

**Collect at 1-2 workers, never 16.** LLVM's counters are process-global, so every worker doing
read-modify-write on the same cache lines contends. Measured on env-5 at 64 B / 128 streams:
1 worker 1.73 -> 0.33 Mpps (a tolerable 5x), but 16 workers 14.56 -> 0.03. Throughput *falls*
from 1 worker to 16, which overhead alone cannot do. PGO only needs relative block frequencies,
and one worker gives those.

## BOLT

```
just profile=release instrument=bolt build dataplane           # adds --emit-relocs
perf record -j any,u -o .pgo/perf.data -- <the binary under load>
just bolt-fdata <binary> .pgo/perf.data                        # -> .pgo/dataplane.fdata
just bolt <binary> [output]                                    # -> <binary>.bolt
```

`instrument=bolt` keeps the debug sections that a normal build strips: `--emit-relocs` also emits
`.rela.debug_*`, so removing `.debug_loclists` would leave a relocation pointing at a section that
is gone and objcopy stops with "symbol `.debug_loclists' required but not present".

`bolt` and `pgo-use` compose -- a PGO build is a perfectly good BOLT input.

**Branch records matter and the bench cannot give them.** The env-5 gateway is a KVM guest without
`amd_lbr_v2` or `ibs`, though the bare-metal host has both, so `perf record -j` fails there and
`just bolt-fdata` falls back to `-nl`, where BOLT infers edge counts from IP samples alone. Until
that passthrough exists, record on a machine with LBR.

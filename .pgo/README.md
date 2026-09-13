# Profile data for PGO and BOLT

`instrumentation=pgo-use` reads `dataplane.profdata` from this directory, and BOLT reads
`dataplane.fdata`. Both are build inputs, so changing one correctly rebuilds what depends on it.

The files are not checked in -- they are megabytes of machine-specific counters with a short shelf
life, and a stale profile is worse than none because `-Cprofile-use` will happily consume it and
optimise for a workload you no longer run. Produce them with `just pgo-fetch` and `just pgo-merge`.

The full loop is in `development/` and summarised by `just --list | grep -E 'pgo|bolt'`.

// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// Stands in for duvet's report viewer, which the git tree does not carry.
//
// The real file is a react bundle built by `npm run build` under `duvet/www`, and it renders the
// JSON that `report/html.rs` has already written into the page above it. Keeping the bundle would
// mean a node toolchain and a second lockfile in this build to reproduce a file that changes
// nothing about what duvet measures: `--json`, the snapshot, and lcov are written by their own
// code and never read this.
document.getElementById("root").innerHTML =
  "<p>This duvet was built without the bundled report viewer. The full report is embedded " +
  "above as JSON, under <code>&lt;script id=result&gt;</code>.</p>";

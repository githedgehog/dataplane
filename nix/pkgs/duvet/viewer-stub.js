// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// Required by duvet's include_str! when building without the untracked React bundle.
// This intentionally disables only the HTML viewer; machine-readable reports remain available.
document.getElementById("root").innerHTML =
  "<p>This duvet was built without the bundled report viewer. The full report is embedded " +
  "above as JSON, under <code>&lt;script id=result&gt;</code>.</p>";

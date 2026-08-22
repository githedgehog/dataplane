#!/usr/bin/env -S deno run --allow-read
// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/**
 * Turn an iai-callgrind JSON run into a markdown report.
 *
 * Reads the newline-delimited JSON that `cargo bench -- --output-format=json` writes to stdout,
 * and prints markdown: a headline suitable for a sticky pull request comment, a table of the
 * metrics that moved, and -- only when something moved sharply enough to be worth looking at -- a
 * chart.
 *
 * The comparison comes from iai-callgrind itself rather than from anything stored here. Run the
 * base commit with `--save-baseline=<name>` and the head commit with `--baseline=<name>`, and each
 * record already carries both values and the delta. That is what keeps this honest across CI
 * runners: callgrind counts instructions rather than measuring time, so two runs on the same
 * runner are comparable no matter which runner it was, and there is nothing to persist between
 * jobs.
 *
 * Usage: bench-report.ts <run.jsonl> [--threshold=5] [--headline-only]
 */

/** A metric value, which iai reports tagged by type. */
type Metric = { Int: number } | { Float: number };

/**
 * Either one measurement, or a new and old pair when run against a baseline.
 *
 * `Both` carries a two-element array; `Left` and `Right` carry the metric directly rather than a
 * one-element array, so they are not simply the degenerate case of `Both`.
 */
type Metrics =
  | { Both: [Metric, Metric] }
  | { Left: Metric }
  | { Right: Metric };

interface Record_ {
  id: string | null;
  function_name: string;
  module_path: string;
  profiles: Array<{
    tool: string;
    summaries: {
      total: {
        summary: Record<string, Record<string, {
          diffs?: { diff_pct?: string };
          metrics: Metrics;
        }>>;
      };
    };
  }>;
}

/** The metrics worth putting in front of a human, per tool. */
const HEADLINE: Record<string, string[]> = {
  Callgrind: ["Ir", "EstimatedCycles"],
  Cachegrind: ["Ir", "EstimatedCycles"],
  DHAT: ["TotalBytes", "TotalBlocks"],
  Memcheck: ["Errors"],
  Massif: ["PeakBytes"],
};

function value(m: Metric): number {
  return "Int" in m ? m.Int : m.Float;
}

interface Row {
  bench: string;
  tool: string;
  metric: string;
  now: number;
  before: number | null;
  pct: number | null;
}

function rows(records: Record_[]): Row[] {
  const out: Row[] = [];
  for (const rec of records) {
    const bench = rec.id ? `${rec.function_name} ${rec.id}` : rec.function_name;
    for (const profile of rec.profiles ?? []) {
      // Keyed by the tool's own spelling, which does not always match `tool`: the DHAT profile
      // reports `tool: "DHAT"` and keys its summary `"Dhat"`. There is exactly one key either
      // way, so take it rather than guessing at the capitalisation.
      const summaries = profile.summaries?.total?.summary ?? {};
      const summary = summaries[profile.tool] ?? Object.values(summaries)[0];
      if (!summary) continue;
      for (const metric of HEADLINE[profile.tool] ?? []) {
        const entry = summary[metric];
        if (!entry) continue;
        const m = entry.metrics;
        const now = "Both" in m ? value(m.Both[0]) : "Left" in m ? value(m.Left) : value(m.Right);
        const before = "Both" in m ? value(m.Both[1]) : null;
        const pct = before === null || before === 0 ? null : ((now - before) / before) * 100;
        out.push({ bench, tool: profile.tool, metric, now, before, pct });
      }
    }
  }
  return out;
}

const fmt = (n: number) => n.toLocaleString("en-US");
const pct = (p: number | null) => (p === null ? "—" : `${p >= 0 ? "+" : ""}${p.toFixed(2)}%`);

/** A fixed-width bar, so the table reads at a glance without needing a chart to render. */
function bar(p: number | null, worst: number): string {
  if (p === null || worst === 0 || Math.abs(p) < 0.005) return "";
  const width = Math.min(10, Math.round((Math.abs(p) / worst) * 10));
  return (p >= 0 ? "▰" : "▱").repeat(Math.max(1, width));
}

function table(rs: Row[]): string {
  const worst = Math.max(0, ...rs.map((r) => Math.abs(r.pct ?? 0)));
  const head = "| benchmark | tool | metric | before | after | change | |\n|---|---|---|---:|---:|---:|---|";
  const body = rs.map((r) =>
    `| ${r.bench} | ${r.tool} | ${r.metric} | ${r.before === null ? "—" : fmt(r.before)} | ${fmt(r.now)} | ${pct(r.pct)} | ${bar(r.pct, worst)} |`
  );
  return [head, ...body].join("\n");
}

/**
 * A bar chart of the changes, emitted only when something moved sharply.
 *
 * `xychart-beta` is, as the name says, beta; if a renderer does not know it the block degrades to
 * a code fence rather than breaking the page. The table above it is the load-bearing part.
 */
function chart(rs: Row[]): string {
  const shown = rs.filter((r) => r.tool === "Callgrind" && r.metric === "Ir" && r.pct !== null);
  if (shown.length === 0) return "";
  const labels = shown.map((r) => `"${r.bench.replace(/"/g, "")}"`).join(", ");
  const values = shown.map((r) => (r.pct ?? 0).toFixed(2)).join(", ");
  const span = Math.max(5, ...shown.map((r) => Math.abs(r.pct ?? 0))) * 1.2;
  return [
    "```mermaid",
    "xychart-beta",
    '    title "Instructions retired, change vs baseline (%)"',
    `    x-axis [${labels}]`,
    `    y-axis "change (%)" ${(-span).toFixed(0)} --> ${span.toFixed(0)}`,
    `    bar [${values}]`,
    "```",
  ].join("\n");
}

function main() {
  const args = Deno.args.filter((a) => !a.startsWith("--"));
  const flags = Deno.args.filter((a) => a.startsWith("--"));
  const threshold = Number(
    flags.find((f) => f.startsWith("--threshold="))?.split("=")[1] ?? "5",
  );
  const headlineOnly = flags.includes("--headline-only");

  if (args.length !== 1) {
    console.error("usage: bench-report.ts <run.jsonl> [--threshold=N] [--headline-only]");
    Deno.exit(2);
  }

  const records: Record_[] = Deno.readTextFileSync(args[0])
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line));

  const rs = rows(records);
  const compared = rs.filter((r) => r.pct !== null);
  const worst = compared.reduce(
    (acc: Row | null, r) => (acc === null || Math.abs(r.pct!) > Math.abs(acc.pct!) ? r : acc),
    null,
  );
  const stark = worst !== null && Math.abs(worst.pct!) >= threshold;

  // The headline is what a sticky comment shows without being unfolded.
  if (compared.length === 0) {
    console.log("**Benchmarks**: no baseline to compare against; recorded a new one.");
  } else if (!stark) {
    console.log(
      `**Benchmarks**: no change beyond ${threshold}% (largest: ${worst!.bench} ${worst!.metric} ${pct(worst!.pct)}).`,
    );
  } else {
    const dir = worst!.pct! > 0 ? "more" : "less";
    console.log(
      `**Benchmarks**: ${worst!.bench} does ${pct(worst!.pct)} ${dir} work (${worst!.metric}).`,
    );
  }
  if (headlineOnly) return;

  console.log("");
  console.log(table(rs));
  if (stark) {
    console.log("");
    console.log(chart(rs));
  }
  console.log("");
  console.log(
    "> Instruction counts from callgrind, not timings: repeatable across runners, and blind to " +
      "anything that changes data layout rather than instruction count. See " +
      "`development/code/benchmarking.md`.",
  );
}

main();

#!/usr/bin/env -S deno run --allow-read --allow-run --allow-write
// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// Keep dependency-free: module imports may require network access in Nix and CI sandboxes.

const REPO = new URL("..", import.meta.url).pathname.replace(/\/$/, "");

interface Report {
  specifications: Record<string, { requirements: number[] }>;
  annotations: {
    target_path: string;
    target_section: string;
    level?: string;
  }[];
  statuses: Record<string, Record<string, number | number[]>>;
}

interface Recorded {
  index: string;
  spec: string;
  section: string;
  outcome: string;
  detail?: string;
  implementations: string[];
  tests: string[];
  caught: number;
  missed: string[];
  unreached: string[];
  tolerated: string[];
  accepted: { mutant: string; reason: string }[];
  unviable: number;
  timeout: number;
}

interface Stats {
  total: number;
  complete: number;
  citations: number;
  tests: number;
  exceptions: number;
  todos: number;
}

const EMPTY = (): Stats => ({
  total: 0,
  complete: 0,
  citations: 0,
  tests: 0,
  exceptions: 0,
  todos: 0,
});

// Keep aligned with duvet/www result.js; this mirrors upstream completeness semantics.
function record(stats: Stats, status: Record<string, number | number[]>) {
  const spec = status.spec;
  const complete = (spec === status.citation && spec === status.test) ||
    spec === status.implication;
  stats.total += 1;
  if (!status.incomplete && (complete || spec === status.exception)) {
    stats.complete += 1;
  }
  if (status.citation) stats.citations += 1;
  if (status.test) stats.tests += 1;
  if (status.exception) stats.exceptions += 1;
  if (status.todo) stats.todos += 1;
}

const BANDS = [
  { from: 0.75, cell: "🟩" },
  { from: 0.5, cell: "🟨" },
  { from: 0.25, cell: "🟧" },
  { from: 0, cell: "🟥" },
];

function bar(part: number, whole: number): string {
  const ratio = whole ? part / whole : 0;
  const filled = part && whole ? Math.max(1, Math.round(10 * ratio)) : 0;
  const { cell } = BANDS.find((band) => ratio >= band.from) ?? BANDS[3];
  const percent = whole ? (100 * ratio).toFixed(1) : "0.0";
  return `${cell.repeat(filled)}${"⬜".repeat(10 - filled)} ${percent}%`;
}

function specName(id: string): string {
  const rfc = /rfc(\d+)$/.exec(id);
  return rfc ? `RFC ${rfc[1]}` : id.replace(/^https?:\/\//, "");
}

const sectionName = (id: string) =>
  id.replace(/^section-/, "").replace(/^appendix-/, "");

const VERDICT: Record<string, string> = {
  held: "✅ held",
  decorative: "❌ decorative",
  uncovered: "❌ uncovered",
  stale: "❌ stale",
  failing: "❌ failing",
  error: "⚠️ error",
  "no-mutants": "⚠️ no mutants",
  unsupported: "⚠️ unsupported",
};

async function run(cmd: string, args: string[]): Promise<number> {
  const { code } = await new Deno.Command(cmd, {
    args,
    cwd: REPO,
    stdout: "piped",
    stderr: "piped",
  }).output();
  return code;
}

function parseArgs(argv: string[]) {
  const args = { json: "/tmp/duvet-summary.json", results: "", help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    const value = () => {
      const next = argv[++i];
      if (next === undefined) throw new Error(`${flag} needs a value`);
      return next;
    };
    switch (flag) {
      case "--json":
        args.json = value();
        break;
      case "--results":
        args.results = value();
        break;
      case "--help":
        args.help = true;
        break;
      default:
        throw new Error(`unknown argument ${flag}`);
    }
  }
  return args;
}

async function main(): Promise<number> {
  const args = parseArgs(Deno.args);
  if (args.help) {
    console.log("usage: duvet-summary.ts [--results <path>] [--json <path>]");
    console.log(
      "  --results takes what `spec-interlock.ts --results` wrote; without it the",
    );
    console.log("  interlock table says the run has not happened rather than");
    console.log("  reporting citations nobody has checked as though they held");
    return 0;
  }

  // Always regenerate: a cached report can describe a different tree.
  if (await run("duvet", ["report", "--json", args.json])) {
    console.error("error: duvet report failed; nothing to summarise");
    return 1;
  }
  const report: Report = JSON.parse(await Deno.readTextFile(args.json));

  const lines: string[] = [];
  const out = (line = "") => lines.push(line);

  const total = EMPTY();
  const rows: string[] = [];
  for (const [id, spec] of Object.entries(report.specifications)) {
    const stats = EMPTY();
    for (const requirement of spec.requirements) {
      const status = report.statuses[String(requirement)];
      if (status) record(stats, status);
    }
    if (!stats.total) continue;
    for (const key of Object.keys(stats) as (keyof Stats)[]) {
      total[key] += stats[key];
    }
    rows.push(
      `| [${
        specName(id)
      }](${id}) | ${stats.total} | ${stats.complete} | ${stats.citations} | ${stats.tests} | ${stats.todos} | ${stats.exceptions} | ${
        bar(stats.complete, stats.total)
      } |`,
    );
  }

  // Duvet succeeds with zero inputs; an empty report is not full compliance.
  if (!total.total) {
    console.error(
      "error: duvet matched no requirement in this tree; there is nothing to summarise",
    );
    return 1;
  }

  out("## Specification compliance");
  out();
  out(
    "| Specification | Requirements | Complete | Cited | Tested | TODO | Exceptions | Coverage |",
  );
  out("| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |");
  rows.forEach(out);
  out(
    `| **all** | **${total.total}** | **${total.complete}** | **${total.citations}** | **${total.tests}** | **${total.todos}** | **${total.exceptions}** | ${
      bar(total.complete, total.total)
    } |`,
  );
  out();

  out("## Citation interlock");
  out();
  if (!args.results) {
    out(
      "The interlock has not run for this summary, so no citation here is known to be more than a comment. Run `just spec-interlock --results <path>` and pass it with `--results`.",
    );
    console.log(lines.join("\n"));
    return 0;
  }

  const recorded: Recorded[] = JSON.parse(
    await Deno.readTextFile(args.results),
  ).requirements ?? [];
  const rank = (
    r: Recorded,
  ) => (r.outcome === "held" ? 2 : r.outcome === "decorative" ? 0 : 1);
  recorded.sort((a, b) => rank(a) - rank(b) || a.index.localeCompare(b.index));

  const held = recorded.filter((r) => r.outcome === "held").length;
  out(
    `${held} of ${recorded.length} requirements carrying both citations hold them: the cited tests notice a change to the cited code.`,
  );
  out();
  out("| Requirement | Implementation | Tests | Verdict |");
  out("| --- | --- | --- | --- |");
  for (const r of recorded) {
    const where = `[${specName(r.spec)} §${
      sectionName(r.section)
    }](${r.spec}#${r.section})<br>\`--only ${r.index}\``;
    const code = r.implementations.map((i) => `\`${i}\``).join("<br>");
    const tests = r.tests.map((t) => `\`${t}\``).join("<br>");
    out(
      `| ${where} | ${code} | ${tests} | ${VERDICT[r.outcome] ?? r.outcome} |`,
    );
  }
  out();

  for (const r of recorded) {
    const notes = [...r.missed, ...r.accepted.map((a) => a.mutant)];
    if (r.outcome === "held" && !r.accepted.length) continue;
    if (!notes.length && !r.detail) continue;
    out(
      `<details><summary>${specName(r.spec)} §${
        sectionName(r.section)
      } (requirement ${r.index}) -- ${
        VERDICT[r.outcome] ?? r.outcome
      }</summary>`,
    );
    // Markdown inside <details> requires blank lines around every block.
    out();
    if (r.detail) {
      out(`${r.detail}`);
      out();
    }
    const list = (title: string, items: string[]) => {
      if (!items.length) return;
      out(`${title}`);
      out();
      for (const item of items) out(`- \`${item}\``);
      out();
    };
    list(
      "Survivors the tests never reach -- give them a different input:",
      r.unreached,
    );
    list(
      "Survivors the tests run straight through -- give them a different assertion:",
      r.tolerated,
    );
    if (r.accepted.length) {
      out("Accepted, with the reason recorded in `scripts/spec-interlock.ts`:");
      out();
      for (const a of r.accepted) out(`- \`${a.mutant}\` -- ${a.reason}`);
      out();
    }
    out("</details>");
    out();
  }

  console.log(lines.join("\n"));
  return 0;
}

if (import.meta.main) Deno.exit(await main());

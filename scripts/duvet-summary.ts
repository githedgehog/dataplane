#!/usr/bin/env -S deno run --allow-read --allow-run --allow-write
// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/**
 * Render the compliance picture as markdown, for a GitHub job summary.
 *
 * duvet writes an HTML report whose viewer is a react bundle it embeds with `include_str!`. That
 * bundle is a node build product, absent from the git tree we build from, and it renders data the
 * same file already carries in plain JSON -- so we do not build it (see nix/pkgs/duvet). This is
 * what replaces it: the same numbers, in a form that pastes into a job summary and reads in a
 * terminal.
 *
 * It also shows something the HTML report cannot. duvet can say a requirement carries a citation
 * and a test; only `scripts/spec-interlock.ts` can say the test notices the code the citation
 * names. Given `--results`, the verdict lands next to the requirement it judges.
 */

// No imports, for the reason spec-interlock.ts gives: a tool wanted in a sandbox with no network
// should not fetch a module to join two paths.

const REPO = new URL("..", import.meta.url).pathname.replace(/\/$/, "");

/** duvet's report, in the shape `duvet report --json` writes it. */
interface Report {
  specifications: Record<string, { requirements: number[] }>;
  annotations: {
    target_path: string;
    target_section: string;
    level?: string;
  }[];
  /** Keyed by annotation index. Each field is the count of specification text it covers. */
  statuses: Record<string, Record<string, number | number[]>>;
}

/** One requirement's interlock verdict, as `spec-interlock.ts --results` records it. */
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

/**
 * Whether a requirement is answered, by duvet's own definition.
 *
 * Taken from the viewer's `result.js` rather than invented here, so that this report and the one
 * upstream renders cannot drift apart: the fields are counts of specification text, and a
 * requirement is complete when the cited and tested text covers all of it, or when an implication
 * does. An exception covers it too, but it is a decision to skip rather than a claim to have
 * implemented, which is why it is counted separately.
 */
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

/**
 * The colour a coverage figure is reported in.
 *
 * Emoji rather than styled text: GitHub-flavoured markdown strips `style` and `<font>`, so a
 * coloured block is the only colour that survives a job summary, a README and a terminal alike.
 * The percentage is always printed beside it, because hue alone is not something every reader
 * can act on.
 */
const BANDS = [
  { from: 0.75, cell: "🟩" },
  { from: 0.5, cell: "🟨" },
  { from: 0.25, cell: "🟧" },
  { from: 0, cell: "🟥" },
];

/** A ten-cell bar, because a column of percentages does not sort itself by eye. */
function bar(part: number, whole: number): string {
  const ratio = whole ? part / whole : 0;
  // Any progress at all keeps a cell. Rounding 4.3% down to an empty bar reads as "none", and
  // the difference between none and a start is most of what this column is for.
  const filled = part && whole ? Math.max(1, Math.round(10 * ratio)) : 0;
  const { cell } = BANDS.find((band) => ratio >= band.from) ?? BANDS[3];
  const percent = whole ? (100 * ratio).toFixed(1) : "0.0";
  return `${cell.repeat(filled)}${"⬜".repeat(10 - filled)} ${percent}%`;
}

/** `https://www.rfc-editor.org/rfc/rfc4884` -> `RFC 4884`, and anything else unchanged. */
function specName(id: string): string {
  const rfc = /rfc(\d+)$/.exec(id);
  return rfc ? `RFC ${rfc[1]}` : id.replace(/^https?:\/\//, "");
}

/** `section-4.6` -> `4.6`, which is how anybody reading an RFC refers to it. */
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

  // Regenerated rather than read from wherever a previous run left it, for the reason the
  // interlock regenerates it: a stale report describes a tree that is no longer here.
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

  // A tree with no vendored specifications is not a tree that complies with all of them.
  // `duvet report` succeeds over zero inputs, so without this the summary renders an empty table
  // and says nothing is wrong -- which is what `just duvet-check` guards against upstream of here.
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
    // Said rather than left blank. A missing interlock run and an interlock run that found
    // nothing wrong look identical in a table of citations, and only one of them is good news.
    out(
      "The interlock has not run for this summary, so no citation here is known to be more than a comment. Run `just spec-interlock --results <path>` and pass it with `--results`.",
    );
    console.log(lines.join("\n"));
    return 0;
  }

  const recorded: Recorded[] = JSON.parse(
    await Deno.readTextFile(args.results),
  ).requirements ?? [];
  // Failures first: a summary is read from the top, and the rows that need somebody are the ones
  // worth the first screen.
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
    // The number is what `--only` takes, so a row that needs work also says how to re-run it.
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

  // The detail goes in a fold: a job summary is a headline, and the mutants that survived are for
  // whoever the headline sends looking.
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
    // A blank line after the tag, and after every block inside it: markdown nested in HTML only
    // renders as markdown when it is separated from the tag.
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

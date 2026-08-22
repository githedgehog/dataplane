#!/usr/bin/env -S deno run --allow-read --allow-run --allow-write
// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// Keep dependency-free: module imports may require network access in Nix and CI sandboxes.

const join = (...parts: string[]) => parts.join("/").replaceAll(/\/+/g, "/");
const REPO = new URL("..", import.meta.url).pathname.replace(/\/$/, "");

const IMPLEMENTATION = "CITATION";
const TEST = "TEST";

const CITATION_LINE = /^\s*\/\/[=#]/;
const ATTRIBUTE_LINE = /^\s*#\[/;
const FN_LINE = /\bfn\s+([A-Za-z_][A-Za-z0-9_]*)/;
const MUTANT_LINE = /^([^:]+):(\d+):(\d+): /;

// Accepted mutants are exemptions: bind each one to a requirement and preserve its justification.
interface Accepted {
  requirement: string;
  mutant: string;
  reason: string;
}

const ACCEPTED: Accepted[] = [
  {
    requirement: "https://www.rfc-editor.org/rfc/rfc4787#section-4.1",
    mutant:
      "nat/src/masquerade/apalloc/alloc.rs: replace match guard e.is_exhaustion() with true in IpAllocator<I>::allocate",
    reason:
      "Equivalent under the allocator's invariants. `reuse_allocated_ip` skips `NoFreePort` " +
      "and loops, so the only error it can return from a well-formed pool is `NoFreeIp`, " +
      "which is exhaustion; the non-exhaustion arm is defensive depth against an internal " +
      "inconsistency. The whole 210-test nat suite passes with the guard forced to `true`. " +
      "The guard is kept because a future allocator that can fail for a non-exhaustion reason " +
      "must not draw a second public address for a host that already holds one.",
  },
  ...[
    "https://www.rfc-editor.org/rfc/rfc4787#section-4.2.1",
    "https://www.rfc-editor.org/rfc/rfc5382#section-8",
  ].map((requirement) => ({
    requirement,
    mutant:
      "nat/src/masquerade/apalloc/port_alloc.rs: replace < with <= in Bitmap256::allocate_port_from_bitmap",
    reason:
      "Equivalent on the second half, and unreachable rather than untested. `allocate_port` " +
      "only enters the bitmap when `!is_full()`, and `bitmap_full()` is both halves at " +
      "`u128::MAX`. Reaching the second-half branch means the first half is already full, so a " +
      "block that is not full has a zero in the second half and `trailing_ones() < 128` always " +
      "holds; `ones == 128`, the only value the two operators disagree on, cannot occur. The " +
      "whole 210-test nat suite passes with `<=` applied. Note the same mutant on the *first* " +
      "half is caught, and correctly: a block with the first half full and the second free is " +
      "ordinary, so `ones == 128` is reachable there and `1u128 << 128` overflows.",
  })),
  {
    requirement: "https://www.rfc-editor.org/rfc/rfc5508#section-4.3",
    mutant:
      "nat/src/icmp_handler/nf.rs: replace embeds_icmp_query -> bool with true",
    reason:
      "Equivalent with respect to REQ-6, and only with respect to REQ-6. The requirement is " +
      "one-sided -- it forbids deleting a session whose embedded payload is a Query, and asks " +
      "nothing of any other payload -- so a NAT that deleted nothing would conform. A predicate " +
      "forced to `true` is exactly that NAT. What it loses is the invalidation optimization, " +
      "which is ours rather than the RFC's, and which the crate does test: " +
      "`an_icmp_error_about_a_tcp_flow_still_tears_it_down` fails with the mutant applied by " +
      "hand, the rest of the 213-test nat suite passes. Deliberately not cited as a REQ-6 test, " +
      "because it checks the behaviour the requirement declines to constrain.",
  },
];

function stableName(mutant: string): string {
  const match = MUTANT_LINE.exec(mutant);
  if (!match) return mutant;
  return `${match[1]}: ${mutant.slice(match[0].length)}`;
}

interface Region {
  path: string;
  start: number;
  end: number;
}

const showRegion = (r: Region) => `${r.path}:${r.start}-${r.end - 1}`;

interface Triple {
  index: string;
  spec: string;
  section: string;
  implementations: Region[];
  tests: string[];
  testSites: Region[];
}

interface Annotation {
  source: string;
  target_path: string;
  target_section: string;
  line: number;
  type?: string;
}

interface Status {
  citation?: number;
  test?: number;
  related?: number[];
}

interface Report {
  annotations: Annotation[];
  statuses: Record<string, Status>;
}

async function run(
  cmd: string,
  args: string[],
  env: Record<string, string> = {},
): Promise<{ code: number; stdout: string; stderr: string }> {
  const output = await new Deno.Command(cmd, {
    args,
    cwd: REPO,
    env,
    stdout: "piped",
    stderr: "piped",
  }).output();
  const decode = (b: Uint8Array) => new TextDecoder().decode(b);
  return {
    code: output.code,
    stdout: decode(output.stdout),
    stderr: decode(output.stderr),
  };
}

async function lineCounts(
  pkg: string,
  tests: string[],
  paths: string[],
  outDir: string,
  sharedTarget: string,
): Promise<Map<string, number> | null> {
  const env = {
    LLVM_COV: join(REPO, "devroot", "bin", "llvm-cov"),
    LLVM_PROFDATA: join(REPO, "devroot", "bin", "llvm-profdata"),
    CARGO_TARGET_DIR: sharedTarget,
  };
  await Deno.mkdir(outDir, { recursive: true });

  const step = async (args: string[]) => {
    const { code, stderr } = await run("cargo", args, env);
    if (code !== 0) {
      console.log(`    warning: coverage step \`${args.join(" ")}\` failed`);
      const tail = stderr.trim().split("\n").slice(-3).join("\n        ");
      if (tail) console.log(`        ${tail}`);
    }
    return code === 0;
  };

  const jsonPath = join(outDir, "coverage.json");
  const ok =
    await step(["llvm-cov", "clean", "--workspace", "--profraw-only"]) &&
    await step([
      "llvm-cov",
      "--no-report",
      "--branch",
      "nextest",
      "-p",
      pkg,
      "-E",
      testFilterset(tests),
    ]) &&
    await step(["llvm-cov", "report", "--json", "--output-path", jsonPath]);
  if (!ok) return null;

  const counts = new Map<string, number>();
  let report;
  try {
    report = JSON.parse(await Deno.readTextFile(jsonPath));
  } catch (e) {
    console.log(`    warning: coverage report unreadable: ${e}`);
    return null;
  }
  for (const file of report.data?.[0]?.files ?? []) {
    const match = paths.find((p) => file.filename.endsWith(p));
    if (!match) continue;
    for (const [line, _col, count, hasCount] of file.segments ?? []) {
      if (!hasCount) continue;
      const key = `${match}:${line}`;
      counts.set(key, Math.max(counts.get(key) ?? 0, count));
    }
  }
  return counts;
}

// Always regenerate: a cached report can check citations from a different tree.
async function duvetReport(jsonPath: string): Promise<Report> {
  const { code } = await run("duvet", ["report", "--json", jsonPath]);
  if (code !== 0) throw new Error("duvet report failed");
  return JSON.parse(await Deno.readTextFile(jsonPath));
}

function skipCitationBlock(lines: string[], start: number): number {
  let i = start;
  while (i < lines.length) {
    const line = lines[i];
    const stripped = line.trim();
    if (
      stripped === "" || CITATION_LINE.test(line) ||
      stripped.startsWith("//") || ATTRIBUTE_LINE.test(line)
    ) {
      i += 1;
      continue;
    }
    break;
  }
  return i;
}

function itemExtent(lines: string[], start: number): number {
  let depth = 0;
  let opened = false;
  let i = start;
  while (i < lines.length) {
    // This is not a Rust parser: braces inside strings or character literals skew the range.
    const code = lines[i].split("//")[0];
    const opens = (code.match(/\{/g) ?? []).length;
    depth += opens - (code.match(/\}/g) ?? []).length;
    if (opens > 0) opened = true;
    i += 1;
    if (opened && depth <= 0) return i;
    if (!opened && code.trimEnd().endsWith(";")) return i;
  }
  return i;
}

async function readLines(path: string): Promise<string[]> {
  return (await Deno.readTextFile(path)).split("\n");
}

async function implementationRegion(
  source: string,
  line: number,
): Promise<Region> {
  const lines = await readLines(join(REPO, source));
  const start = skipCitationBlock(lines, line - 1);
  return { path: source, start: start + 1, end: itemExtent(lines, start) + 1 };
}

async function testName(
  source: string,
  line: number,
): Promise<[string, Region]> {
  const lines = await readLines(join(REPO, source));
  const start = skipCitationBlock(lines, line - 1);
  for (let i = start; i < Math.min(start + 5, lines.length); i += 1) {
    const match = FN_LINE.exec(lines[i]);
    if (match) {
      return [match[1], {
        path: source,
        start: i + 1,
        end: itemExtent(lines, i) + 1,
      }];
    }
  }
  throw new Error(
    `${source}:${line}: a type=test citation does not precede a function`,
  );
}

async function collect(report: Report): Promise<Triple[]> {
  const triples: Triple[] = [];
  for (const [index, status] of Object.entries(report.statuses)) {
    if (status.citation === undefined || status.test === undefined) continue;
    let triple: Triple | undefined;
    for (const j of status.related ?? []) {
      const annotation = report.annotations[j];
      triple ??= {
        index,
        spec: annotation.target_path,
        section: annotation.target_section,
        implementations: [],
        tests: [],
        testSites: [],
      };
      const kind = annotation.type ?? IMPLEMENTATION;
      if (kind === IMPLEMENTATION) {
        triple.implementations.push(
          await implementationRegion(annotation.source, annotation.line),
        );
      } else if (kind === TEST) {
        const [name, site] = await testName(annotation.source, annotation.line);
        triple.tests.push(name);
        triple.testSites.push(site);
      }
    }
    if (triple && triple.implementations.length && triple.tests.length) {
      triples.push(triple);
    }
  }
  return triples;
}

async function packageOf(path: string): Promise<string> {
  const manifest = join(REPO, path.split("/")[0], "Cargo.toml");
  for (const line of (await Deno.readTextFile(manifest)).split("\n")) {
    if (line.startsWith("name")) {
      return line.split("=")[1].trim().replaceAll('"', "");
    }
  }
  throw new Error(`${manifest}: no package name`);
}

// cargo-mutants does not apply regex filters to StructField mutants. This only reduces build cost;
// selectRegions is the authoritative scope check.
function mutantFilter(regions: Region[]): string {
  const byFile = new Map<string, Set<number>>();
  for (const region of regions) {
    const lines = byFile.get(region.path) ?? new Set<number>();
    for (let n = region.start; n < region.end; n += 1) lines.add(n);
    byFile.set(region.path, lines);
  }
  const parts = [...byFile.entries()].sort().map(([path, lines]) => {
    const escaped = path.replaceAll(".", "\\.");
    return `${escaped}:(${[...lines].sort((a, b) => a - b).join("|")}):`;
  });
  return `^(?:${parts.join("|")})`;
}

function selectRegions(mutants: string[], regions: Region[]): string[] {
  return mutants.filter((mutant) => {
    const match = MUTANT_LINE.exec(mutant);
    if (!match) return false;
    const [, path, line] = match;
    return regions.some((r) =>
      r.path === path && r.start <= Number(line) && Number(line) < r.end
    );
  });
}

// Bare nextest names are substring filters and can let an uncited test kill a mutant.
// Anchor function names to module boundaries and the end of the test name.
function testFilterset(tests: string[]): string {
  return tests.map((name) => `test(/(^|::)${name}$/)`).join(" + ");
}

interface Suite {
  testcases?: Record<string, { "filter-match"?: { status?: string } }>;
}

// nextest list exits 0 for zero matches; inspect every selected name to detect stale citations.
async function missingTests(
  pkg: string,
  tests: string[],
): Promise<string[] | null> {
  const { code, stdout } = await run("cargo", [
    "nextest",
    "list",
    "-p",
    pkg,
    "-E",
    testFilterset(tests),
    "--message-format",
    "json",
  ]);
  if (code !== 0) return null;
  let suites: Record<string, Suite>;
  try {
    suites = JSON.parse(stdout)["rust-suites"] ?? {};
  } catch {
    return null;
  }
  const selected: string[] = [];
  for (const suite of Object.values(suites)) {
    for (const [name, testcase] of Object.entries(suite.testcases ?? {})) {
      if (testcase["filter-match"]?.status === "matches") selected.push(name);
    }
  }
  return tests.filter((name) =>
    !selected.some((full) => full === name || full.endsWith(`::${name}`))
  );
}

const TERMINAL = new Set([
  "CaughtMutant",
  "MissedMutant",
  "Timeout",
  "Unviable",
]);

// cargo-mutants exit codes 0, 2, and 3 all represent completed measurements.
const COMPLETED = new Set([0, 2, 3]);

interface Outcome {
  scenario: unknown;
  summary: string;
}

// Result buckets survive failed or interrupted runs. Require a passing baseline and a terminal
// outcome for every generated mutant before treating them as evidence.
async function auditMutants(
  outDir: string,
  code: number,
  tests: string[],
): Promise<Result | null> {
  const readJson = async (name: string) => {
    try {
      return JSON.parse(
        await Deno.readTextFile(join(outDir, "mutants.out", name)),
      );
    } catch {
      return null;
    }
  };
  const outcomes = await readJson("outcomes.json");
  const generated = await readJson("mutants.json");
  if (!outcomes || !Array.isArray(generated)) {
    return {
      outcome: "error",
      detail:
        `cargo mutants exited ${code} without writing a readable mutants.out; nothing was measured`,
    };
  }
  const all: Outcome[] = outcomes.outcomes ?? [];
  const baseline = all.find((o) => o.scenario === "Baseline");
  if (!baseline) {
    return {
      outcome: "error",
      detail:
        `cargo mutants exited ${code} without recording a baseline; nothing was measured`,
    };
  }
  if (baseline.summary !== "Success") {
    return {
      outcome: "failing",
      detail: `${
        tests.join(", ")
      } do not pass against unmutated code (baseline ${baseline.summary}); no mutant says anything until they do`,
    };
  }
  const tested = all.filter((o) => o.scenario !== "Baseline");
  if (tested.length !== generated.length) {
    return {
      outcome: "error",
      detail:
        `cargo mutants exited ${code} having tested ${tested.length} of the ${generated.length} mutants it generated; the buckets are a partial run`,
    };
  }
  const unclassified = tested.filter((o) => !TERMINAL.has(o.summary));
  if (unclassified.length) {
    return {
      outcome: "error",
      detail: `cargo mutants left ${unclassified.length} mutants in ${
        [...new Set(unclassified.map((o) => o.summary))].join(", ")
      }, which is not a result this tool knows how to read`,
    };
  }
  if (!COMPLETED.has(code)) {
    return {
      outcome: "error",
      detail:
        `cargo mutants exited ${code}, which does not mean a completed run; the buckets are not evidence`,
    };
  }
  return null;
}

interface Result {
  outcome:
    | "held"
    | "decorative"
    | "uncovered"
    | "stale"
    | "unsupported"
    | "no-mutants"
    | "failing"
    | "error";
  detail?: string;
  caught?: string[];
  missed?: string[];
  accepted?: Accepted[];
  unreached?: string[];
  tolerated?: string[];
  unviable?: string[];
  timeout?: string[];
}

async function runTriple(
  triple: Triple,
  output: string,
  jobs: number,
  used: Set<Accepted>,
): Promise<Result> {
  const pkg = await packageOf(triple.implementations[0].path);
  const testPackages = new Set(
    await Promise.all(triple.testSites.map((s) => packageOf(s.path))),
  );
  if (testPackages.size !== 1 || !testPackages.has(pkg)) {
    return {
      outcome: "unsupported",
      detail: `implementation in ${pkg}, tests in ${
        [...testPackages].join(", ")
      }`,
    };
  }
  const missing = await missingTests(pkg, triple.tests);
  if (missing === null) {
    return {
      outcome: "error",
      detail:
        `cargo nextest list failed for ${pkg}; the citation was not checked`,
    };
  }
  if (missing.length) {
    return {
      outcome: "stale",
      detail: `${pkg} has no test named ${missing.join(", ")}`,
    };
  }

  const outDir = join(output, `requirement-${triple.index}`);
  const files = [...new Set(triple.implementations.map((r) => r.path))].sort();

  const counts = await lineCounts(
    pkg,
    triple.tests,
    files,
    outDir,
    join(output, "cov-target"),
  );
  const regionLines = triple.implementations.flatMap((r) =>
    Array.from(
      { length: r.end - r.start },
      (_, i) => `${r.path}:${r.start + i}`,
    )
  );
  const executable = regionLines.filter((key) => counts?.has(key));
  const executed = executable.filter((key) => (counts?.get(key) ?? 0) > 0);
  if (counts && executable.length && !executed.length) {
    return {
      outcome: "uncovered",
      detail: `${triple.tests.join(", ")} never executes ${
        triple.implementations.map(showRegion).join(", ")
      }; the citation cannot be testing this requirement`,
    };
  }
  const mutation = await run("cargo", [
    "mutants",
    "--package",
    pkg,
    "--test-tool",
    "nextest",
    ...files.flatMap((path) => ["--file", path]),
    "--re",
    mutantFilter(triple.implementations),
    "--output",
    outDir,
    "--jobs",
    String(jobs),
    "--no-times",
    "--",
    "-E",
    testFilterset(triple.tests),
  ]);
  const failure = await auditMutants(outDir, mutation.code, triple.tests);
  if (failure) return failure;

  const read = async (name: string): Promise<string[]> => {
    const path = join(outDir, "mutants.out", `${name}.txt`);
    let text: string;
    try {
      text = await Deno.readTextFile(path);
    } catch {
      return [];
    }
    return selectRegions(
      text.split("\n").filter((l) => l.trim() !== ""),
      triple.implementations,
    );
  };

  const [caught, survived, unviable, timeout] = await Promise.all(
    ["caught", "missed", "unviable", "timeout"].map(read),
  );

  const accepted: Accepted[] = [];
  const missed = survived.filter((mutant) => {
    const entry = ACCEPTED.find((a) =>
      a.requirement === `${triple.spec}#${triple.section}` &&
      a.mutant === stableName(mutant)
    );
    if (entry) {
      accepted.push(entry);
      used.add(entry);
      return false;
    }
    return true;
  });
  // Unviable- or timeout-only regions provide no evidence; accepted survivors do.
  if (!caught.length && !missed.length && !accepted.length) {
    const why = unviable.length || timeout.length
      ? `${unviable.length} unviable and ${timeout.length} timed out, so none could be tested`
      : "generated no mutants";
    return {
      outcome: "no-mutants",
      detail: `the cited region ${
        triple.implementations.map(showRegion).join(", ")
      } ${why}; the citation cannot be checked this way`,
      unviable,
      timeout,
    };
  }
  // Without coverage, leave survivors unclassified rather than guessing reachability.
  const reached = (mutant: string) => {
    const match = MUTANT_LINE.exec(mutant);
    return match ? (counts!.get(`${match[1]}:${match[2]}`) ?? 0) > 0 : false;
  };
  return {
    outcome: missed.length ? "decorative" : "held",
    caught,
    missed,
    accepted,
    unreached: counts ? missed.filter((m) => !reached(m)) : [],
    tolerated: counts ? missed.filter(reached) : [],
    unviable,
    timeout,
  };
}

interface Recorded {
  index: string;
  spec: string;
  section: string;
  outcome: Result["outcome"];
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

function parseArgs(argv: string[]) {
  const args = {
    list: false,
    help: false,
    only: [] as string[],
    jobs: 4,
    output: join(REPO, "target", "spec-interlock"),
    json: "/tmp/duvet-interlock.json",
    results: "",
  };
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    const value = () => {
      const next = argv[++i];
      if (next === undefined) throw new Error(`${flag} needs a value`);
      return next;
    };
    switch (flag) {
      case "--list":
        args.list = true;
        break;
      case "--help":
        args.help = true;
        break;
      case "--only":
        args.only.push(value());
        break;
      case "--jobs":
        args.jobs = Number(value());
        break;
      case "--output":
        args.output = value();
        break;
      case "--json":
        args.json = value();
        break;
      case "--results":
        args.results = value();
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
    console.log(
      "usage: spec-interlock.ts [--list] [--only <requirement>]... [--jobs N]",
    );
    console.log(
      "  [--results <path>] records the verdicts as JSON for scripts/duvet-summary.ts",
    );
    console.log(
      "  results and the instrumented build are kept under target/spec-interlock; the build is",
    );
    console.log(
      "  the expensive part of a run and every requirement in a package reuses it",
    );
    return 0;
  }

  const report = await duvetReport(args.json);
  let triples = await collect(report);
  if (args.only.length) {
    triples = triples.filter((t) => args.only.includes(t.index));
    // Reject typos rather than turning a targeted check into a clean no-op.
    const unmatched = args.only.filter((id) =>
      !triples.some((t) => t.index === id)
    );
    if (unmatched.length) {
      console.error(
        `error: no requirement carrying both citations is numbered ${
          unmatched.join(", ")
        }; \`--list\` prints the numbers`,
      );
      return 1;
    }
  }

  if (args.list) {
    for (const triple of triples) {
      console.log(
        `${triple.spec}#${triple.section}  (requirement ${triple.index})`,
      );
      for (const region of triple.implementations) {
        console.log(`    implementation  ${showRegion(region)}`);
      }
      triple.tests.forEach((name, i) => {
        console.log(
          `    test            ${name}  [${showRegion(triple.testSites[i])}]`,
        );
      });
      console.log();
    }
    console.log(
      `${triples.length} requirements carry both an implementation and a test`,
    );
    return 0;
  }

  // Duvet can succeed with no inputs; never report an empty interlock as success.
  if (!triples.length) {
    console.error(
      "error: no requirement carries both an implementation and a test citation; there is nothing to check",
    );
    return 1;
  }

  await Deno.mkdir(args.output, { recursive: true });
  const used = new Set<Accepted>();
  const recorded: Recorded[] = [];
  let failures = 0;
  for (const triple of triples) {
    console.log(
      `==> ${triple.spec}#${triple.section} (requirement ${triple.index})`,
    );
    const result = await runTriple(
      triple,
      args.output,
      Number(args.jobs),
      used,
    );
    if (result.outcome === "held") {
      console.log(
        `    held: ${result.caught!.length} of ${
          result.caught!.length + result.accepted!.length
        } mutants in the cited region caught by ${triple.tests.join(", ")}${
          result.accepted!.length
            ? `, ${result.accepted!.length} accepted below`
            : ""
        }`,
      );
    } else if (result.outcome === "decorative") {
      failures += 1;
      console.log(
        `    DECORATIVE: ${result.missed!.length} mutants survive ${
          triple.tests.join(", ")
        }`,
      );
      if (result.unreached?.length) {
        console.log(
          `      unreached (${result.unreached.length}) -- the test never runs these lines, so`,
        );
        console.log(
          `      closing them means changing what it feeds, not what it asserts:`,
        );
        for (const mutant of result.unreached) console.log(`        ${mutant}`);
      }
      if (result.tolerated?.length) {
        console.log(
          `      tolerated (${result.tolerated.length}) -- the test runs these lines and passes`,
        );
        console.log(
          `      anyway, so either an assertion is missing or the mutant is equivalent:`,
        );
        for (const mutant of result.tolerated) console.log(`        ${mutant}`);
      }
      if (!result.unreached?.length && !result.tolerated?.length) {
        console.log(`      (unclassified -- coverage was not collected)`);
        for (const mutant of result.missed!) console.log(`        ${mutant}`);
      }
    } else {
      failures += 1;
      console.log(`    ${result.outcome.toUpperCase()}: ${result.detail}`);
    }
    const skipped = (result.unviable?.length ?? 0) +
      (result.timeout?.length ?? 0);
    if (skipped && result.outcome !== "no-mutants") {
      console.log(
        `    (${skipped} unviable or timed out, not counted either way)`,
      );
    }
    recorded.push({
      index: triple.index,
      spec: triple.spec,
      section: triple.section,
      outcome: result.outcome,
      detail: result.detail,
      implementations: triple.implementations.map(showRegion),
      tests: triple.tests,
      caught: result.caught?.length ?? 0,
      missed: result.missed ?? [],
      unreached: result.unreached ?? [],
      tolerated: result.tolerated ?? [],
      accepted: (result.accepted ?? []).map(({ mutant, reason }) => ({
        mutant,
        reason,
      })),
      unviable: result.unviable?.length ?? 0,
      timeout: result.timeout?.length ?? 0,
    });
    // Keep exemptions visible in normal output.
    for (const entry of result.accepted ?? []) {
      console.log(`    accepted: ${entry.mutant}`);
      console.log(`        ${entry.reason}`);
    }
  }

  // Fail stale exemptions so they cannot silently match a future mutant.
  const stale = ACCEPTED.filter((entry) => !used.has(entry));
  const checkedAll = !args.only.length;
  if (stale.length && checkedAll) {
    failures += stale.length;
    console.log();
    for (const entry of stale) {
      console.log(`STALE ACCEPT: no surviving mutant matches`);
      console.log(`    requirement ${entry.requirement}`);
      console.log(`    mutant      ${entry.mutant}`);
    }
  }

  if (args.results) {
    await Deno.writeTextFile(
      args.results,
      `${JSON.stringify({ requirements: recorded }, null, 2)}\n`,
    );
  }

  console.log();
  console.log(
    `${
      triples.length - failures
    }/${triples.length} requirements hold their citations`,
  );
  return failures ? 1 : 0;
}

if (import.meta.main) Deno.exit(await main());

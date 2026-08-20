#!/usr/bin/env -S deno run --allow-read --allow-run --allow-write
// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/**
 * Check that a `type=test` citation actually tests its `type=implementation` citation.
 *
 * duvet checks that a citation *exists*. It cannot check that the test named by one says
 * anything about the code named by the other: both are comments, and a refactor can separate
 * them without either changing. That gap is what makes a citation decorative, and it is
 * invisible in every report the three tools produce on their own.
 *
 * This closes it by making the tools check each other. For each requirement duvet has matched
 * to both an implementation and a test, mutate *only* the cited implementation region and run
 * *only* the cited tests. A mutant that survives is a change to the code that claims to
 * implement the requirement which the test claiming to check it does not notice.
 *
 * The unit is a (requirement, implementation, test) triple rather than a file, because that is
 * what the claim is about. `cargo mutants -f <file>` would answer a weaker question -- "is this
 * file tested" -- and would drown the signal in mutants belonging to requirements nobody cited.
 */

// No imports, deliberately. `jsr:@std/...` would be fetched on first run, which puts this tool
// behind the network in exactly the situation it is most wanted -- a CI or nix sandbox with
// none -- for a path join and an argument parse. The same reasoning vendors the specifications
// under `.duvet/`; see development/code/spec-compliance.md.

const join = (...parts: string[]) => parts.join("/").replaceAll(/\/+/g, "/");
const REPO = new URL("..", import.meta.url).pathname.replace(/\/$/, "");

/**
 * duvet emits no `type` key for the default annotation kind, which is the implementation
 * citation. Spelling it here keeps the defaulting in one place.
 */
const IMPLEMENTATION = "CITATION";
const TEST = "TEST";

/** A duvet citation line: `//= <url>`, `//= type=<kind>`, or the quoted text `//# ...`. */
const CITATION_LINE = /^\s*\/\/[=#]/;
const ATTRIBUTE_LINE = /^\s*#\[/;
/** `fn name(`, `pub fn name(`, `async fn name(`. The name is what nextest filters on. */
const FN_LINE = /\bfn\s+([A-Za-z_][A-Za-z0-9_]*)/;
/** A mutant as cargo-mutants names it in `caught.txt` and friends: `path:line:col: what`. */
const MUTANT_LINE = /^([^:]+):(\d+):(\d+): /;

/** A half-open line range `[start, end)`, 1-indexed, in `path`. */
interface Region {
  path: string;
  start: number;
  end: number;
}

const showRegion = (r: Region) => `${r.path}:${r.start}-${r.end - 1}`;

/** One requirement, the code cited as implementing it, and the tests cited as checking it. */
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
): Promise<{ code: number; stdout: string }> {
  const output = await new Deno.Command(cmd, {
    args,
    cwd: REPO,
    stdout: "piped",
    stderr: "piped",
  }).output();
  return { code: output.code, stdout: new TextDecoder().decode(output.stdout) };
}

/**
 * Run `duvet report` and read back its JSON.
 *
 * Always regenerated rather than cached: a stale report would silently check the previous
 * commit's citations, which is the failure this tool exists to catch.
 */
async function duvetReport(jsonPath: string): Promise<Report> {
  const { code } = await run("duvet", ["report", "--json", jsonPath]);
  if (code !== 0) throw new Error("duvet report failed");
  return JSON.parse(await Deno.readTextFile(jsonPath));
}

/**
 * The first index at or after `start` that is not part of a citation comment.
 *
 * Ordinary `//` comments between the citation and the code it annotates are prose about the
 * citation -- every existing site has some -- so they are skipped too, as are the attributes
 * and doc comments that precede an item.
 */
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

/**
 * The line index just past the item or statement beginning at `start`.
 *
 * Brace matching rather than a Rust parser: the cited construct is a statement or a single
 * item, and the alternative -- taking the whole enclosing function -- would attribute mutants
 * to a requirement that does not cover them.
 */
function itemExtent(lines: string[], start: number): number {
  let depth = 0;
  let opened = false;
  let i = start;
  while (i < lines.length) {
    // Strings and char literals containing braces would break this. None of the cited sites
    // has one, and a miscount shows up as a region that fails to bound a mutant, not as a
    // silently wrong verdict.
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

/** The code a `type=implementation` citation at `line` annotates. */
async function implementationRegion(
  source: string,
  line: number,
): Promise<Region> {
  const lines = await readLines(join(REPO, source));
  const start = skipCitationBlock(lines, line - 1);
  return { path: source, start: start + 1, end: itemExtent(lines, start) + 1 };
}

/** The name of the test function a `type=test` citation at `line` annotates. */
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

/** Every requirement duvet has matched to both an implementation and a test. */
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

/** The cargo package owning a workspace-relative source path. */
async function packageOf(path: string): Promise<string> {
  const manifest = join(REPO, path.split("/")[0], "Cargo.toml");
  for (const line of (await Deno.readTextFile(manifest)).split("\n")) {
    if (line.startsWith("name")) {
      return line.split("=")[1].trim().replaceAll('"', "");
    }
  }
  throw new Error(`${manifest}: no package name`);
}

/**
 * A `cargo mutants --re` pattern narrowing the run towards `regions`.
 *
 * Best effort only, for cost. It cannot be trusted as the selector: cargo-mutants applies
 * neither `--re` nor `--exclude-re` nor `.cargo/mutants.toml` to `StructField`-genre mutants,
 * so a pattern matching nothing still yields every "delete field X from struct Y" in the
 * package. `selectRegions` is what actually decides which mutants count.
 */
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

/**
 * The mutants that fall inside a cited implementation region.
 *
 * The verdict is computed here rather than delegated to cargo-mutants' own filters, because
 * those leak (see `mutantFilter`). A mutant outside every cited region says nothing about the
 * citation under test and is discarded rather than counted either way.
 */
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

/**
 * A nextest filterset selecting the cited tests and nothing else.
 *
 * A bare test name is a *substring* filter: passing `foo` also runs `foo_now`. That widens both
 * the coverage run and the mutation run past the citation, and an uncited test whose name merely
 * contains a cited one can then kill the mutants and earn the citation a verdict nobody wrote a
 * test for. A citation names a function rather than a path, so each pattern anchors the end of
 * the name and, at the front, a module boundary.
 *
 * The names come from `FN_LINE` and so are `[A-Za-z_][A-Za-z0-9_]*`: no regex metacharacter can
 * appear in one, and there is nothing to escape.
 */
function testFilterset(tests: string[]): string {
  return tests.map((name) => `test(/(^|::)${name}$/)`).join(" + ");
}

/** The part of `cargo nextest list --message-format json` this tool reads. */
interface Suite {
  testcases?: Record<string, { "filter-match"?: { status?: string } }>;
}

/**
 * The cited tests nextest cannot find, or null if it could not be asked.
 *
 * Without this the tool's central failure mode is silent: a renamed test makes the filterset
 * match nothing, nextest exits 0 having run nothing, every mutant survives, and a citation that
 * is merely stale is reported as decorative. `cargo nextest list` exits 0 whether or not a name
 * matches anything, so the answer is in the listing rather than in the status.
 *
 * Every cited name is checked rather than any of them: a citation naming two tests is a claim
 * about both, and one that still exists would otherwise cover for one that does not.
 */
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
  // The listing carries every test in the binary it built; `filter-match` is what the filterset
  // said about each one.
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

/** The summaries cargo-mutants gives a mutant it finished with. */
const TERMINAL = new Set([
  "CaughtMutant",
  "MissedMutant",
  "Timeout",
  "Unviable",
]);

/**
 * The cargo-mutants exit codes that mean the run reached the end.
 *
 * 0 is every mutant caught, 2 is some survived, 3 is some timed out; each is a completed
 * measurement. 1 is usage and 4 is a failing baseline. An unrecognized code is not assumed to be
 * benign: a verdict drawn from a run nobody can account for is the thing this tool exists to
 * refuse.
 */
const COMPLETED = new Set([0, 2, 3]);

/** The part of cargo-mutants' `outcomes.json` this tool reads. */
interface Outcome {
  /** The string `"Baseline"`, or a `{ Mutant: ... }` object. */
  scenario: unknown;
  summary: string;
}

/**
 * Why a mutation run cannot be classified, or null if it can be.
 *
 * The buckets are files, and a run that died partway through leaves a `caught.txt` holding
 * whatever it reached first. Reading them without asking how the run ended turns a tool failure
 * into a verdict: a failing baseline leaves both buckets empty and reads as "generated no
 * mutants", and an interrupted run reads as `held` on the mutants it happened to catch before it
 * stopped. `outcomes.json` records what was attempted and how each attempt ended, and
 * `mutants.json` -- written before the first mutant is built -- records what the run set out to
 * do; the two together are the only evidence that the buckets are a whole measurement.
 */
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
  // The baseline is cargo-mutants running the cited tests against unmutated code. Its absence
  // and its failure are different things, and reporting either one as the other sends whoever
  // reads it to the wrong place.
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
    | "stale"
    | "unsupported"
    | "no-mutants"
    /** The cited tests fail on unmutated code, so no mutant result means anything. */
    | "failing"
    /** The measurement did not happen or did not finish; no verdict is available. */
    | "error";
  detail?: string;
  caught?: string[];
  missed?: string[];
  unviable?: string[];
  timeout?: string[];
}

/** Mutate the cited implementation, run only the cited tests, and report survivors. */
async function runTriple(
  triple: Triple,
  output: string,
  jobs: number,
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

  const [caught, missed, unviable, timeout] = await Promise.all(
    ["caught", "missed", "unviable", "timeout"].map(read),
  );
  // A region whose every mutant is unviable or timed out is not evidence either way: nothing
  // ran that the test could have noticed. Reporting that as "held" would credit the citation
  // for a check that never happened, which is the exact failure this tool exists to catch.
  if (!caught.length && !missed.length) {
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
  return {
    outcome: missed.length ? "decorative" : "held",
    caught,
    missed,
    unviable,
    timeout,
  };
}

/** `--flag value` and `--flag`, which is all this tool needs. */
function parseArgs(argv: string[]) {
  const args = {
    list: false,
    help: false,
    only: [] as string[],
    jobs: 4,
    output: join(REPO, "target", "spec-interlock"),
    json: "/tmp/duvet-interlock.json",
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
    return 0;
  }

  const report = await duvetReport(args.json);
  let triples = await collect(report);
  if (args.only.length) {
    triples = triples.filter((t) => args.only.includes(t.index));
    // `--only` is the cheap path for a citation somebody has just changed, so a typo in one --
    // or a requirement duvet has renumbered under it -- must not read as a clean run.
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

  // Nothing to check is not the same as nothing wrong: an empty report is what a tree with no
  // vendored specifications produces, and reporting `0/0` over one is the failure mode this
  // tool exists to refuse in the citations it checks.
  if (!triples.length) {
    console.error(
      "error: no requirement carries both an implementation and a test citation; there is nothing to check",
    );
    return 1;
  }

  await Deno.mkdir(args.output, { recursive: true });
  let failures = 0;
  for (const triple of triples) {
    console.log(
      `==> ${triple.spec}#${triple.section} (requirement ${triple.index})`,
    );
    const result = await runTriple(triple, args.output, Number(args.jobs));
    if (result.outcome === "held") {
      console.log(
        `    held: ${
          result.caught!.length
        } mutants in the cited region, all caught by ${
          triple.tests.join(", ")
        }`,
      );
    } else if (result.outcome === "decorative") {
      failures += 1;
      console.log(
        `    DECORATIVE: ${result.missed!.length} mutants survive ${
          triple.tests.join(", ")
        }`,
      );
      for (const mutant of result.missed!) console.log(`        ${mutant}`);
    } else {
      failures += 1;
      console.log(`    ${result.outcome.toUpperCase()}: ${result.detail}`);
    }
    // Counted but not listed: an unviable mutant is one that did not compile, which says
    // nothing about the test. The count is kept because a region that is *entirely* unviable
    // is the `no-mutants` case above, and that distinction is worth being able to see.
    const skipped = (result.unviable?.length ?? 0) +
      (result.timeout?.length ?? 0);
    if (skipped && result.outcome !== "no-mutants") {
      console.log(
        `    (${skipped} unviable or timed out, not counted either way)`,
      );
    }
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

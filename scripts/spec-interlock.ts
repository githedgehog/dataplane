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

/**
 * A mutant that survives its requirement's cited tests, and why that is the correct outcome.
 *
 * `development/code/mutation-testing.md` asks for every mutant to be *classified*, not killed:
 * some are equivalent, and the cheapest way to turn one green is to assert whatever the code
 * already does, which entrenches the behaviour instead of checking it. Without somewhere to
 * record that judgement the interlock reports an equivalent mutant as decorative forever, and
 * the pressure is to write the entrenching test.
 *
 * Kept here rather than in a data file for the reason `.cargo/mutants.toml` gives for holding
 * cargo-mutants' exclusions: the reasoning stays in one place, next to what acts on it.
 */
interface Accepted {
  /** The requirement, so an accept cannot silently cover a different citation. */
  requirement: string;
  /** cargo-mutants' own stable name -- `<path>: <what>`, with no line or column, so that the
   * entry survives the function being moved or reformatted. */
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
];

/** cargo-mutants' stable name for a mutant: its `<path>: <what>`, dropping line and column. */
function stableName(mutant: string): string {
  const match = MUTANT_LINE.exec(mutant);
  if (!match) return mutant;
  return `${match[1]}: ${mutant.slice(match[0].length)}`;
}

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
  throw new Error(`${source}:${line}: a type=test citation does not precede a function`);
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
 * Whether the cited test names match at least one test nextest will run.
 *
 * Without this the tool's central failure mode is silent: a renamed test makes the filter match
 * nothing, nextest exits 0 having run nothing, every mutant survives, and a citation that is
 * merely stale is reported as decorative.
 */
async function selectsATest(pkg: string, tests: string[]): Promise<boolean> {
  const { code, stdout } = await run("cargo", [
    "nextest",
    "list",
    "-p",
    pkg,
    ...tests,
  ]);
  return code === 0 && tests.some((name) => stdout.includes(name));
}

interface Result {
  outcome: "held" | "decorative" | "stale" | "unsupported" | "no-mutants";
  detail?: string;
  caught?: string[];
  missed?: string[];
  accepted?: Accepted[];
  unviable?: string[];
  timeout?: string[];
}

/** Mutate the cited implementation, run only the cited tests, and report survivors. */
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
      detail: `implementation in ${pkg}, tests in ${[...testPackages].join(", ")}`,
    };
  }
  if (!await selectsATest(pkg, triple.tests)) {
    return {
      outcome: "stale",
      detail: `no test in ${pkg} matches ${triple.tests.join(", ")}`,
    };
  }

  const outDir = join(output, `requirement-${triple.index}`);
  const files = [...new Set(triple.implementations.map((r) => r.path))].sort();
  await run("cargo", [
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
    ...triple.tests,
  ]);

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

  // Split the survivors into the ones somebody has judged equivalent and the ones nobody has.
  // Only the second kind is a finding.
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
    accepted,
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
      case "--list": args.list = true; break;
      case "--help": args.help = true; break;
      case "--only": args.only.push(value()); break;
      case "--jobs": args.jobs = Number(value()); break;
      case "--output": args.output = value(); break;
      case "--json": args.json = value(); break;
      default: throw new Error(`unknown argument ${flag}`);
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
  if (args.only.length) triples = triples.filter((t) => args.only.includes(t.index));

  if (args.list) {
    for (const triple of triples) {
      console.log(`${triple.spec}#${triple.section}  (requirement ${triple.index})`);
      for (const region of triple.implementations) {
        console.log(`    implementation  ${showRegion(region)}`);
      }
      triple.tests.forEach((name, i) => {
        console.log(`    test            ${name}  [${showRegion(triple.testSites[i])}]`);
      });
      console.log();
    }
    console.log(
      `${triples.length} requirements carry both an implementation and a test`,
    );
    return 0;
  }

  await Deno.mkdir(args.output, { recursive: true });
  const used = new Set<Accepted>();
  let failures = 0;
  for (const triple of triples) {
    console.log(`==> ${triple.spec}#${triple.section} (requirement ${triple.index})`);
    const result = await runTriple(triple, args.output, Number(args.jobs), used);
    if (result.outcome === "held") {
      console.log(
        `    held: ${result.caught!.length} mutants in the cited region, all caught by ${
          triple.tests.join(", ")
        }`,
      );
    } else if (result.outcome === "decorative") {
      failures += 1;
      console.log(
        `    DECORATIVE: ${result.missed!.length} mutants survive ${triple.tests.join(", ")}`,
      );
      for (const mutant of result.missed!) console.log(`        ${mutant}`);
    } else {
      failures += 1;
      console.log(`    ${result.outcome.toUpperCase()}: ${result.detail}`);
    }
    // Counted but not listed: an unviable mutant is one that did not compile, which says
    // nothing about the test. The count is kept because a region that is *entirely* unviable
    // is the `no-mutants` case above, and that distinction is worth being able to see.
    const skipped = (result.unviable?.length ?? 0) + (result.timeout?.length ?? 0);
    if (skipped && result.outcome !== "no-mutants") {
      console.log(`    (${skipped} unviable or timed out, not counted either way)`);
    }
    // Printed on every run, not hidden. An accepted mutant is a judgement somebody made, and it
    // should be as visible as the finding it replaced -- otherwise the list only ever grows.
    for (const entry of result.accepted ?? []) {
      console.log(`    accepted: ${entry.mutant}`);
      console.log(`        ${entry.reason}`);
    }
  }

  // An accept that matches nothing is worse than no accept: it reads as a considered judgement
  // while silently covering a mutant that no longer exists, and it would go on hiding whatever
  // takes that name next.
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

  console.log();
  console.log(
    `${triples.length - failures}/${triples.length} requirements hold their citations`,
  );
  return failures ? 1 : 0;
}

if (import.meta.main) Deno.exit(await main());

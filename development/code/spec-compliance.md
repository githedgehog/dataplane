# Specification compliance with duvet

One of the major problems for network software is complying with the vast number of RFCs that specify the proper
behavior.  Often, this behavior is surprising, even if you are very familiar with the particular protocol, or
have regularly used a particular function.  Even if your code appears to work, it can break in very difficult
to detect ways, or with very specific software, because of an RFC clause that the application depends on but that
is violated by the software.  To avoid this, Duvet is used to document the relevant RFCs and
document compliance code and tests.

[duvet] extracts the [RFC 2119] requirements of a specification and matches them against citations in the source:
a `//=` block naming a section, followed by the requirement quoted verbatim.
A requirement nothing implements, or an implementation nothing tests, becomes visible in the report.

We build a pinned fork (`npins` pin `duvet`) into the dev shell, so every command below runs
inside `nix-shell`.

## Layout

Everything under `.duvet/` is committed except `reports/`.

| Path | What it is |
| --- | --- |
| `.duvet/config.toml` | The crates that get scanned (`[[source]]`) and the specifications tracked (`[[specification]]`) |
| `.duvet/specifications/**.txt` | Vendored specification text; duvet fetches only when the file is missing, so the report needs no network |
| `.duvet/requirements/**/section-*.toml` | Requirements extracted from that text; generated, never hand-edited |
| `.duvet/snapshot.txt` | The committed report; `just duvet-check` fails when it drifts |

## Writing a citation

A citation of a requirement looks as follows:

```rust
//= https://www.rfc-editor.org/rfc/rfc4787#section-4.3
//= type=test
//= reason=held: for established flows; see the OneWay gap recorded in nf.rs
//# REQ-6:  The NAT mapping Refresh Direction MUST have a "NAT Outbound
//# refresh behavior" of "True".
#[test]
fn outbound_traffic_keeps_an_established_mapping_alive() {
```

The block sits directly above the item it is about: the function that meets the requirement, or the test that
checks it.
`type` is one of `spec`, `test`, `implementation` (the default), `exception`, `todo`, `implication`.
`reason` is free text; duvet does not require it, but every `exception` here carries one, because an `exception`
asserts that somebody weighed the requirement and declined it while a `todo` asserts someone needs to
either evaluate the requirement, or actually implement it.

Cite the section where a requirement is introduced and explained, not the summary section that restates it.
Many RFCs consolidate their numbered requirements into one section at the end — e.g., RFC 4787 §12, RFC 5382 §8,
RFC 5508 §9 — repeating the text of each requirement verbatim.
duvet keys requirements by section anchor, so it extracts each restatement as a requirement in its own right: REQ-6 is
counted once under `#section-4.3` and again under `#section-12`, and a citation naming one anchor says nothing about
the other.
Annotating the normative copy is the convention here, so the summary copies stay uncited forever.
That is the "permanent floor" note `just duvet-summary` prints under its table — 49 of the 121 requirements currently
counted are restatements, so the headline percentage can never reach 100%.
`scripts/duvet-summary.ts` hard-codes which section of each specification is the summary one.

## Routine maintenance

Annotations are part of the change that adds them.
After editing one, or after moving cited code:

```bash
nix-shell --run "just duvet"        # rewrites .duvet/snapshot.txt and .duvet/requirements
```

Commit the resulting `.duvet/` diff alongside the code.
CI runs `just duvet-check` (also part of `just lint`), which sets the committed copies aside, regenerates them, diffs
the two, and puts the originals back; a stale snapshot is a lint failure.
`just duvet-summary` prints the coverage tables that land in the CI job summary.

### Fixing a broken reference

A citation that no longer lines up with the specification is a hard error: `duvet report` exits non-zero and writes
neither the snapshot nor the HTML report, so `just duvet`, `just duvet-check` and `just lint` all fail so broken
commits cannot get merged. There are two ways to break a citation, and the message says which one it is.

**The quote is not in the cited section.**
The `//#` lines have to appear in that section verbatim, so trimming the quote to fit the code, re-wrapping it, or
aiming an otherwise correct quote at the wrong section all give:

```text
could not find text in section "section-4.3" of https://www.rfc-editor.org/rfc/rfc4787
```

Re-copy the text from `.duvet/requirements/www.rfc-editor.org/rfc/rfc4787/section-4.3.toml` rather than retyping it
from the RFC — that file is the extractor's own copy, already line-wrapped the way the matcher sees it.

**The cited section does not exist.**
The anchor has to name a section of that document, so a typo, or an anchor carried over from another RFC that numbers
its sections differently, gives:

```text
missing section "section-4.9" in https://www.rfc-editor.org/rfc/rfc4787
```

Any real section of the document resolves, whether or not duvet extracted requirements from it; the sections that do
carry requirements are the `section-*.toml` files under `.duvet/requirements/<host>/<rfc>/`, each spelling its anchor
out in the `target =` line.

One more parse hazard: `//=` is the citation marker, so a banner comment of the form `//===== Fib =====//` in a scanned
crate is a citation with no URL and errors the run.

## Adding a specification

Add a `[[specification]]` entry to `.duvet/config.toml`, run `just duvet` once with network access so duvet downloads
the text, and commit the vendored `.txt` along with the generated requirements and snapshot.

Always name the individual RFC, never a [BCP].
A Best Current Practice is a stable label the RFC Editor puts on the current advice about some topic: BCP 127 means
"how a NAT should behave", and which RFCs it points at changes as the advice is revised.
Most BCPs are a single RFC, but some are several — BCP 127 is RFC 4787, RFC 6888 and RFC 7857 — and the published
`bcp127.txt` is those documents concatenated.
Each of them has its own section 5, duvet keys requirements by section anchor, so the last document in the file wins
and the earlier ones lose whole sections.
Nothing warns you: the report still succeeds and still quotes a requirement count, just a much smaller one than the
member RFCs hold between them.

## Proving a citation is more than a comment

duvet is a text scanner.
A `type=test` citation tells it that somebody wrote a comment above a test function claiming the test checks that
requirement, and that is the whole of what `duvet-check` verifies — the annotation is present and its quote matches the
RFC.
The test underneath it may assert nothing about the requirement, may assert the wrong thing, may be `#[ignore]`d, may
be compiled out by a `cfg`, or may return before it reaches the interesting case.
The report counts it as tested regardless, which makes a wrong citation worse than no citation: it reports coverage
nobody has.

`just spec-interlock` closes that gap by making the test prove itself.
For each requirement carrying both an implementation and a test citation, it checks with `llvm-cov` that the cited
tests actually execute the cited code, then mutates that code and reruns only those tests.
If a mutant survives — the code's behaviour changed and the cited tests still passed — the citation is deemed decorative.
The verdicts are `held` (the tests notice a change to the cited code), `decorative` (they do not), `uncovered` (they
never execute it) and `stale` (the citation names a test that no longer exists).

```bash
nix-shell --run "just spec-interlock --list"                           # requirements it can check, with their numbers
nix-shell --run "just spec-interlock --only 42 --results /tmp/i.json"  # one requirement
nix-shell --run "just duvet-summary --results /tmp/i.json"             # verdicts folded into the tables
```

It is mutation testing, so it is far too slow for ordinary CI; run it when adding or changing a `type=test` citation.
Survivors judged equivalent are recorded, with the reasoning, in the `ACCEPTED` list in `scripts/spec-interlock.ts`.

[BCP]: https://www.rfc-editor.org/rfc/rfc2026#section-5
[duvet]: https://awslabs.github.io/duvet/
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119

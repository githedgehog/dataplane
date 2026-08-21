# Specification compliance with duvet

Status: **three specifications tracked, the RFC corpus and its errata audited, the citation
interlock built; every cited requirement now holds.**
The open-questions list below is expected to grow; it is written down so that it grows in one place
rather than in four people's heads.

## What it is for

[duvet] matches citations in the source -- `//= <url>` followed by the requirement text, quoted
verbatim -- against requirements it extracts from a specification. A requirement nothing implements,
or an implementation nothing tests, becomes visible.

It is the third leg of a stool. [bolero](./property-testing.md) asks whether a property holds.
[cargo-mutants](./mutation-testing.md) asks whether there are enough properties. Neither can ask
whether they are the properties the specification called for.

That third question is not decoration. Mutation testing can actively **entrench a deviation**:
the cheapest way to kill a surviving mutant is to assert the behaviour that was observed, which
cements whatever the code already did. A suite can converge on a perfect score against the wrong
specification, and nothing inside the suite can notice.

## What it found, first time out

Two specifications, roughly one afternoon.

|                            | outcome                                                 |
| -------------------------- | ------------------------------------------------------- |
| RFC 4884 length validation | **real defect**, fixed in `net/src/headers/embedded.rs` |
| RFC 5382 REQ-7, REQ-10     | already held, already tested, never named               |
| RFC 5382 REQ-5, REQ-1      | conformance gaps, recorded as `todo`                    |

The defect is the strongest argument for the tool: `is_full_payload()` checked the RFC 4884 length
attribute in **bits** where the RFC counts 32-bit **words**, so it rejected seven of eight
conforming lengths and admitted sub-128-octet fields the RFC forbids. It had property tests. They
passed.

The two already-held requirements are the second-strongest argument, for the opposite reason. The
masquerade exclusivity property -- "two live flows never share a translation" -- was written before
anyone read RFC 5382, and turns out to _be_ REQ-7 verbatim. Citing it converts an accident into a
claim a reviewer can check and a refactor cannot quietly undo.

### `todo` versus `exception`

Both are ways of saying "not implemented". They are not interchangeable. An `exception` asserts that
somebody weighed the requirement and declined it; a `todo` asserts only that nobody has yet. Using
`exception` for an undecided requirement is self-granted absolution, and it is invisible afterwards.
REQ-1 and REQ-5 are `todo` for exactly this reason.

## What the tool will and will not parse

Measured by running the extractor over the entire RFC series -- 9,827 documents, 23 seconds.

**It is deterministic.** Two full sweeps produced 68,257 emitted files that are byte-identical, and
single-threaded output matches parallel. Snapshot regression gating is safe.

**It fails loudly on 35 documents**, all `invalid utf-8`, nearly all pre-1990 documents carrying
Latin-1 bytes. The only ones a networking project might want are RFC 1305 (NTPv3) and RFC 2557.

**It is blind to lowercase normative language.** This is the important one:

|                            | RFC 2119 keywords | lowercase must/should | cites RFC 2119 |
| -------------------------- | ----------------- | --------------------- | -------------- |
| RFC 8200 (IPv6, STD 86)    | 0                 | 79                    | no             |
| RFC 3022 (traditional NAT) | 0                 | 24                    | no             |

RFC 8200 says "It must obey the protocol requirements for routers when receiving (forwarding)
interfaces." That is a real obligation with no uppercase token to key on. duvet is not
malfunctioning -- there is nothing to grip -- but the effect is that **the two specifications
closest to what this dataplane is cannot be tracked directly.** This is the boundary of the method:
it covers BCP-style documents with numbered `REQ-` clauses very well and foundational standards-track
documents not at all.

Of the 3,767 documents that extract nothing, almost all are legitimately requirement-free. The large
cluster showing exactly ten keywords is the boilerplate "The key words MUST, MUST NOT, ..."
paragraph, which duvet correctly declines to treat as normative.

**Modern format is fine.** There is no cliff at RFC 8650; xml2rfc v3 output parses (RFC 9000: 522
requirements, RFC 9110: 412, RFC 8446: 431).

## Is a citation true? The interlock

`just spec-interlock`, implemented by `scripts/spec-interlock.ts`.

duvet checks that a `type=test` citation _exists_. It cannot check that the test named by one
says anything about the code named by the other: both are comments, and a refactor can separate
them without either changing. A requirement can therefore show implementation **and** test --
the fully-green state -- while nothing tests it.

The check is to make the tools check each other. For each requirement duvet has matched to both
an implementation and a test, mutate **only** the cited implementation region and run **only**
the cited tests. A mutant that survives is a change to the code that claims to implement the
requirement which the test that claims to check it does not notice.

The unit is a (requirement, implementation, test) triple, not a file. `cargo mutants -f <file>`
answers a weaker question -- "is this file tested" -- and buries the signal: the RFC 4884 finding
below was four mutants among the 125 that `embedded.rs` generates.

### Three tiers, cheapest first

Each catches what the one below it cannot, and running them in this order is what keeps the
expensive one affordable.

1. **Coverage** -- `cargo llvm-cov` over the cited region, running only the cited tests. Answers
   "did the test go there at all". Seconds.
2. **Mutation** -- `cargo mutants` over the same region, same tests. Answers "did it care". Minutes.
3. **Judgement** -- a person. Answers "is this the right sentence, on the right code, and is this
   survivor equivalent". Not automatable, and the sections below are what it has to work with.

Coverage runs first because it can settle the question outright: a cited test that executes **no**
line of the cited region cannot be testing the requirement, and there is no reason to build a
mutant to confirm it.

It must not become a threshold. A caught mutant was necessarily executed, so coverage adds nothing
wherever mutation already succeeds -- only zero is decisive, and only as an error. Anything above
zero is used to _explain_ a survivor rather than to judge one, which is the split below.

### Outcomes

|                | meaning                                                                |
| -------------- | ---------------------------------------------------------------------- |
| **held**       | every mutant in the cited region was caught, or accepted with a reason |
| **decorative** | a mutant survived unaccounted for                                      |
| **uncovered**  | the cited tests execute none of the cited region                       |
| **no-mutants** | the region produced nothing testable -- usually every mutant unviable  |
| **stale**      | the cited test name matches no test; the citation has rotted           |

`no-mutants` is not a pass. Reporting it as one would credit a citation for a check that never
ran, which is the failure the tool exists to catch. `stale` exists because it is the tool's own
worst failure mode: a renamed test makes the filter match nothing, nextest exits 0 having run
nothing, every mutant survives, and a citation that is merely out of date is reported as
decorative. The test names are checked against `cargo nextest list` before any mutant runs.

The same hazard has now appeared three times -- `stale`, `no-mutants`, and a coverage collection
that failed silently and returned an empty map, which reads as "nothing was executed" and
relabelled every survivor. **A measurement that fails silently reads as a measurement that
succeeded.** Every step here reports its own failure as a distinct outcome for that reason.

### Why a mutant survived

A survivor has two possible causes needing opposite fixes, and mutation alone cannot tell them
apart. Coverage of the mutated line does:

|               | meaning                             | the fix                                           |
| ------------- | ----------------------------------- | ------------------------------------------------- |
| **unreached** | the cited tests never ran that line | change what the test **feeds**                    |
| **tolerated** | they ran it and passed anyway       | change what it **asserts** -- or it is equivalent |

Splitting the ten survivors on RFC 4787 REQ-3 by hand took longer than the run that found them.

### Accepted mutants

Some survivors are equivalent, and the cheapest way to turn one green is to assert whatever the
code already does -- the entrenchment [mutation testing](./mutation-testing.md) warns about,
arrived at from the other direction. `scripts/spec-interlock.ts` therefore carries an `ACCEPTED`
list: a requirement, a mutant, and a reason.

Two rules keep it from becoming a way of not looking. An accept is **printed in full on every
run**, next to the finding it replaced. And an accept that matches no live mutant is a **failure**,
because a stale one reads as a considered judgement while silently covering whatever takes that
name next.

Both current entries are upstream invariants rather than gaps, and both were settled the same way:
read the code, then apply the mutant by hand and run the whole crate's suite. That is the shape of
the argument to expect.

### What it found, first time out

Seven requirements carried both an implementation and a test. duvet reported all seven green.
**Three actually held.** Closing the other four is recorded below, because what each one turned
out to be is more useful than the count.

| finding                           | what it really was                                   |
| --------------------------------- | ---------------------------------------------------- |
| RFC 4884, "at least 128 octets"   | a genuine test gap, in two ways                      |
| RFC 4787 REQ-2, "pooling: Paired" | an equivalent mutant                                 |
| RFC 4787 REQ-3 / RFC 5382 REQ-7   | a citation on the wrong code, then on the wrong test |

**RFC 4884 -- a real gap, on the path where the original defect was.** The test iterated
`[120, 124]`, so `<` versus `<=` at the boundary was invisible: 128 itself was never tested.
Worse, the citation sat on **both** the ICMPv4 and ICMPv6 branches and there was no v6 fixture at
all, so three of the v6 branch's mutants had nothing to catch them. The RFC 4884 fix had been
applied to both branches and tested on one. Closed by taking the boundary from both sides in both
families.

**RFC 4787 REQ-2 -- not a defect.** `replace match guard e.is_exhaustion() with true` survives,
and is equivalent: `reuse_allocated_ip` skips `NoFreePort` and loops, so from a well-formed pool
it can only return `NoFreeIp`, which _is_ exhaustion. Accepted with that reasoning.

**RFC 4787 REQ-3 / RFC 5382 REQ-7 -- wrong twice over, and the most instructive.** The citation
sat on `allocate_v4`, which only forwards; every mutant of it was unviable, so the interlock could
not check the citation at all. Moving it to `Bitmap256::allocate_port_from_bitmap` -- the bit that
marks a port used, and the narrowest thing whose mutation would violate either requirement -- made
it checkable, and it immediately failed with ten survivors.

Coverage said seven of those were **unreached**: the cited stage-level property draws a handful of
ports, so it never fills a 256-port block and never enters the second half of the bitmap. One of
the seven replaced the bit that marks a port used, which is port overloading itself.

And the fix was **no new test**. `a_region_can_be_allocated_dry` already walks two address ranges
dry asserting no tuple is handed out twice; it simply was not cited. Adding the citation killed
nine. The tenth was an invariant and is accepted.

### What that costs to believe

Three things generalise, and all three are invisible to duvet:

- **A citation can be on the wrong code.** REQ-3 pointed at a forwarding wrapper for as long as it
  existed. `no-mutants` is the only signal that catches this, which is why it is not a pass.
- **A citation can be on the right code and name the wrong test.** The requirement was fully
  tested, by a good test, that nobody had cited. duvet cannot see this at all: it checks that a
  `type=test` citation exists, not that the test it names is the one doing the work.
- **A requirement can need more than one cited test, at different altitudes.** The stage-level
  property states port overloading where it is observable -- two flows, one reply path. The
  exhaustion walk reaches the code that would commit it. Neither is sufficient; both are cited.

## Where a citation goes, and what that costs an abstraction

The rule is one sentence: **cite the narrowest region whose mutation would violate the
requirement.**

It is worth stating because the obvious alternative -- cite the function whose name matches the
requirement -- is what produced the RFC 4787 REQ-3 result above, and because there is a live
worry that a citation model tied to source regions will end up penalising delegation, generics
and macros. Measured, it mostly does not, and where it does the constraint is narrow.

### Generics and traits: no cost

Trait default bodies and generic functions mutate normally, and one citation on them covers
every instantiation. `net/src/checksum.rs` is the worked example: the `Checksum` trait's provided
methods carry the RFC 1624 incremental-update arithmetic, and the mutants land exactly on it
(`delete !`, `replace >> with <<`). Its low mutant density -- 3.1 per 100 lines against 12.0 for
`ipv4/mod.rs` -- is signatures without bodies, not logic that got away.

This is an argument _for_ abstraction. A requirement implemented once behind a generic needs one
citation and one test. The RFC 4884 finding above is what the alternative costs: lines 259 and
290 of `embedded.rs` are the same check written twice, once for ICMPv4 and once for ICMPv6, and
the v6 copy went untested and uncaught. Duplication is what hid it.

### Delegation: cite the delegate, and mind the return type

Two separate things, which the REQ-3 result ran together.

A thin forwarding function is the wrong place to cite because it decides nothing -- the
requirement lives in what it forwards to. That is the real error in the REQ-3 citation:
`allocate_v4` forwards to `allocate_from_tables`, which is shared by v4 and v6 and is where one
citation would cover both.

Its mutants being _unviable_ is a different problem with a different cause. cargo-mutants
replaces a function body with a synthesised return value, so whether it can mutate a function at
all depends on how hard that type is to fabricate.
`Result<AllocationResult<AllocatedPort<Ipv4Addr>>, AllocatorError>` defeats it; a delegating
function returning `bool` mutates fine. So an unviable region is not evidence of over-abstraction
-- it is evidence that nothing there was checkable, whatever the reason.

### Macros: a real blind spot, and the one rule worth keeping

cargo-mutants generates **nothing** for macro-generated code. Probed directly:

```rust
macro_rules! bounded { ($name:ident, $min:expr) => {
    pub fn $name(len: usize) -> bool { len >= $min }
}; }
bounded!(at_least_128, 128);   // zero mutants -- the boundary cannot be broken
pub fn concrete(len: usize) -> bool { len >= 128 }   // three mutants
```

The `>=` in the macro is exactly the boundary class that RFC 4884 got wrong, and it is
unreachable by mutation and therefore by the interlock.

That is narrower than "macros are a problem". In this tree the separation already holds: the
protocol logic a specification constrains is written directly and mutates well -- `tcp/mod.rs`
15.3 mutants per 100 lines, `icmp6/mod.rs` 14.6, `ipv4/mod.rs` 12.0 -- while the macro-heavy
files are the combinator and accessor layer, `headers/view.rs` at 1.5 and `headers/pat.rs` at
2.1, which no RFC has an opinion about. No requirement cited today sits in a macro body.

So the rule is not "avoid macros". It is: **do not put a normative decision inside a macro
body.** Generate the plumbing; write the comparison the specification names. If that is ever too
expensive, the fallback is the `contract::` pattern -- lift the decision into a `Requirement`
predicate the macro calls, which is ordinary mutable code with a citation on it.

## Do not cite a composite BCP

The worst failure found, because it exits 0 and reports a plausible number.

209 of 239 BCP entries in the mirror are symlinks to a single RFC and are harmless. The other 27 are
concatenations, and **BCP 127 is one of them**: RFC 4787 + RFC 6888 + RFC 7857 in one file.

|                                              | requirements |
| -------------------------------------------- | ------------ |
| `bcp127.txt`                                 | **42**       |
| RFC 4787 + 6888 + 7857, extracted separately | **129**      |

duvet keys requirements by section anchor, and each member document has its own `section-5`, so the
last document in the concatenation wins. RFC 6888 loses all three of its sections; RFC 4787 loses
eight of thirteen, including section 5, _NAT Session Refresh_, where the UDP timeout requirements
live. No warning is emitted.

Always cite the individual RFC. The composites remain useful as a **membership oracle** -- "BCP 127
now contains an RFC we do not track" is the cheapest available drift alarm, and it is a `grep` over
27 files rather than something duvet has to parse.

## Synthesizing requirements for a non-conforming specification

duvet accepts a Markdown specification (`-f markdown`), and this is the intended route for RFC 8200
and RFC 3022: restate their lowercase obligations in RFC 2119 form, in-repo, as a separate
`[[specification]]`.

The mechanism cooperates. Section anchors are heading slugs rather than numbers, so the composite
collision cannot occur, and the prose around a requirement is carried into the emitted TOML as a
comment, so a derivation note travels with it.

**The hazard is that this is the one place the method can certify itself.** duvet's value is that
the quoted unit is a sentence somebody else wrote. Once we author the specification we control both
sides of the match, and the path of least resistance is to write the requirement the code already
satisfies -- the same entrenchment failure as mutation testing, moved up a level and much harder to
see, because the result looks like compliance with RFC 8200.

Rules, therefore:

- Every synthesized requirement quotes its **source sentence verbatim**, adjacent to it.
- A synthesized requirement may **never be more specific** than the sentence it derives from.
- Where the original is genuinely ambiguous, that ambiguity **is the finding**. Record both readings
  for a human; do not resolve it into one confident restatement.
- Review is by somebody who reads the original. A reviewer looking only at our Markdown cannot catch
  the failure this is guarding against.

## Errata

An RFC body is immutable, so a correction to one lives only in its errata. The corpus carries them
in `inline-errata/`: 1,750 RFCs rendered as HTML with their **Verified** errata spliced into the
text, the corrected passage wrapped in `<span class="Verified-inline-styling">` and an endnote block
giving the EID, section, original text, corrected text and notes.

Only Verified errata are inlined -- all 1,750 renderings say so in their header, and no other status
appears. `RFCs_for_errata.txt` names 2,584 RFCs, so **847 have errata that this corpus never shows
you**: Reported, Held for Document Update, or Rejected. That is the residual fetch leg, and it is a
much smaller one than it looked.

**Use the file, not the index.** Ten RFCs have renderings and are absent from
`RFCs_for_errata.txt` -- among them RFC 1191, Path MTU Discovery. Every one was verified after the
index's own timestamp, so the index is stale in one direction only: it never lists a spurious RFC,
it just misses recent ones. The presence or absence of `inline-errata/rfcNNNN.html` is authoritative
for "has Verified errata"; the index is authoritative for nothing.

What that says about the specifications in play:

|                                                  | errata             |
| ------------------------------------------------ | ------------------ |
| RFC 4787, RFC 5382, RFC 5508, RFC 6888, RFC 7857 | none of any status |
| RFC 4884                                         | one, EID 3         |

**EID 3 does not touch us.** It corrects Section 7's description of the ICMP Extension Header
checksum from "the one's complement sum of the data structure" to "...of the ICMP Extension
Structure" -- naming what was already unambiguous from context. The sentence carries no RFC 2119
keyword, so duvet never extracted it: the two requirements it does extract from Section 7 are a
`MAY` about ignoring unrecognised objects and a `MUST` about the reassembly buffer size, and neither
is edited. Nothing in the tree parses an extension structure or verifies its checksum; every RFC
4884 citation we hold is in Section 3 or Section 5, on the length attribute. So
`MIN_ORIGINAL_DATAGRAM_OCTETS` was decided against text the erratum leaves alone.

**Read the endnotes, do not diff the body.** In 524 of the 1,750 renderings an erratum has an
endnote but no spliced-in span, because its "Original Text" is not a verbatim quote the renderer
could locate -- it is a `GLOBAL` scope, or a prose commentary rather than a passage. RFC 8200 is one
of them. Diffing a rendering against the base text therefore under-reports; the endnote list is the
complete one.

Two errata on specifications we have discussed but do not track are worth having read:

- **RFC 2663 EID 400** corrects Section 2.6 from "segments containing FINs or SYNs will be the last
  packets of the session" to "FINs or **RSTs**" -- the original sentence was nonsense, since a SYN
  never ends a session. Corrected, it is a warning against exactly what masquerade does: we
  invalidate the pair the moment `next_flow_status` returns `Reset` or `Closed`, and RFC 2663 says a
  NAT cannot assume no retransmission follows. **This is not a defect.** RFC 5382 revisits the same
  question and leaves it to us -- "NAT behavior for handling RST packets, or connections in
  TIME_WAIT state is left unspecified", with an explicit `MAY` to hold state and an explicit note
  that holding it "may limit the throughput of connections through a NAT with limited resources".
  We took the throughput side. The erratum is what makes that a decision rather than an oversight.
- **RFC 8200 EID 5945** rewrites Section 4.5 from the three-part fragmentation model back to the
  two-part model of RFC 2460, dropping the "Extension & Upper-Layer Headers" division. It concerns
  source fragmentation, which this dataplane does not perform, so it is recorded and not acted on.

**The vendored specification stays the base text.** `.duvet/specifications/` must hold what duvet
would fetch, or the quotes stop matching and the vendoring stops being a drop-in for the network.
Errata are checked alongside it, not merged into it.

## Which specifications apply to us

A first enumeration, from what the tree already names: every `RFC ####` mention in a `.rs` file,
mapped to the crate that makes it. It is a lower bound -- it finds specifications somebody has
already thought about, not ones nobody has -- but it is evidence rather than recollection, and it
is a `grep` to regenerate.

Twenty-eight RFCs, of which three are tracked.

| RFC | crates | note |
| --- | --- | --- |
| 8200 (IPv6) | `net` | **46 mentions, the most in the tree, and duvet cannot parse it** -- 0 uppercase keywords, 79 lowercase. Synthesis or nothing. |
| 4787 (NAT/UDP) | `nat`, `dataplane` | tracked |
| 4884 (ICMP extension) | `nat`, `net` | tracked |
| 7348 (VXLAN) | `net`, `dpdk` | 15 mentions, untracked |
| 4302 (IP AH) | `net` | 11 mentions, untracked |
| 5382 (NAT/TCP) | `nat` | tracked |
| 792, 1812, 1122, 1191 | `net`, `dataplane` | foundational; expect the same lowercase problem as 8200 |
| 9293 (TCP), 2018, 7323, 3168, 6946, 3540, 2675 | `net` | TCP option and fragmentation behaviour |
| 5508 (NAT/ICMP) | `nat`, `net` | duvet-friendly, on-topic, untracked -- 92 requirements |
| 6437, 4861, 6918 | `net` | IPv6 flow label, ND |
| 1624 | `net` | checksum update |
| 7854, 8671 | `routing` | BMP |
| 3339, 9562, 7637 | `config`, `mgmt`, `id`, `dpdk` | formats, not behaviour |

What this changes about the plan:

- **The largest specification surface is the one duvet handles worst.** `net` is the biggest crate
  and its obligations are concentrated in RFC 8200, RFC 791, RFC 792 and RFC 1812 -- the
  lowercase-normative, foundational documents. Extending compliance tracking to the whole codebase
  is therefore mostly a _synthesis_ problem, not a configuration problem, and synthesis is the part
  of this method with a hazard attached.
- **The cheap wins are still in NAT.** RFC 5508 is duvet-friendly, on-topic, and one config edit
  from being tracked.
- **Most crates have no external specification at all.** `lpm`, `acl`, `flow-filter`, `config`,
  `mgmt` and roughly thirty others implement internal semantics. duvet has nothing to say about
  them; bolero and cargo-mutants have everything to say. Whether to synthesize in-repo
  specifications for them is deliberately still open -- see the scoping question below.

## Open questions

Expected to expand. Nothing here is scheduled.

1. ~~**Which RFCs apply to us at all.**~~ A first pass is above. What remains is the harder half:
   the specifications that constrain us and that nothing in the tree mentions.
2. **Which of those are not RFC 2119 conforming**, and so need synthesis per the section above.
   RFC 8200 is the known case and the most consequential one.
3. ~~**Is a citation true?**~~ Built; see [the interlock](#is-a-citation-true-the-interlock). All
   seven cited requirements hold, which means the tool currently has nothing to say and its next
   real test is the next citation somebody writes. What remains is whether it becomes a gate:
   seven minutes for seven requirements is too slow per pull request over everything, but
   `--only` on a changed citation is cheap, and `uncovered` is now reachable without building a
   single mutant.
4. **Errata.** Mostly settled; see [Errata](#errata) below. What remains is the 847 RFCs whose
   errata exist but are not Verified, for which the corpus holds no body. None of them is tracked
   today; RFC 4443 and RFC 3022 are both in that set and both plausible future targets.
5. **How the corpus is pinned** -- a git mirror, or `oras` into ghcr.io behind `npins`. Sizing: the
   metadata that drives every drift alarm (indexes, `bcp/`, `std/`) is 5MB; the 232MB is RFC bodies,
   of which we cite perhaps ten. Text gzips about 4:1.
6. **Two alarms, not one.** RFC bodies are immutable, so a diff in `rfc5382.txt` means a rerender or
   a corrupt mirror: rare and loud. A new erratum, a new `updated_by`, a new BCP member is expected
   churn: a routine pull request. Collapsing both into "the pin moved" trains people to rubber-stamp
   it. The corpus has a `rerendered/` directory precisely because the first case is real.
7. **A scoping policy, before the first large specification lands.** Adding STUN drops 200 uncited
   requirements into the snapshot in one commit; QUIC would add 522. Without a rule for scoping
   _within_ a specification the report becomes wallpaper on the day it gets interesting -- the same
   lesson as "do not test printers" and "classify, do not eliminate".
8. ~~**Should the snapshot be a blocking gate?**~~ Yes, and it is: `just duvet-check`. The snapshot
   had drifted two commits after being introduced, which settled the argument -- a
   regenerate-by-hand rule is one nobody runs. What remains is wiring it into CI.
9. **A coverage report analogous to the existing ones**, so that specification coverage is read the
   same way as line and mutant coverage.

## Operational notes

- **`//=` is duvet's citation marker.** Banner comments of the form `//======== Fib ========//` are
  parsed as citations and produce errors; `routing/src/cli/display.rs` needed a space inserted after
  the slashes.
- **Everything under `.duvet/` is committed except `reports/`.** `duvet report` reads the
  specification from `.duvet/specifications/` and only reaches the network when it is missing, so
  vendoring the text is what lets the report run in a nix build sandbox. Verified offline under
  `unshare -rn`.
- **The mirror is a drop-in for the network fetch.** Text pulled by rsync is byte-identical to what
  duvet fetches from rfc-editor.org, and re-extraction produces identical requirements apart from
  the `target` line.
- **`see_also` is empty** in the per-RFC JSON, so the RFC-to-BCP mapping has to come from the `bcp/`
  symlinks or the index files, not the metadata.
- **`-n.json`** in the corpus is an all-null artifact of the mirror. It parses, so it will not crash
  a loader, but anything iterating the JSON should skip a null `doc_id`.

[duvet]: https://awslabs.github.io/duvet/

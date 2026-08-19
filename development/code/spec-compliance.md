# Specification compliance with duvet

Status: **three specifications tracked, the RFC corpus and its errata audited, the procedure
itself not yet proven.**
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

| | outcome |
| --- | --- |
| RFC 4884 length validation | **real defect**, fixed in `net/src/headers/embedded.rs` |
| RFC 5382 REQ-7, REQ-10 | already held, already tested, never named |
| RFC 5382 REQ-5, REQ-1 | conformance gaps, recorded as `todo` |

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

| | RFC 2119 keywords | lowercase must/should | cites RFC 2119 |
| --- | --- | --- | --- |
| RFC 8200 (IPv6, STD 86) | 0 | 79 | no |
| RFC 3022 (traditional NAT) | 0 | 24 | no |

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

## Do not cite a composite BCP

The worst failure found, because it exits 0 and reports a plausible number.

209 of 239 BCP entries in the mirror are symlinks to a single RFC and are harmless. The other 27 are
concatenations, and **BCP 127 is one of them**: RFC 4787 + RFC 6888 + RFC 7857 in one file.

| | requirements |
| --- | --- |
| `bcp127.txt` | **42** |
| RFC 4787 + 6888 + 7857, extracted separately | **129** |

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

| | errata |
| --- | --- |
| RFC 4787, RFC 5382, RFC 5508, RFC 6888, RFC 7857 | none of any status |
| RFC 4884 | one, EID 3 |

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

## Open questions

Expected to expand. Nothing here is scheduled.

1. **Which RFCs apply to us at all.** Prior to everything else, and never yet enumerated. RFC 4787
   (59 requirements), RFC 5508 (92), RFC 6888 (41) and RFC 7857 (29) are duvet-friendly, directly
   on-topic and untracked -- 221 requirements one config edit away, no synthesis needed.
2. **Which of those are not RFC 2119 conforming**, and so need synthesis per the section above.
3. **Is a citation true?** duvet checks that a `type=test` citation _exists_, not that the test
   exercises the requirement. This is the vacuity problem that the llvm-cov execution counters
   caught twice. The cross-check uses artifacts we already produce: mutate the region cited
   `type=implementation` and see whether the test cited `type=test` fails. If it does not, the
   citation is decorative. This is the only item on this list that makes the three tools check each
   other rather than merely coexist.
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
8. **Should the snapshot be a blocking gate?** Unlike cargo-mutants it can be: `duvet report` takes
   4ms and is bit-for-bit deterministic. It would be the cheapest correctness gate we have.
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

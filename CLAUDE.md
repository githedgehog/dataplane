# Rules for AI agents

Follow the [development guide](development/README.md).

If you make a design decision or do a code review, try to cite the section of the
development guide you are following.

## Commit messages

A commit message signposts the diff; it does not restate it. Rationale belongs where it
constrains the code -- in the code, its doc comments, or the development guide -- because a
second copy in the message is a second thing to keep correct, and the two will drift.

A message carries what the diff cannot:

- the "why" of the commit,
- non-obvious process facts,

It does not re-summarize the change, narrate how it was made, or repeat an argument the
commit already puts in the tree. For a docs commit, the file is the content; the message
points at it.

Keep `git log` scannable: a few lines by default, longer only where the diff is opaque and
the message is what makes the commit reviewable.

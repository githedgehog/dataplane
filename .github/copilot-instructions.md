# AI code review instructions

## Logic

Find logic errors in the code under review.

- If you are confident that the code is incorrect, and you are confident in a fix, suggest the fix.
- If you are not confident that the code is correct or don't understand it, ask for clarification.
- If the logic you review is overly complex or difficult to understand, suggest simplifications or improvements.
- If the logic is so complex that you don't have a simple fix, say so in a comment and mark it as a suggested blocker
  to merging the code.

## Style

Consider the contents of the [repository's development guide][dev-guide]

- Contributors are expected to consider and follow these guidelines.
- Provide feedback about places where we deviate from our stated goals.
  If a deviation from our goals is found, comment on it
  - if it constitutes a violation of a major guideline (such as correct use of unsafe code).
  - or if it is not already explicitly acknowledged as a temporary measure in the PR's commit messages, description, or
    included code or PR comments.
  - Minor deviations from our goals are acceptable if they are explicitly acknowledged and justified somewhere in the
    contents of the code under review.

If you find style flaws, cite the relevant parts of our development guide which have been contradicted (if
applicable).
The development guide is not exhaustive.
You may freely comment on style or quality criteria which are not covered in the guide.

## Docs

Look for areas where the code under review has caused the implementation to drift out of sync with our documentation.

If you find inconsistencies, only address it if the inconsistency is introduced by the changes under review.
If this inconsistency is introduced by the changes under review, suggest revisions to the documentation to reflect the
implementation as it would exist if the changes were merged.

## Failure Analysis

If the workflow fails, include links to or excerpts from relevant logs from the failed workflow run in your comments.
Suggest a fix if your are confident that you understand the root cause and you are confident in your fix.
In this event, cite the relevant part of the failed workflow's logs and summarize the reasoning you used when composing
the fix.

If you don't have a fix or have low confidence about a fix, compose a short summary of the relevant events in the failed
workflow run.
Only comment in this way if you are confident that you understand the events which occurred in the workflow run.
Include links to or excerpts from the relevant logs to support your analysis if relevant.

## Future work

If the PR under review notes the need for future work or fixes, compose a comment with the contents of the github issue
you would write to describe the required work.
This comment should

1. begin with a yaml formatted block which includes the title of the issue and any appropriate labels used by this
   repository.
2. an array which suggests links to any other open and relevant issues or pull requests you find
   - in this repository
   - in the [dpdk-sys repository][dpdk-sys]
   - in the [gateway-proto repository][gateway-proto]
   - in the [gateway repository][gateway]
   - in the [testn repository][testn]
   - in the [dplane-rpc repository][dplane-rpc]
3. followed by a fenced code block in markdown format describing the suggested work to be done.

If the PR under review is updated, do not compose a new issue comment.
Edit the extant issue comment instead.

## Comment metadata

Preface your comments with a fenced yaml block in the following format

```yaml
confidence: <confidence>
tags: [<tags array>]
```

Where `<confidence>` is a measure from 0 to 10 based on your confidence in the quality or correctness of your
comment.
Zero indicates low confidence or uncertainty, 10 indicates high confidence or certainty.

`<tags array>` is an array of strings representing the tags associated with the comment.

Valid tags include:

- `logic`
- `style`
- `docs`
- `failure-analysis`
- `other`

And should be included based on the section or sections of this file which directed you to make such a comment.
Multiple tags may apply to a single comment.

If you decide to comment on something that is not covered by the above categories, mark the comment as `other`.
The `other` tag should only be used if no other tag is appropriate.

[dev-guide]: ../development/README.md
[dpdk-sys]: https://github.com/githedgehog/dpdk-sys
[gateway-proto]: https://github.com/githedgehog/gateway-proto
[gateway]: https://github.com/githedgehog/gateway
[testn]: https://github.com/githedgehog/testn
[dplane-rpc]: https://github.com/githedgehog/dplane-rpc

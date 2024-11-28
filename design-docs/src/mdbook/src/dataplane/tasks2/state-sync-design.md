# State sync (design)

My major objection to this, as an issue, is that we are inherently eventually consistent (if consistent at all) in the two actor model.
It seems like we are setting ourselves up for the famous [Byzantine General's Problem](https://en.wikipedia.org/wiki/Byzantine_fault).

> [!WARNING]
> Here be dragons!

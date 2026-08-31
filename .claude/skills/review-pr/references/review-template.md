# Review report template

Use this structure exactly. Drop empty sections rather than writing "None" in
three of them.

---

## PR #<N> — <title>

**Author:** @<login> (<N> prior merged PRs to this repo, or "first contribution")
**Scope:** <X> files, +<A>/−<D>, <N> commits
**Claims:** one line on what the description says it does

### Verdict

One of: **Merge**, **Merge after fixes**, **Needs discussion**, **Do not merge** —
followed by one sentence of why. Put this first so the maintainer can stop reading
here if they want to.

### Checks

| Check | Result |
| --- | --- |
| CI on GitHub | passed / not run (fork) / failed |
| `make lint` | pass / N errors |
| `make test` | N passed, N failed |
| Coverage on changed lines | X% |
| Working tree clean after tests | yes / files left behind: … |
| New tests fail on `main` | verified / not verified / no new tests |

Paste the failing output for anything that isn't a pass, trimmed to the relevant
lines.

### Blocking

Numbered. Each one: `file:line` — what's wrong — why it matters — suggested fix.
Be specific enough that the contributor can act without a follow-up question.

### Should fix

Same format. Things worth a round trip but not worth blocking on if the
maintainer is in a hurry.

### Nits

One line each. No file:line needed.

### Questions for the contributor

Things that might be intentional. Ask rather than assert.

### What's good here

Genuinely — name the specific things done well. This is the part that makes
contributors come back, and it costs two lines.

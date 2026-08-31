# Installing the review-pr skill

The skill is one folder. Both Claude Code and Antigravity read the same
`SKILL.md` format, they just look in different directories.

| Agent | Workspace path |
| --- | --- |
| Claude Code | `.claude/skills/review-pr/` |
| Antigravity | `.agents/skills/review-pr/` (older versions: `.agent/skills/`) |

## One copy, two paths

Keep the real files in one place and symlink the other, so a fix to the checklist
lands in both agents at once:

```bash
cd /path/to/driftsentry

mkdir -p .claude/skills .agents
cp -r review-pr .claude/skills/review-pr
chmod +x .claude/skills/review-pr/scripts/pr_setup.sh

mkdir -p .agents/skills
ln -s ../../.claude/skills/review-pr .agents/skills/review-pr

git add .claude .agents
git commit -m "chore: add review-pr skill for Claude Code and Antigravity"
```

Git stores the symlink fine. If you ever review from Windows without
`core.symlinks` enabled, replace the `ln -s` with a second `cp -r` and re-copy
when the skill changes.

## Check it works

Claude Code:

```
/skills          # review-pr should be listed
```

Then, in the repo, say something like *"review PR #4"*. The skill triggers on
mentions of PRs, contributions, forks, or `#<number>` — you shouldn't need to name
it. If it doesn't fire, `use the review-pr skill to review PR #4` forces it.

Antigravity discovers skills at conversation start and picks them up by
description in the same way.

## Requirements

- `gh` CLI, authenticated (`gh auth status`)
- Python 3.12 and `make`
- A clean main working tree — the setup script creates a sibling worktree at
  `../driftsentry-pr-<N>/`, so make sure that path is writable

## Making it yours

`references/driftsentry-checklist.md` is the part worth editing over time. Every
time a review catches something the checklist missed, add it. That file is the
actual asset here; the workflow around it is scaffolding.

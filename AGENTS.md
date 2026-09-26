# AGENTS.md

Rules for working in this repository. Every one is traceable to a statement the
repo already makes; nothing here is invented policy. Citations are `path:line` and
are meant to be checked, not trusted.

## Verify before you claim

The gate is one command, and it is the same one CI runs
(`astrolabe/cli.py:1462-1475`):

```
uv run --extra dev --extra browser-auth astrolabe check
```

It runs `ruff check tests/ astrolabe/`, `ruff format --check tests/`,
`mypy tests astrolabe`, then `pytest` under a coverage floor
(`pyproject.toml:82`). A change is not done until that command passes.

**Both extras are load-bearing, and dropping one is destructive.** They are optional
extras (`pyproject.toml:49-50`), so a bare `uv run` or `uv sync` re-syncs to the
default selection and *removes* packages rather than adding them.
`uv run --extra dev astrolabe check` — the obvious-looking command — takes pytest,
ruff and mypy with it, and the gate cannot run. Adding `--extra browser-auth`
brings `publicsuffixlist`, `secretstorage` and `cryptography`, which
`tests/test_browser_cookies.py` exercises for real: those tests are not skipped when
the extra is absent, so a run without it fails. Worse, `uv sync --extra dev
--extra browser-auth` still prunes `cloakbrowser` (the `stealth` extra), which
silently turns the browser e2e into skips — a green suite that tests nothing. Add
`--extra stealth` when you want the browser tests to run locally, and never run a
bare `uv run` to "just check something".

A test that has never been observed to fail is not a passing test. When you add or
change one, break the behaviour on purpose, watch it go red, and revert. This repo
keeps that discipline in its own history and it is the whole point of the
`misleading_success_output` class.

## Safety boundary

Default generation and execution expose only operations classified as queries from
trusted evidence (`README.md:9-13`). Persisted or unknown operations are
inventory-only; recipes are executable code and require explicit trust
acknowledgement. Historical example artifacts are documentation, not contracts.

Shape-only capture is the guarantee: no payload values are persisted, credentials
never enter a generated chart, and the operator allowlists default to empty. Do not
weaken `verification_allowed` (`astrolabe/operation.py:71-88`), the
`semantic_kind == "query"` guard (`astrolabe/mcp_server.py:2794`), the allowlists, or
the shape-only guarantee to make a test pass.

These controls reduce accidental disclosure; they do not make the tool impossible
to misuse. The operator, OS account, browser, keyring, dependencies and the
configured server process are trusted (`docs/relay-and-browser-auth.md:44-51`). Do
not soften or delete that block when editing the security doc — reference it.

## Operator-owned configuration

`ASTROLABE_BROWSER_AUTH_DOMAINS`, `ASTROLABE_SESSION_DOMAINS`,
`ASTROLABE_CDP_ENDPOINTS` and `ASTROLABE_BROWSER_EGRESS` are operator config, read
from the environment, empty by default (`docs/relay-and-browser-auth.md:7-13`). No
tool argument may select or widen any of them. An agent able to widen its own
authorization envelope makes the gate meaningless, and a comment saying so is not a
control — there is a test that asserts each tool's input schema omits these.

## Lint debt shrinks, never grows

`pyproject.toml:94-96`: the ruff per-file-ignore list is an inherited baseline.
"Shrink this list as debt is paid down; never add newly-introduced codes to it."
Each remaining code carries its measured violation count in the comment above it.
Never add a code; never silence a finding with a narrower ignore or a blanket
`noqa` to make a removal look clean.

An optional dependency imported under a runtime `try/except ImportError` gets a
`[[tool.mypy.overrides]]` entry rather than an inline ignore, because the gate has
to type-check without the extra installed (`pyproject.toml`, the
`publicsuffixlist` block). A developer venv that happens to carry the extra will
keep mypy green through a change a clean checkout rejects — verify from a clean
environment before you call the gate passing.

## Generated output never lands in the repo

Run outputs, Charts and captures are gitignored (`astrolabe-*/`, `chart-*/`,
`.gitignore:11-13`) and belong in `ASTROLABE_WORKSPACE`, defaulting to
`$XDG_DATA_HOME/astrolabe` (`README.md:111`). Tests that need a Chart read a
committed synthetic fixture under `tests/fixtures/`, never a generated capture. A
developer re-running a capture must not be able to change a fixture a test reads as
a regression suite.

## Commit and scope

Conventional commits, matching the existing history. Stage explicit paths; never
`git add -A` or `git add .`, because generated run output is untracked but present
and a broad add will sweep it in. Never commit secrets, cookies, HARs or captured
target material. One concern per commit. Do not reformat or refactor code outside
the change you were asked for — the repo's own history includes a commit whose
entire content was a drive-by reformat of lines a previous change left long.

Do not claim a performance win without a measurement, and do not claim a CI gate
that has never executed. If you cannot verify something, say so plainly rather than
asserting it.

# AGENTS.md

Operational notes for this repository: commands, layout, recipes, traps and a
dev diary. Dates are UTC. Everything here is about `astrolabe` only.

## Gate

```sh
uv run --extra dev --extra browser-auth --extra stealth astrolabe check
```

`astrolabe check` runs, in order:

1. `ruff check tests/ astrolabe/`
2. `ruff format --check tests/`
3. `mypy tests astrolabe`
4. `pytest` with `--cov=astrolabe --cov-fail-under=70`

Failure prints `astrolabe: validation: quality gate <step> failed` and exits 9.

### Extras

All three are optional groups in `pyproject.toml`, so **any `uv run` or
`uv sync` that omits one prunes it from the environment.**

| extra | brings | if missing |
|---|---|---|
| `dev` | pytest, ruff, mypy, coverage | gate cannot run |
| `browser-auth` | `publicsuffixlist`, `secretstorage`, `cryptography` | `tests/test_browser_cookies.py` fails (not skipped) |
| `stealth` | `cloakbrowser` | browser e2e silently skips — green suite, nothing tested |

Fresh clone:

```sh
uv sync --extra dev --extra browser-auth --extra stealth
```

### Venv

Symptom of a stale venv: `uv run pytest` resolves to system Python and dies in
collection, or a `.venv/bin/*` entrypoint carries a shebang pointing at a
directory that no longer exists.

```sh
rm -rf .venv && uv sync --extra dev --extra browser-auth --extra stealth
```

Verify with `head -1 .venv/bin/astrolabe` — it should be a `#!/bin/sh` wrapper,
not an absolute path into another checkout.

## Layout

| path | what it is |
|---|---|
| `astrolabe/cli.py` | the 16-subcommand CLI; `ExitCode` enum at `:217` |
| `astrolabe/server.py` | the single MCP server: mapping tools + execution mounted |
| `astrolabe/mapping_mcp.py` | capture/mapping tools (`map_site`, `scan_site`, `generate_chart`, …) |
| `astrolabe/sextant.py` | execution engine: `Runtime`, GraphQL/APQ/REST dispatch, `search_tools`/`call_tool` |
| `astrolabe/capture.py` | the browser capture engine (2.1k lines) |
| `astrolabe/browser.py` | pluggable backend: `playwright` \| `cloakbrowser`, CDP attach |
| `astrolabe/fetch.py` | `astrolabe fetch` controller (ported from `cffetch`) |
| `astrolabe/fetch_driver.py` | the fetch driver process; runs under `ip netns` for `--netns` |
| `astrolabe/envfile.py` | the only reader of `.env` |
| `astrolabe/security.py` | sanitizers, egress policy, `capture_fidelity()` |
| `astrolabe/toolpack.py` | pack schema + `Settings`; the one pack validator |
| `astrolabe/transport.py` | shared retry policy |
| `tests/test_mcp_surface_baseline.py` | frozen tool lists, exact literals |

## Servers

One server, one surface:

```jsonc
"mcp": {
  "astrolabe": {
    "type": "local",
    "command": ["/abs/path/to/astrolabe/.venv/bin/astrolabe-mcp"],
    "cwd": "/abs/path/to/astrolabe",
    "environment": { "ASTROLABE_TOOLPACKS": "/home/<you>/.local/share/astrolabe" },
    "enabled": true
  }
}
```

- `command` must stay an array — this repo's path contains a space.
- 13 tools: 11 mapping + `search_tools` + `call_tool`.
- `astrolabe-mapping-mcp` and `sextant-mcp` still exist as narrower entrypoints.
- Legacy `fastmcp` V1 config style is `mcp.<name>`; V2 is `mcp.servers.<name>`.

**Symptom: `search_tools` returns 0 operations.** The execution half reads
`ASTROLABE_TOOLPACK` / `ASTROLABE_TOOLPACKS` only; it has no default workspace
discovery. `list_charts` in the mapping half does. Set `ASTROLABE_TOOLPACKS` to
the workspace or to a comma-separated list of chart dirs.

## Recipes

### Add a CLI subcommand

1. Write `cmd_<name>(a)` above `build_parser()` in `astrolabe/cli.py`.
2. Register it in `build_parser()`; use `parents=[machine]` for `--json`.
3. Add the name to the expected set in `tests/test_cli.py::test_all_subcommands_registered`.
4. If it owns many flags, put them in a module function and call it from
   `build_parser()` — see `fetch.add_arguments`.

### Add an MCP tool

1. Decorate a function in `astrolabe/mapping_mcp.py` (capture) or
   `astrolabe/sextant.py` (execution, behind `call_tool`).
2. Add the name to `MAPPING_TOOL_NAMES` or the unified list in
   `tests/test_mcp_surface_baseline.py`; that file pins exact literals on purpose.
3. If it takes an operator setting (egress, allowlists), do not add the argument —
   there is a test asserting none is exposed.

### Port a helper in from another tool

1. Put the controller in its own module (`astrolabe/<name>.py`); keep any
   subprocess half in a second module.
2. Keep the existing exit-code/JSON contract if anything already calls it.
   `cli.main` remaps `SystemExit` onto its own enum; a contract that must survive
   that sets `passthrough = True` on the exception (see `fetch.FetchExit`).
3. Credentials go to `.env` via `astrolabe/envfile.py`, never into `os.environ`.
4. If the module is capture-side, leave `sextant.py` alone: the unified server
   imports it, and nothing enforces the old import split any more.
5. Prove the port against the old tool: same flags, same verdict, same exit code.

### Prove a test is real

Break the behaviour on purpose, run the single test, watch it fail, revert.
A test never observed failing is not evidence.

```sh
.venv/bin/python -m pytest tests/test_fetch.py::<name> -q --no-cov
```

### Serve locally without a client

```sh
python3 /tmp/mcp_probe.py .venv/bin/astrolabe-mcp        # init + tools/list
python3 /tmp/mcp_call.py  .venv/bin/astrolabe-mcp -- list_charts '{}'
```

## Traps

| symptom | cause | fix |
|---|---|---|
| gate can't find pytest/mypy | a `uv run` without all three extras pruned them | `uv sync` with all three |
| browser e2e all skipped | `stealth` extra absent | add `--extra stealth` |
| collection error, Python 3.14 from `/usr` | broken `.venv` shebangs | rebuild the venv |
| `search_tools` → 0 ops | no `ASTROLABE_TOOLPACKS` | point it at the workspace |
| `list_charts` and `search_tools` disagree | two discovery paths (known debt) | set `ASTROLABE_TOOLPACKS` explicitly |
| repo is 850 MB | charts captured into the repo root | `ASTROLABE_WORKSPACE` / move them out |
| `git add -A` stages junk | 100+ untracked `chart-*` dirs | stage explicit paths |

## Conventions

- Conventional commits, lowercase scope: `feat(fetch): …`, `fix(sextant): …`.
- One concern per commit; stage explicit paths, never `git add -A`.
- Generated output belongs in `ASTROLABE_WORKSPACE`
  (default `$XDG_DATA_HOME/astrolabe`), never in the repo.
- Tests that need a Chart read `tests/fixtures/`, never a live capture.
- Never commit cookies, HARs, `auth.headers.json` or captured target material.
- Ruff per-file-ignores in `pyproject.toml` are an inherited baseline: shrink,
  never add. Each code carries its measured count in the comment above it.
- Optional imports guarded by `try/except ImportError` get a
  `[[tool.mypy.overrides]]` entry, not an inline ignore.
- Coverage floor is 70; raise the floor when the suite measures higher, never lower it.

## Dev diary

### 2026-11-19

- `0f11db2` `feat(fetch)`: ported `cffetch` into `astrolabe/fetch.py` +
  `astrolabe/fetch_driver.py`. Same JSON verdict and 0/1/2/3/4 exit contract;
  `FetchExit.passthrough` survives `cli.main`'s remap. Added the bot-wall vendor
  taxonomy (perimeterx/datadome/akamai/kasada) that astrolabe lacked; fixed
  Akamai matching, which compared a lowercase needle to the raw `Server` header.
- `9cc8421` `docs(fetch)`: README, AGENTS and the security doc.
- Added `astrolabe/envfile.py` + `.env.example`: operator credentials in a
  gitignored `.env`, returned as a dict, never written into `os.environ`.
- Rebuilt `.venv`; the old entrypoints pointed at a deleted checkout.
- `~/.local/bin/cffetch` is now a shim to `astrolabe fetch`. The 304-line
  original was overwritten before a copy was taken; `cffetch.bak.20261023-223422`
  is an earlier iteration, and `~/.local/libexec/cffetch/netns_fetch.py` is intact.
- Unified server: `astrolabe/server.py` mounts the execution surface onto the
  mapping server, so one entrypoint exposes 13 tools. The import-closure split
  was packaging, not a product boundary.

### 2026-10-01

- `53768bd` collapsed the per-Chart servers into one sextant host; per-Chart
  surfaces stay internal behind `search_tools`/`call_tool`.
- `91adb33` fixed namespace collisions: newest pack wins, older ones are skipped
  and reported at `astrolabe://manifest`.

### 2026-09-27

- `656732a` one shared retry policy in `transport.py`; permanent verdicts are no
  longer retried.

### 2026-09-26 / 09-25

- `b28ed69`, `813d973` replaced generated chart fixtures with a committed
  synthetic pack; the surface baseline pins exact literals against it.
- `d8b1550` added this file and documented the verification command.
- `bc0bbfe` closed gate gaps: CDP endpoint validation, CI skip reporting.

## Open debt

- `sextant.py` and `mapping_mcp.py` each implement "where are the Charts":
  `_collect_toolpack_paths`/`_configured_roots` vs `list_charts`'s glob. They
  disagree when `ASTROLABE_TOOLPACKS` is unset. Hoisting both into `toolpack.py`
  is the fix.
- `_code_root` (`sextant.py`) is a verbatim copy of `code_root` (`mapping_mcp.py`).
- `_chart_server_for` mutates `os.environ` to reuse `Settings.from_env`.
- `warm.py` has no test (0% coverage).
- Native browser decryption is implemented on Linux only.
- `scripts/ig_*.py` are untracked and dogfood a known capture gap: Relay SSR
  preloads fire no XHR, so they are never observed.

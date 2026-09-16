#!/usr/bin/env python3
"""astrolabe recipe — the reference contract + linter for per-site recipe modules.

A recipe is preferably bounded declarative JSON. The legacy
`surfaces/<domain>.recipe.py` escape hatch is imported by `recipe_worker.py`
inside a bubblewrap process with no network or host filesystem, then drives the
browser through the allowlisted RPC in `recipe_runtime.py`.
Over several iterations that interface has accreted attributes ad hoc --
SURFACES, drive(), ACTIVE_PROBES, SESS_HEADERS, SESS_HEADER_HARVEST, and most
recently AUTH_HEADERS / AUTH_HEADER_PATTERN -- and nowhere named the whole
thing at once. `RecipeModule` below is that reference. Every attribute is
OPTIONAL: a recipe defines whatever subset it needs; capture.py reads each one
with getattr()/hasattr() and treats an absent attribute as "not used".

## The recipe interface

  SURFACES: list[str]
      URLs `astrolabe.capture.main()` visits up front, one navigation + settle
      wait per URL, before drive()/ACTIVE_PROBES/introspection run. This is
      the primary way a recipe seeds pages the passive capture should see.

  def drive(page, log) -> None
      Optional custom interaction after SURFACES have all been visited (and
      before the optional --crawl pass, so actions start on the last surface): drive search filters, open pagers,
      scroll feeds, land on nested settings pages -- anything a plain page
      visit can't reach. `page` is the live cloakbrowser Page (Playwright-like
      API: page.goto/eval_on_selector_all/wait_for_timeout/...); `log` is a
      one-arg callable for progress lines. Exceptions inside drive() are
      caught by capture.py and logged, not fatal -- a broken drive() degrades
      to a partial-but-complete map rather than losing the whole capture.

  ACTIVE_PROBES: list[dict]
      Endpoints fired directly through the page's own fetch() context (after
      SURFACES + drive()), using session headers harvested from the SPA's own
      XHRs. Use this for endpoints the SPA's own navigation never triggers,
      or targets that mint a session token client-side that a bare HTTP
      client can't reproduce. Each entry: {"url": str, "method": str = "GET",
      "body": dict | None}. `url` is required; capture.py does `probe["url"]`
      with no default and raises KeyError if it's missing.

  SESS_HEADERS: dict[str, str]
      Extra request headers, as literal values, added to every ACTIVE_PROBES
      fetch call. Use for headers a recipe already knows the value of (a
      stable public API key, an app-id header) rather than one that has to be
      harvested from the live page.

  SESS_HEADER_HARVEST: dict[str, str]
      Maps a header name to a JavaScript expression (a string), evaluated in
      the page context (`page.evaluate(f"() => {expr}")`) to pull a session
      value the SPA minted client-side -- e.g.
      {"x-api-key": "localStorage.getItem('apiKey')"}. Evaluated once, after
      drive(), before ACTIVE_PROBES fire.

  AUTH_HEADERS: list[str]
      Extra exact header names, beyond capture.py's generic defaults
      (AUTH_HEADER_NAMES_DEFAULT), that should always be treated as part of
      this site's auth/client-identification surface. Purely additive --
      cannot disable a default. See capture.build_auth_matcher().

  AUTH_HEADER_PATTERN: str
      An extra regex (OR'd into capture.AUTH_HEADER_PATTERN_DEFAULT via
      re.compile) for auth-header detection by name pattern rather than exact
      match. Purely additive, same as AUTH_HEADERS. Must compile as a Python
      regex.

## SECURITY / TRUST BOUNDARY -- READ BEFORE RUNNING THE LINTER ON UNTRUSTED INPUT

A Python recipe file is executable code, and recipe
files come from two places that are NOT inherently trustworthy: `astrolabe scan`
scaffolds (deterministic, but built from whatever a site's own sitemap/HTML
contains) and recipes handed to you by someone else. Linting must not require
running that code.

`lint_recipe()` -- the default, and the only path `main()` calls -- NEVER
imports the recipe. It parses the file with `ast.parse()` and inspects the
syntax tree, so it is safe to run on a recipe you have not reviewed: at worst
a malformed file fails to parse.

`lint_recipe_dynamic()` is a separate, explicitly opt-in function that DOES
import the recipe in the linter process to answer the handful of questions static
analysis cannot -- e.g. the true call signature of a `drive` that isn't a
plain top-level `def` (built by a decorator or factory). Nothing in this
module calls it automatically. Call it only on a recipe you would already be
willing to import without Astrolabe's normal sandbox. Normal capture does not use
this dynamic linter.
"""

from __future__ import annotations

import argparse
import ast
import difflib
import json
import re
import sys
from dataclasses import dataclass
from typing import Any, Literal, Protocol

Severity = Literal["error", "warning", "info"]

DECLARATIVE_RECIPE_VERSION = 1
DECLARATIVE_ACTIONS = frozenset(
    {"scroll", "click", "search", "wait", "wait_for", "press", "select"}
)
# Actions that change page state must say why they are safe to perform.
ANNOTATED_ACTIONS = frozenset({"click", "search", "press", "select"})
SELECTOR_ACTIONS = frozenset({"click", "search", "press", "select", "wait_for"})
PRESS_KEYS = frozenset({"Enter", "Tab", "Escape", "ArrowDown", "ArrowUp", "Space"})
MAX_DECLARATIVE_ACTIONS = 50
MAX_SELECTOR_WAIT_MS = 15_000


@dataclass(frozen=True)
class DeclarativeRecipe:
    SURFACES: list[str]
    ACTIONS: list[dict[str, Any]]
    ACTIVE_PROBES: list[dict[str, Any]]
    declarative = True

    def drive(self, page: Any, log: Any, interaction: Any = None, settle: Any = None) -> None:
        """Run each action, then let the page's API traffic settle before the next.

        Without the settle step a click that fires an XHR is immediately followed by
        the next action (or the end of the recipe), and the response it caused is
        attributed to the wrong interaction or never observed at all.
        """
        for index, action in enumerate(self.ACTIONS):
            kind = action["action"]
            annotation = action.get("safe_annotation", "bounded read-only action")
            if action.get("optional") and not _selector_appears(page, action):
                log(f"[declarative] {index + 1}/{len(self.ACTIONS)} {kind}: skipped (absent)")
                continue
            if interaction:
                interaction("input" if kind in {"search", "select"} else kind, annotation)
            if kind == "wait":
                page.wait_for_timeout(action["milliseconds"])
            elif kind == "wait_for":
                page.wait_for_selector(action["selector"], timeout=action["timeout_ms"])
            elif kind == "scroll":
                page.evaluate("pixels => window.scrollBy(0, pixels)", action["pixels"])
            elif kind == "click":
                page.click(action["selector"], timeout=action["timeout_ms"])
            elif kind == "press":
                page.press(action["selector"], action["key"], timeout=action["timeout_ms"])
            elif kind == "select":
                page.select_option(
                    action["selector"], action["value"], timeout=action["timeout_ms"]
                )
            elif kind == "search":
                page.fill(action["selector"], action["value"], timeout=action["timeout_ms"])
                if action.get("submit"):
                    page.press(action["selector"], "Enter", timeout=action["timeout_ms"])
            if settle and kind not in {"wait", "wait_for"}:
                settle(kind)
            log(f"[declarative] {index + 1}/{len(self.ACTIONS)} {kind}: {annotation}")


def _selector_appears(page: Any, action: dict[str, Any]) -> bool:
    try:
        page.wait_for_selector(action["selector"], timeout=action["timeout_ms"])
    except Exception:
        return False
    return True


def load_declarative_recipe(path: str) -> DeclarativeRecipe:
    """Parse a bounded JSON recipe as data; never import or execute supplied code."""
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read declarative recipe: {exc}") from exc
    return parse_declarative_recipe(value)


def parse_declarative_recipe(value: Any) -> DeclarativeRecipe:
    """Validate an in-memory declarative recipe; the single source of its rules."""
    if not isinstance(value, dict) or value.get("schema_version") != DECLARATIVE_RECIPE_VERSION:
        raise ValueError("declarative recipe requires schema_version 1")
    surfaces = value.get("surfaces") or []
    actions = value.get("actions") or []
    probes = value.get("active_probes") or []
    if not isinstance(surfaces, list) or not all(isinstance(item, str) for item in surfaces):
        raise ValueError("declarative recipe surfaces must be an array of URLs")
    if not isinstance(actions, list) or not all(isinstance(item, dict) for item in actions):
        raise ValueError("declarative recipe actions must be an array of objects")
    if len(actions) > MAX_DECLARATIVE_ACTIONS:
        raise ValueError(f"declarative recipe allows at most {MAX_DECLARATIVE_ACTIONS} actions")
    normalized_actions = [_normalize_action(index, action) for index, action in enumerate(actions)]
    if not isinstance(probes, list) or not all(isinstance(item, dict) for item in probes):
        raise ValueError("declarative recipe active_probes must be an array of objects")
    normalized_probes = []
    for index, probe in enumerate(probes):
        if not isinstance(probe.get("url"), str):
            raise ValueError(f"active probe {index} requires url")
        method = str(probe.get("method") or "GET").upper()
        if method not in {"GET", "HEAD", "OPTIONS"}:
            raise ValueError(f"active probe {index} method {method} is not read-only")
        normalized_probes.append({"url": probe["url"], "method": method})
    return DeclarativeRecipe(list(surfaces), normalized_actions, normalized_probes)


def _normalize_action(index: int, action: dict[str, Any]) -> dict[str, Any]:
    kind = action.get("action")
    if kind not in DECLARATIVE_ACTIONS:
        raise ValueError(f"action {index} has unsupported action {kind!r}")
    normalized = dict(action)
    if kind in ANNOTATED_ACTIONS and not normalized.get("safe_annotation"):
        raise ValueError(f"action {index} requires safe_annotation")
    if kind in SELECTOR_ACTIONS:
        selector = normalized.get("selector")
        if not isinstance(selector, str) or not 1 <= len(selector) <= 500:
            raise ValueError(f"action {index} requires selector")
    if kind == "search":
        search_value = normalized.get("value")
        if not isinstance(search_value, str) or not 1 <= len(search_value) <= 100:
            raise ValueError(f"action {index} search value must contain 1-100 characters")
    if kind == "select":
        option = normalized.get("value")
        if not isinstance(option, str) or not 1 <= len(option) <= 200:
            raise ValueError(f"action {index} select value must contain 1-200 characters")
    if kind == "press" and normalized.get("key") not in PRESS_KEYS:
        raise ValueError(f"action {index} key must be one of {sorted(PRESS_KEYS)}")
    if "optional" in normalized and not isinstance(normalized["optional"], bool):
        raise ValueError(f"action {index} optional must be a boolean")
    if normalized.get("optional") and kind not in SELECTOR_ACTIONS - {"wait_for"}:
        raise ValueError(f"action {index} only selector actions can be optional")
    if kind in SELECTOR_ACTIONS:
        normalized["timeout_ms"] = min(
            max(int(normalized.get("timeout_ms", 5000)), 0), MAX_SELECTOR_WAIT_MS
        )
    if kind == "wait":
        normalized["milliseconds"] = min(max(int(normalized.get("milliseconds", 500)), 0), 5000)
    if kind == "scroll":
        normalized["pixels"] = min(max(int(normalized.get("pixels", 800)), -5000), 5000)
    return normalized


@dataclass(frozen=True)
class ActiveProbe:
    """One entry of ACTIVE_PROBES: an endpoint fired directly through the
    page's fetch() context, after passive capture + drive() finish."""

    url: str
    method: str = "GET"
    body: dict[str, Any] | None = None


class RecipeModule(Protocol):
    """The full recipe interface capture.load_recipe() understands. A real
    recipe module defines any subset of these -- everything is optional, and
    capture.py reads each one defensively (getattr/hasattr with a default).
    This Protocol exists as a typed, single-source reference for the
    attributes named in the module docstring above; it is not used to
    type-check a loaded module at runtime (a dynamically exec'd module isn't
    statically checkable that way) -- lint_recipe() below is the runtime
    check.
    """

    SURFACES: list[str]
    ACTIVE_PROBES: list[dict[str, Any]]
    SESS_HEADERS: dict[str, str]
    SESS_HEADER_HARVEST: dict[str, str]
    AUTH_HEADERS: list[str]
    AUTH_HEADER_PATTERN: str

    def drive(self, page: Any, log: Any) -> None: ...


# Attribute/function names lint_recipe() understands. Anything else at module
# level is a recipe's own business (constants like BASE, helper functions
# like _try/hop, imports, ...) -- never flagged, except when it's suspiciously
# close to one of these (see _typo_findings()).
KNOWN_ATTRS = frozenset(
    {
        "SURFACES",
        "ACTIVE_PROBES",
        "SESS_HEADERS",
        "SESS_HEADER_HARVEST",
        "AUTH_HEADERS",
        "AUTH_HEADER_PATTERN",
    }
)
KNOWN_FUNCS = frozenset({"drive"})

# Cutoffs picked empirically against the real recipes in surfaces/*.recipe.py:
# high enough that genuine site-specific constants (BASE, API, REST_CATALOG,
# SEARCH_QUERIES, SOCKETIO_URL, ...) and helper functions (hop, _try, _hrefs,
# _abs, ...) never false-positive, low enough that real typos (SURFACE,
# ACTIVE_PROBE, AUTH_HEADER, SESS_HEADER, drve, Drive, driver) are always
# caught. See tests/test_recipe.py for the calibration cases.
ATTR_TYPO_CUTOFF = 0.72
FUNC_TYPO_CUTOFF = 0.6


@dataclass(frozen=True)
class Finding:
    """One linter result. `attr` is the recipe attribute this finding is
    about (None for file-level findings, e.g. a syntax error)."""

    severity: Severity
    attr: str | None
    message: str
    line: int | None = None

    def __str__(self) -> str:
        where = f"{self.attr} " if self.attr else ""
        at = f" (line {self.line})" if self.line else ""
        return f"[{self.severity}] {where}{self.message}{at}"


def _literal_str(node: ast.expr) -> str | None:
    """Return node's string value if it is a plain string constant or a
    static f-string with no interpolated expressions; None if the value
    can't be determined without executing the file."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr) and all(
        isinstance(v, ast.Constant) and isinstance(v.value, str) for v in node.values
    ):
        return "".join(v.value for v in node.values if isinstance(v, ast.Constant))  # type: ignore[misc]
    return None


def _type_name(node: ast.expr) -> str:
    if isinstance(node, ast.Constant):
        return type(node.value).__name__
    return type(node).__name__


def _check_string_list(name: str, node: ast.expr, findings: list[Finding]) -> None:
    """SURFACES / AUTH_HEADERS: expect a list/tuple of strings. Only flags
    what's staticaly certain -- an element built from a Call/Name/BinOp (an
    f-string referencing another constant, a computed value, ...) is common
    in real recipes and is left unverified rather than guessed at."""
    if isinstance(node, (ast.List, ast.Tuple)):
        for i, el in enumerate(node.elts):
            if isinstance(el, ast.Constant) and not isinstance(el.value, str):
                findings.append(
                    Finding(
                        "error",
                        name,
                        f"{name}[{i}] must be a string, got {_type_name(el)}",
                        getattr(el, "lineno", None),
                    )
                )
            elif isinstance(el, (ast.List, ast.Tuple, ast.Dict, ast.Set)):
                findings.append(
                    Finding(
                        "error",
                        name,
                        f"{name}[{i}] must be a string, got {type(el).__name__}",
                        getattr(el, "lineno", None),
                    )
                )
        if not node.elts:
            findings.append(
                Finding("info", name, f"{name} is an empty list", getattr(node, "lineno", None))
            )
    elif isinstance(node, (ast.Dict, ast.Constant, ast.Set)):
        findings.append(
            Finding(
                "error",
                name,
                f"{name} must be a list of strings, got {_type_name(node)}",
                getattr(node, "lineno", None),
            )
        )
    # else: built dynamically (Call/Name/BinOp/comprehension/...) -- can't
    # verify statically, not flagged.


def _check_str_dict(name: str, node: ast.expr, findings: list[Finding]) -> None:
    """SESS_HEADERS / SESS_HEADER_HARVEST: expect a dict literal with string
    keys. Values are left unchecked (SESS_HEADER_HARVEST's values are JS
    expression strings; SESS_HEADERS' values are header values, sometimes a
    reference to a runtime-computed secret)."""
    if isinstance(node, ast.Dict):
        for k in node.keys:
            if k is not None and not (isinstance(k, ast.Constant) and isinstance(k.value, str)):
                findings.append(
                    Finding(
                        "error",
                        name,
                        f"{name} keys must be strings, got {_type_name(k)}",
                        getattr(k, "lineno", None),
                    )
                )
    elif isinstance(node, (ast.List, ast.Tuple, ast.Constant, ast.Set)):
        findings.append(
            Finding(
                "error",
                name,
                f"{name} must be a dict, got {_type_name(node)}",
                getattr(node, "lineno", None),
            )
        )


def _check_active_probes(node: ast.expr, findings: list[Finding]) -> None:
    if not isinstance(node, (ast.List, ast.Tuple)):
        if isinstance(node, (ast.Dict, ast.Constant, ast.Set)):
            findings.append(
                Finding(
                    "error",
                    "ACTIVE_PROBES",
                    f"ACTIVE_PROBES must be a list of dicts, got {_type_name(node)}",
                    getattr(node, "lineno", None),
                )
            )
        return
    for i, el in enumerate(node.elts):
        if not isinstance(el, ast.Dict):
            continue  # built dynamically -- can't verify statically
        keys = {
            k.value for k in el.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)
        }
        literals = {
            k.value: v.value
            for k, v in zip(el.keys, el.values, strict=False)
            if isinstance(k, ast.Constant)
            and isinstance(k.value, str)
            and isinstance(v, ast.Constant)
        }
        if "url" not in keys:
            findings.append(
                Finding(
                    "error",
                    "ACTIVE_PROBES",
                    f"ACTIVE_PROBES[{i}] is missing the required 'url' key "
                    "(capture.py does probe['url'] with no default -- this "
                    "raises KeyError at capture time)",
                    getattr(el, "lineno", None),
                )
            )
        method = str(literals.get("method") or "GET").upper()
        if method not in {"GET", "HEAD", "OPTIONS"} and not (
            literals.get("allow_write") is True and isinstance(literals.get("safe_annotation"), str)
        ):
            findings.append(
                Finding(
                    "error",
                    "ACTIVE_PROBES",
                    f"ACTIVE_PROBES[{i}] {method} requires allow_write=True and safe_annotation",
                    getattr(el, "lineno", None),
                )
            )
        for k, v in zip(el.keys, el.values, strict=False):
            if (
                isinstance(k, ast.Constant)
                and k.value == "method"
                and isinstance(v, ast.Constant)
                and not isinstance(v.value, str)
            ):
                findings.append(
                    Finding(
                        "error",
                        "ACTIVE_PROBES",
                        f"ACTIVE_PROBES[{i}]['method'] must be a string, got {_type_name(v)}",
                        getattr(v, "lineno", None),
                    )
                )
            if (
                isinstance(k, ast.Constant)
                and k.value == "body"
                and isinstance(v, ast.Constant)
                and v.value is not None
                and not isinstance(v.value, dict)
            ):
                findings.append(
                    Finding(
                        "error",
                        "ACTIVE_PROBES",
                        f"ACTIVE_PROBES[{i}]['body'] must be a dict (or omitted), "
                        f"got {_type_name(v)}",
                        getattr(v, "lineno", None),
                    )
                )


def _check_auth_header_pattern(node: ast.expr, findings: list[Finding]) -> None:
    lit = _literal_str(node)
    if lit is None:
        if isinstance(node, (ast.List, ast.Tuple, ast.Dict, ast.Set)) or (
            isinstance(node, ast.Constant) and not isinstance(node.value, str)
        ):
            findings.append(
                Finding(
                    "error",
                    "AUTH_HEADER_PATTERN",
                    f"AUTH_HEADER_PATTERN must be a string, got {_type_name(node)}",
                    getattr(node, "lineno", None),
                )
            )
        # else: built dynamically (an f-string with interpolation, a Call,
        # ...) -- can't statically resolve the pattern text, not flagged.
        return
    try:
        re.compile(lit)
    except re.error as e:
        findings.append(
            Finding(
                "error",
                "AUTH_HEADER_PATTERN",
                f"AUTH_HEADER_PATTERN is not a compilable regex: {e}",
                getattr(node, "lineno", None),
            )
        )


def _drive_arity_ok(args: ast.arguments) -> bool:
    """True if a function with this signature can be called as drive(page, log)."""
    positional = list(args.posonlyargs) + list(args.args)
    n_required = len(positional) - len(args.defaults)
    if args.vararg is not None:
        return n_required <= 2
    return n_required <= 2 <= len(positional)


def _check_drive_funcdef(
    node: ast.FunctionDef | ast.AsyncFunctionDef, findings: list[Finding]
) -> None:
    if isinstance(node, ast.AsyncFunctionDef):
        findings.append(
            Finding(
                "warning",
                "drive",
                "drive is defined as 'async def' -- capture.py calls "
                "recipe.drive(page, log) synchronously and will not await it",
                node.lineno,
            )
        )
    if not _drive_arity_ok(node.args):
        n = len(node.args.posonlyargs) + len(node.args.args)
        findings.append(
            Finding(
                "error",
                "drive",
                f"drive must be callable as drive(page, log) (2 positional "
                f"arguments); found {n} parameter(s)",
                node.lineno,
            )
        )


def _check_drive_assign(node: ast.expr, findings: list[Finding]) -> None:
    if isinstance(node, ast.Lambda):
        if not _drive_arity_ok(node.args):
            n = len(node.args.posonlyargs) + len(node.args.args)
            findings.append(
                Finding(
                    "error",
                    "drive",
                    f"drive must be callable as drive(page, log) (2 positional "
                    f"arguments); found {n} parameter(s) in the lambda",
                    getattr(node, "lineno", None),
                )
            )
        return
    if isinstance(node, (ast.Constant, ast.List, ast.Tuple, ast.Dict, ast.Set)):
        findings.append(
            Finding(
                "error",
                "drive",
                f"drive must be callable; found a {_type_name(node)} literal assigned to it",
                getattr(node, "lineno", None),
            )
        )
        return
    # Call/Name/Attribute/... (drive built by a factory or aliased) -- can't
    # verify arity statically. Flag as info so a human knows to check, but
    # don't fail the lint over it.
    findings.append(
        Finding(
            "info",
            "drive",
            "drive is not a plain 'def drive(...)' -- its call signature was "
            "not statically verified; use lint_recipe_dynamic() to check it "
            "for real (imports the recipe -- only run on a trusted file)",
            getattr(node, "lineno", None),
        )
    )


def _typo_findings(
    assigns: dict[str, ast.expr], funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]
) -> list[Finding]:
    findings: list[Finding] = []
    for name, node in assigns.items():
        if name in KNOWN_ATTRS or not re.fullmatch(r"[A-Z_][A-Z0-9_]*", name):
            continue
        match = difflib.get_close_matches(name, sorted(KNOWN_ATTRS), n=1, cutoff=ATTR_TYPO_CUTOFF)
        if match:
            findings.append(
                Finding(
                    "warning",
                    name,
                    f"module-level '{name}' looks like a possible typo of '{match[0]}' "
                    "(the recipe interface attribute) rather than a site-specific constant",
                    getattr(node, "lineno", None),
                )
            )
    for name, fnode in funcs.items():
        if name in KNOWN_FUNCS:
            continue
        match = difflib.get_close_matches(
            name.lower(), sorted(KNOWN_FUNCS), n=1, cutoff=FUNC_TYPO_CUTOFF
        )
        if match:
            findings.append(
                Finding(
                    "warning",
                    name,
                    f"module-level function '{name}' looks like a possible typo of "
                    f"'{match[0]}' (capture.py looks it up by the exact name 'drive')",
                    fnode.lineno,
                )
            )
    return findings


def _call_name(node: ast.Call) -> str:
    parts = []
    value: ast.expr = node.func
    while isinstance(value, ast.Attribute):
        parts.append(value.attr)
        value = value.value
    if isinstance(value, ast.Name):
        parts.append(value.id)
    return ".".join(reversed(parts))


def _safety_findings(tree: ast.Module, source: str) -> list[Finding]:
    findings = []
    lines = source.splitlines()
    dangerous_imports = {
        "aiohttp",
        "httpx",
        "os",
        "pathlib",
        "requests",
        "shutil",
        "socket",
        "subprocess",
        "urllib",
    }
    sensitive_calls = {
        "open": "filesystem access",
        "exec": "dynamic code execution",
        "eval": "dynamic code execution",
        "os.system": "subprocess execution",
        "os.remove": "filesystem deletion",
        "os.unlink": "filesystem deletion",
        "shutil.rmtree": "filesystem deletion",
        "subprocess.run": "subprocess execution",
        "subprocess.Popen": "subprocess execution",
    }
    interactive_methods = {
        "check",
        "click",
        "evaluate",
        "fill",
        "goto",
        "press",
        "select_option",
        "submit",
        "type",
    }

    def annotated(node: ast.AST) -> bool:
        line = getattr(node, "lineno", 0)
        return line > 1 and "astrolabe-safe:" in lines[line - 2].lower()

    for node in ast.walk(tree):
        imported = None
        if isinstance(node, ast.Import):
            imported = [item.name.split(".", 1)[0] for item in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported = [node.module.split(".", 1)[0]]
        if imported:
            for name in imported:
                if name in dangerous_imports:
                    findings.append(
                        Finding(
                            "warning",
                            None,
                            f"recipe imports {name}; review its filesystem/network/process capability",
                            getattr(node, "lineno", None),
                        )
                    )
        if (
            isinstance(node, ast.Attribute)
            and node.attr in {"browser", "context", "request"}
            and not annotated(node)
        ):
            findings.append(
                Finding(
                    "warning",
                    "drive",
                    f"direct browser capability {node.attr!r} escapes the constrained page "
                    "interface; add a preceding '# astrolabe-safe: ...' review annotation",
                    node.lineno,
                )
            )
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        risk = sensitive_calls.get(name)
        if risk and not annotated(node):
            findings.append(
                Finding(
                    "warning",
                    None,
                    f"{name} performs {risk}; add a preceding '# astrolabe-safe: ...' review annotation",
                    node.lineno,
                )
            )
        method = name.rsplit(".", 1)[-1]
        if method in interactive_methods and not annotated(node):
            findings.append(
                Finding(
                    "warning",
                    "drive",
                    f"{method} may submit data or trigger effects; add a preceding "
                    "'# astrolabe-safe: ...' review annotation",
                    node.lineno,
                )
            )
    return findings


def recipe_safety_findings(path: str) -> list[Finding]:
    """Return only capability/action findings without importing the recipe."""
    try:
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        tree = ast.parse(source, filename=path)
    except (OSError, SyntaxError) as exc:
        return [Finding("error", None, f"cannot inspect recipe safety: {exc}")]
    return _safety_findings(tree, source)


def lint_recipe(path: str) -> list[Finding]:
    """Statically lint a recipe .py file against the RecipeModule interface.

    Parses with ast.parse() ONLY -- the recipe is never imported, never
    executed. Safe to run on an untrusted or unreviewed recipe file (a
    astrolabe scan scaffold, or one handed to you by someone else); see the
    module docstring's trust-boundary section.

    Returns a list of Finding, most-relevant first is not guaranteed --
    callers that need a verdict should check `any(f.severity == "error" for
    f in findings)`.
    """
    if path.lower().endswith(".json"):
        try:
            recipe = load_declarative_recipe(path)
        except ValueError as exc:
            return [Finding("error", None, str(exc))]
        if not recipe.SURFACES and not recipe.ACTIONS:
            return [Finding("warning", None, "declarative recipe has no surfaces or actions")]
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
    except OSError as e:
        return [Finding("error", None, f"cannot read recipe file: {e}")]

    try:
        tree = ast.parse(src, filename=path)
    except SyntaxError as e:
        return [Finding("error", None, f"cannot parse recipe: {e}", e.lineno)]

    assigns: dict[str, ast.expr] = {}
    funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigns[target.id] = node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            assigns[node.target.id] = node.value
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs[node.name] = node

    findings: list[Finding] = []

    if "SURFACES" in assigns:
        _check_string_list("SURFACES", assigns["SURFACES"], findings)
    if "AUTH_HEADERS" in assigns:
        _check_string_list("AUTH_HEADERS", assigns["AUTH_HEADERS"], findings)
    if "SESS_HEADERS" in assigns:
        _check_str_dict("SESS_HEADERS", assigns["SESS_HEADERS"], findings)
    if "SESS_HEADER_HARVEST" in assigns:
        _check_str_dict("SESS_HEADER_HARVEST", assigns["SESS_HEADER_HARVEST"], findings)
    if "ACTIVE_PROBES" in assigns:
        _check_active_probes(assigns["ACTIVE_PROBES"], findings)
    if "AUTH_HEADER_PATTERN" in assigns:
        _check_auth_header_pattern(assigns["AUTH_HEADER_PATTERN"], findings)

    if "drive" in funcs:
        _check_drive_funcdef(funcs["drive"], findings)
    elif "drive" in assigns:
        _check_drive_assign(assigns["drive"], findings)

    if not assigns.get("SURFACES") and "drive" not in funcs and "drive" not in assigns:
        findings.append(
            Finding(
                "warning",
                None,
                "recipe defines no SURFACES and no drive() -- capture will have "
                "nothing to visit unless --seeds is passed on the command line",
            )
        )

    findings.extend(_typo_findings(assigns, funcs))
    findings.extend(_safety_findings(tree, src))

    return findings


def lint_recipe_dynamic(path: str) -> list[Finding]:
    """Opt-in dynamic companion to lint_recipe(): imports the recipe directly
    to check the handful of things static analysis cannot -- e.g. the real
    call signature of a `drive` built by a decorator or factory rather than a
    plain `def`.

    SECURITY: this EXECUTES the recipe file as Python. Never call this on a
    recipe you have not already decided you trust enough to run for real
    (e.g. via `astrolabe map --recipe <file>`). lint_recipe() (ast-only) is the
    safe default and the only one main() calls.
    """
    import inspect

    import importlib.util

    findings: list[Finding] = []
    try:
        spec = importlib.util.spec_from_file_location("dynamic_astrolabe_recipe", path)
        if spec is None or spec.loader is None:
            raise ImportError("cannot construct recipe module spec")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except Exception as e:  # noqa: BLE001 - recipe code can raise anything
        return [Finding("error", None, f"recipe raised on import: {e}")]

    drive = getattr(mod, "drive", None)
    if drive is not None:
        if not callable(drive):
            findings.append(Finding("error", "drive", "drive is not callable"))
        else:
            try:
                sig = inspect.signature(drive)
                sig.bind("page", "log")
            except TypeError as e:
                findings.append(Finding("error", "drive", f"drive(page, log) does not bind: {e}"))

    surfaces = getattr(mod, "SURFACES", None)
    if surfaces is not None and (
        not isinstance(surfaces, (list, tuple)) or not all(isinstance(s, str) for s in surfaces)
    ):
        findings.append(Finding("error", "SURFACES", "SURFACES must be a list of strings"))

    return findings


def _print_findings(findings: list[Finding], path: str) -> None:
    if not findings:
        print(f"[recipe] {path}: clean")
        return
    for f in sorted(findings, key=lambda f: {"error": 0, "warning": 1, "info": 2}[f.severity]):
        print(f"[recipe] {path}: {f}")
    n_err = sum(1 for f in findings if f.severity == "error")
    n_warn = sum(1 for f in findings if f.severity == "warning")
    n_info = sum(1 for f in findings if f.severity == "info")
    print(f"[recipe] {path}: {n_err} error(s), {n_warn} warning(s), {n_info} info(s)")


def main() -> None:
    ap = argparse.ArgumentParser(prog="recipe", description="lint a astrolabe recipe")
    ap.add_argument("recipe_file", help="path to a declarative .json or Python .py recipe")
    a = ap.parse_args()

    findings = lint_recipe(a.recipe_file)
    _print_findings(findings, a.recipe_file)
    if any(f.severity == "error" for f in findings):
        sys.exit(1)


if __name__ == "__main__":
    main()

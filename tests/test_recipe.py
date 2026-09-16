"""Tests for astrolabe.recipe -- the recipe interface reference + linter.

lint_recipe() is ast-based (never imports the recipe file), so tests write
throwaway .py files to tmp_path and lint them directly; this exercises the
same "safe on untrusted input" property the module promises.
"""

from __future__ import annotations

import glob
import sys

import pytest

from astrolabe.recipe import Finding, lint_recipe, load_declarative_recipe, main


def _write(tmp_path, name, source):
    p = tmp_path / name
    p.write_text(source)
    return str(p)


def _errors(findings):
    return [f for f in findings if f.severity == "error"]


def _warnings(findings):
    return [f for f in findings if f.severity == "warning"]


# ---- real recipes lint cleanly ----------------------------------------------


REAL_RECIPES = sorted(glob.glob("surfaces/*.recipe.py"))


@pytest.mark.parametrize("path", REAL_RECIPES)
def test_real_recipes_lint_with_no_errors(path):
    """Every recipe actually in surfaces/ must lint with zero errors -- the
    linter must not false-positive on real, working recipes."""
    findings = lint_recipe(path)
    assert _errors(findings) == [], [str(f) for f in _errors(findings)]


def test_real_recipes_have_no_typo_warnings():
    """The typo-detection cutoffs were calibrated against these exact files
    (BASE, API, REST_CATALOG, SOCKETIO_URL, SEARCH_QUERIES, _try, hop, ...) --
    none of their real constants/helpers should ever be flagged as a typo of
    the recipe interface."""
    for path in REAL_RECIPES:
        findings = lint_recipe(path)
        typo_warnings = [f for f in findings if "typo" in f.message]
        assert typo_warnings == [], (path, [str(f) for f in typo_warnings])


# ---- SURFACES ----------------------------------------------------------------


def test_surfaces_wrong_element_type_is_error(tmp_path):
    path = _write(tmp_path, "bad.recipe.py", "SURFACES = ['https://example.com/', 42]\n")
    findings = lint_recipe(path)
    assert any(f.attr == "SURFACES" and f.severity == "error" for f in findings)


def test_surfaces_wrong_container_type_is_error(tmp_path):
    path = _write(tmp_path, "bad.recipe.py", "SURFACES = {'a': 'b'}\n")
    findings = lint_recipe(path)
    assert any(f.attr == "SURFACES" and f.severity == "error" for f in findings)


def test_surfaces_fstrings_are_not_flagged(tmp_path):
    path = _write(
        tmp_path,
        "ok.recipe.py",
        'BASE = "https://example.com"\nSURFACES = [f"{BASE}/a", f"{BASE}/b"]\n',
    )
    findings = lint_recipe(path)
    assert _errors(findings) == []


def test_surfaces_dynamically_built_not_flagged(tmp_path):
    """A list built via a call/comprehension can't be statically verified --
    must not be flagged as wrong-type just because it isn't a literal."""
    path = _write(
        tmp_path,
        "ok.recipe.py",
        "def _mk():\n    return ['https://example.com/']\n\nSURFACES = _mk()\n",
    )
    findings = lint_recipe(path)
    assert _errors(findings) == []


# ---- ACTIVE_PROBES ------------------------------------------------------------


def test_active_probes_missing_url_is_error(tmp_path):
    path = _write(
        tmp_path,
        "bad.recipe.py",
        "ACTIVE_PROBES = [{'method': 'GET'}]\n",
    )
    findings = lint_recipe(path)
    assert any(
        f.attr == "ACTIVE_PROBES" and f.severity == "error" and "url" in f.message for f in findings
    )


def test_active_probes_with_url_is_clean(tmp_path):
    path = _write(
        tmp_path,
        "ok.recipe.py",
        "ACTIVE_PROBES = [{'method': 'GET', 'url': 'https://example.com/api'}]\n",
    )
    findings = lint_recipe(path)
    assert _errors(findings) == []


def test_python_post_probe_requires_review_annotation(tmp_path):
    path = _write(
        tmp_path,
        "bad.recipe.py",
        "ACTIVE_PROBES = [{'method': 'POST', 'url': 'https://example.com/search'}]\n",
    )
    assert any("allow_write=True" in finding.message for finding in _errors(lint_recipe(path)))


def test_python_post_probe_with_explicit_review_is_clean(tmp_path):
    path = _write(
        tmp_path,
        "ok.recipe.py",
        "ACTIVE_PROBES = [{'method': 'POST', 'url': 'https://example.com/search', "
        "'allow_write': True, 'safe_annotation': 'read-only search'}]\n",
    )
    assert _errors(lint_recipe(path)) == []


def test_declarative_recipe_parses_without_python_execution(tmp_path):
    path = tmp_path / "safe.recipe.json"
    path.write_text(
        '{"schema_version":1,"surfaces":["https://example.com/"],"actions":['
        '{"action":"search","selector":"#q","value":"synthetic",'
        '"safe_annotation":"read-only search"}],"active_probes":['
        '{"url":"https://example.com/api","method":"GET"}]}'
    )
    recipe = load_declarative_recipe(str(path))
    assert recipe.SURFACES == ["https://example.com/"]
    assert recipe.ACTIONS[0]["action"] == "search"


def test_declarative_drive_reports_each_causal_action(tmp_path):
    path = _write(
        tmp_path,
        "recipe.json",
        '{"schema_version":1,"actions":['
        '{"action":"scroll","pixels":100},'
        '{"action":"search","selector":"#q","value":"synthetic",'
        '"safe_annotation":"read-only search"}]}',
    )
    recipe = load_declarative_recipe(str(path))
    page = type(
        "Page",
        (),
        {
            "evaluate": lambda *args: None,
            "fill": lambda *args, **kwargs: None,
            "press": lambda *args, **kwargs: None,
        },
    )()
    interactions = []
    recipe.drive(page, lambda _message: None, lambda *values: interactions.append(values))
    assert interactions == [
        ("scroll", "bounded read-only action"),
        ("input", "read-only search"),
    ]
    assert lint_recipe(str(path)) == []


@pytest.mark.parametrize(
    "payload",
    [
        '{"schema_version":1,"actions":[{"action":"click","selector":"#delete"}]}',
        '{"schema_version":1,"active_probes":[{"url":"https://example.com","method":"POST"}]}',
        '{"schema_version":99}',
    ],
)
def test_declarative_recipe_rejects_unreviewed_or_unsupported_actions(tmp_path, payload):
    path = tmp_path / "bad.recipe.json"
    path.write_text(payload)
    assert _errors(lint_recipe(str(path)))


def test_python_recipe_ast_warns_on_capabilities_and_unannotated_actions(tmp_path):
    path = _write(
        tmp_path,
        "risky.recipe.py",
        "import subprocess\n\ndef drive(page, log):\n"
        "    subprocess.run(['true'])\n"
        "    page.click('#submit')\n",
    )
    messages = [finding.message for finding in lint_recipe(path)]
    assert any("imports subprocess" in message for message in messages)
    assert any("subprocess execution" in message for message in messages)
    assert any("may submit data" in message for message in messages)


def test_active_probes_wrong_method_type_is_error(tmp_path):
    path = _write(
        tmp_path,
        "bad.recipe.py",
        "ACTIVE_PROBES = [{'url': 'https://example.com/api', 'method': 7}]\n",
    )
    findings = lint_recipe(path)
    assert any(f.attr == "ACTIVE_PROBES" and f.severity == "error" for f in findings)


def test_active_probes_dynamic_entries_not_flagged(tmp_path):
    path = _write(
        tmp_path,
        "ok.recipe.py",
        "def _probe():\n    return {'url': 'https://example.com/api'}\n\nACTIVE_PROBES = [_probe()]\n",
    )
    findings = lint_recipe(path)
    assert _errors(findings) == []


# ---- AUTH_HEADER_PATTERN -------------------------------------------------------


def test_auth_header_pattern_uncompilable_is_error(tmp_path):
    path = _write(tmp_path, "bad.recipe.py", "AUTH_HEADER_PATTERN = r'(unclosed['\n")
    findings = lint_recipe(path)
    assert any(
        f.attr == "AUTH_HEADER_PATTERN" and f.severity == "error" and "regex" in f.message
        for f in findings
    )


def test_auth_header_pattern_valid_regex_is_clean(tmp_path):
    path = _write(tmp_path, "ok.recipe.py", "AUTH_HEADER_PATTERN = r'^x-acme-'\n")
    findings = lint_recipe(path)
    assert _errors(findings) == []


def test_auth_header_pattern_wrong_type_is_error(tmp_path):
    path = _write(tmp_path, "bad.recipe.py", "AUTH_HEADER_PATTERN = 42\n")
    findings = lint_recipe(path)
    assert any(f.attr == "AUTH_HEADER_PATTERN" and f.severity == "error" for f in findings)


# ---- SESS_HEADERS / SESS_HEADER_HARVEST ----------------------------------------


def test_sess_headers_non_string_key_is_error(tmp_path):
    path = _write(tmp_path, "bad.recipe.py", "SESS_HEADERS = {1: 'x'}\n")
    findings = lint_recipe(path)
    assert any(f.attr == "SESS_HEADERS" and f.severity == "error" for f in findings)


def test_sess_header_harvest_wrong_container_is_error(tmp_path):
    path = _write(tmp_path, "bad.recipe.py", "SESS_HEADER_HARVEST = ['x-api-key']\n")
    findings = lint_recipe(path)
    assert any(f.attr == "SESS_HEADER_HARVEST" and f.severity == "error" for f in findings)


def test_sess_headers_valid_is_clean(tmp_path):
    path = _write(tmp_path, "ok.recipe.py", "SESS_HEADERS = {'x-api-key': 'abc'}\n")
    findings = lint_recipe(path)
    assert _errors(findings) == []


# ---- drive() -------------------------------------------------------------------


def test_drive_wrong_arity_is_error(tmp_path):
    path = _write(tmp_path, "bad.recipe.py", "def drive(page):\n    pass\n")
    findings = lint_recipe(path)
    assert any(f.attr == "drive" and f.severity == "error" for f in findings)


def test_drive_correct_arity_is_clean(tmp_path):
    path = _write(tmp_path, "ok.recipe.py", "def drive(page, log):\n    pass\n")
    findings = lint_recipe(path)
    assert _errors(findings) == []


def test_drive_extra_optional_args_ok(tmp_path):
    """drive(page, log, extra=None) can still be called as drive(page, log)."""
    path = _write(tmp_path, "ok.recipe.py", "def drive(page, log, extra=None):\n    pass\n")
    findings = lint_recipe(path)
    assert _errors(findings) == []


def test_drive_varargs_ok(tmp_path):
    path = _write(tmp_path, "ok.recipe.py", "def drive(*args):\n    pass\n")
    findings = lint_recipe(path)
    assert _errors(findings) == []


def test_drive_async_def_is_warning(tmp_path):
    path = _write(tmp_path, "bad.recipe.py", "async def drive(page, log):\n    pass\n")
    findings = lint_recipe(path)
    assert any(
        f.attr == "drive" and f.severity == "warning" and "async" in f.message for f in findings
    )


def test_drive_assigned_non_callable_is_error(tmp_path):
    path = _write(tmp_path, "bad.recipe.py", "drive = 5\n")
    findings = lint_recipe(path)
    assert any(f.attr == "drive" and f.severity == "error" for f in findings)


def test_drive_missing_entirely_not_flagged_when_surfaces_present(tmp_path):
    path = _write(tmp_path, "ok.recipe.py", "SURFACES = ['https://example.com/']\n")
    findings = lint_recipe(path)
    assert _errors(findings) == []


# ---- typo detection --------------------------------------------------------


def test_attribute_typo_is_warning(tmp_path):
    path = _write(tmp_path, "bad.recipe.py", "SURFACE = ['https://example.com/']\n")
    findings = lint_recipe(path)
    assert any(
        f.attr == "SURFACE" and f.severity == "warning" and "typo" in f.message for f in findings
    )


def test_function_typo_is_warning(tmp_path):
    path = _write(tmp_path, "bad.recipe.py", "def drve(page, log):\n    pass\n")
    findings = lint_recipe(path)
    assert any(
        f.attr == "drve" and f.severity == "warning" and "typo" in f.message for f in findings
    )


@pytest.mark.parametrize(
    "const",
    ["BASE", "API", "REST_CATALOG", "SOCKETIO_URL", "SEARCH_QUERIES", "GQL_ENDPOINT"],
)
def test_common_site_constants_never_flagged_as_typos(tmp_path, const):
    path = _write(tmp_path, "ok.recipe.py", f"{const} = 'https://example.com'\n")
    findings = lint_recipe(path)
    assert [f for f in findings if "typo" in f.message] == []


@pytest.mark.parametrize("name", ["hop", "_try", "_hrefs", "_abs"])
def test_common_helper_names_never_flagged_as_typos(tmp_path, name):
    path = _write(tmp_path, "ok.recipe.py", f"def {name}(x):\n    return x\n")
    findings = lint_recipe(path)
    assert [f for f in findings if "typo" in f.message] == []


# ---- file-level -------------------------------------------------------------


def test_syntax_error_is_a_single_error_finding(tmp_path):
    path = _write(tmp_path, "bad.recipe.py", "def drive(page, log:\n    pass\n")
    findings = lint_recipe(path)
    assert len(findings) == 1
    assert findings[0].severity == "error"
    assert findings[0].attr is None


def test_missing_file_is_error(tmp_path):
    findings = lint_recipe(str(tmp_path / "does-not-exist.recipe.py"))
    assert len(findings) == 1
    assert findings[0].severity == "error"


def test_empty_recipe_warns_nothing_to_visit(tmp_path):
    path = _write(tmp_path, "empty.recipe.py", "# nothing here\n")
    findings = lint_recipe(path)
    assert any(f.attr is None and "nothing to visit" in f.message for f in findings)


def test_finding_str_includes_severity_and_message():
    f = Finding("error", "drive", "boom", 3)
    s = str(f)
    assert "error" in s and "boom" in s and "drive" in s


# ---- main() CLI convention ---------------------------------------------------


def test_main_exits_zero_on_clean_recipe(tmp_path, monkeypatch, capsys):
    path = _write(tmp_path, "ok.recipe.py", "SURFACES = ['https://example.com/']\n")
    monkeypatch.setattr(sys, "argv", ["recipe", path])
    main()  # no SystemExit raised -> implicit success
    out = capsys.readouterr().out
    assert "clean" in out


def test_main_exits_nonzero_on_errors(tmp_path, monkeypatch, capsys):
    path = _write(tmp_path, "bad.recipe.py", "ACTIVE_PROBES = [{'method': 'GET'}]\n")
    monkeypatch.setattr(sys, "argv", ["recipe", path])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1
    out = capsys.readouterr().out
    assert "error" in out


def test_declarative_drive_settles_after_each_state_change_and_skips_absent_optionals():
    from astrolabe.recipe import parse_declarative_recipe

    recipe = parse_declarative_recipe(
        {
            "schema_version": 1,
            "actions": [
                {
                    "action": "search",
                    "selector": "#name",
                    "value": "synthetic",
                    "submit": True,
                    "safe_annotation": "read-only name search",
                },
                {
                    "action": "click",
                    "selector": "#acknowledge",
                    "optional": True,
                    "timeout_ms": 50,
                    "safe_annotation": "dismiss disclaimer",
                },
                {"action": "wait_for", "selector": ".results"},
                {
                    "action": "select",
                    "selector": "#division",
                    "value": "civil",
                    "safe_annotation": "choose division",
                },
                {
                    "action": "press",
                    "selector": "#division",
                    "key": "Enter",
                    "safe_annotation": "submit filter",
                },
            ],
        }
    )
    calls = []

    class Page:
        def fill(self, selector, value, timeout=None):
            calls.append(("fill", selector, value))

        def press(self, selector, key, timeout=None):
            calls.append(("press", selector, key))

        def click(self, selector, timeout=None):
            calls.append(("click", selector))

        def select_option(self, selector, value, timeout=None):
            calls.append(("select", selector, value))

        def wait_for_selector(self, selector, timeout):
            if selector == "#acknowledge":
                raise TimeoutError("absent")
            calls.append(("wait_for", selector, timeout))

    recipe.drive(Page(), lambda _m: None, settle=lambda kind: calls.append(("settle", kind)))
    assert calls == [
        ("fill", "#name", "synthetic"),
        ("press", "#name", "Enter"),
        ("settle", "search"),
        ("wait_for", ".results", 5000),
        ("select", "#division", "civil"),
        ("settle", "select"),
        ("press", "#division", "Enter"),
        ("settle", "press"),
    ]


@pytest.mark.parametrize(
    "action",
    [
        {"action": "press", "selector": "#q", "key": "Control+W", "safe_annotation": "x"},
        {"action": "select", "selector": "#q", "safe_annotation": "x"},
        {"action": "wait", "optional": True},
        {"action": "click", "selector": "", "safe_annotation": "x"},
    ],
)
def test_declarative_recipe_rejects_unbounded_new_actions(action):
    from astrolabe.recipe import parse_declarative_recipe

    with pytest.raises(ValueError):
        parse_declarative_recipe({"schema_version": 1, "actions": [action]})

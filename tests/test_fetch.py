"""The ported fetch ladder: egress resolution, ladder outcomes and exit codes."""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest

from astrolabe import cli, envfile, fetch, fetch_driver


def _args(*argv: str):
    return fetch.build_parser().parse_args(["https://example.test/page", *argv])


# ---- residential proxy -------------------------------------------------------


def test_resproxy_defaults_to_the_configured_geography():
    url = fetch.resproxy_url({"ASTROLABE_RESPROXY_USER": "u", "ASTROLABE_RESPROXY_PASS": "p"})
    assert url == "http://u:p_country-us_state-virginia@geo.iproyal.com:12321"


def test_resproxy_composes_state_city_and_session_selectors():
    url = fetch.resproxy_url(
        {"ASTROLABE_RESPROXY_USER": "u", "ASTROLABE_RESPROXY_PASS": "p"},
        state="North Carolina",
        city="Raleigh",
        session="abc123",
        lifetime="30m",
    )
    assert "state-northcarolina" in url
    assert "city-raleigh" in url
    assert "session-abc123_lifetime-30m" in url


def test_resproxy_url_quotes_credentials_so_at_and_colon_survive():
    url = fetch.resproxy_url({"ASTROLABE_RESPROXY_USER": "u@x", "ASTROLABE_RESPROXY_PASS": "p:w"})
    assert "u%40x" in url
    assert "p%3Aw" in url


def test_resproxy_accepts_the_legacy_bastille_spelling():
    url = fetch.resproxy_url({"BASTILLE_RESPROXY_USER": "u", "BASTILLE_RESPROXY_PASS": "p"})
    assert url.startswith("http://u:p_")


def test_resproxy_without_credentials_names_the_variables_it_needs():
    with pytest.raises(ValueError, match="RESPROXY_USER"):
        fetch.resproxy_url({})


# ---- command redaction -------------------------------------------------------


def test_print_cmd_redacts_the_proxy_credential():
    redacted = fetch.redact(["astrolabe", "--proxy", "http://u:p@host:1", "url"])
    assert "http://u:p@host:1" not in redacted
    assert "<redacted>" in redacted


def test_print_cmd_redacts_a_credential_header_but_keeps_its_name():
    redacted = fetch.redact(
        ["astrolabe", "--header", "Authorization: Bearer abc", "--header", "Accept: json"]
    )
    joined = " ".join(redacted)
    assert "Bearer abc" not in joined
    assert "Authorization: <redacted>" in joined
    assert "Accept: json" in joined


# ---- driver argv -------------------------------------------------------------


def test_driver_argv_passes_the_browser_surface_through():
    args = _args(
        "--header",
        "A: b",
        "--warm",
        "https://example.test/",
        "--action=click:#go",
        "--browser-path",
        "/opt/chromium",
    )
    argv = fetch._driver_argv(args, "https://example.test/page")
    joined = " ".join(argv)
    assert "--header A: b" in joined
    assert "--warm https://example.test/" in joined
    assert "--action=click:#go" in joined
    assert "--browser-path /opt/chromium" in joined


def test_operator_config_fills_the_knobs_argparse_could_not(tmp_path, monkeypatch):
    """The .env is read after argparse builds defaults, so these must be resolved
    from the file or the settings it exists to hold would silently not apply."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "ASTROLABE_BYPARR_URL=http://solver.test/v1\n"
        "ASTROLABE_EGRESS_VERIFY_CMD=/opt/verify.sh\n"
        "CLOAKBROWSER_PATH=/opt/chromium\n",
        encoding="utf-8",
    )
    for name in ("ASTROLABE_BYPARR_URL", "ASTROLABE_EGRESS_VERIFY_CMD", "CLOAKBROWSER_PATH"):
        monkeypatch.delenv(name, raising=False)
    args = _args("--env-file", str(env_file))
    fetch._apply_env_defaults(args, envfile.resolve(str(env_file)))
    assert args.byparr_url == "http://solver.test/v1"
    assert args.egress_verify_cmd == "/opt/verify.sh"
    assert args.browser_path == "/opt/chromium"


def test_driver_output_takes_the_last_line_and_reports_garbage():
    ok = subprocess.CompletedProcess([], 0, stdout='noise\n{"status": "ok"}\n', stderr="")
    assert fetch._parse_driver_output(ok) == {"status": "ok"}
    bad = subprocess.CompletedProcess([], 0, stdout="not json", stderr="")
    assert fetch._parse_driver_output(bad)["status"] == "error"
    empty = subprocess.CompletedProcess([], 1, stdout="", stderr="boom")
    assert "boom" in fetch._parse_driver_output(empty)["error"]


# ---- ladder outcomes ---------------------------------------------------------


def _run(monkeypatch, capsys, driver_result, *argv):
    monkeypatch.setattr(fetch, "_run_driver", lambda *a, **k: driver_result)
    code = fetch.run(_args(*argv))
    return code, json.loads(capsys.readouterr().out.strip().splitlines()[-1])


def test_served_page_returns_zero_and_names_the_path(monkeypatch, capsys):
    code, payload = _run(monkeypatch, capsys, {"status": "ok", "http_status": 200})
    assert code == fetch.OK
    assert payload["via"] == "cloakbrowser"


def test_browser_error_returns_one(monkeypatch, capsys):
    code, payload = _run(monkeypatch, capsys, {"status": "error", "error": "launch: nope"})
    assert code == fetch.FETCH_ERROR
    assert payload["error"].startswith("launch")


def test_soft_block_returns_four_and_names_the_vendor(monkeypatch, capsys):
    code, payload = _run(
        monkeypatch, capsys, {"status": "soft_block", "soft_block_marker": "vendor:datadome"}
    )
    assert code == fetch.SOFT_BLOCK
    assert "datadome" in payload["marker"]


def test_challenge_is_not_sent_to_byparr_when_the_caller_says_no(monkeypatch, capsys):
    code, payload = _run(monkeypatch, capsys, {"status": "challenge"}, "--no-byparr")
    assert code == fetch.CHALLENGE_UNRESOLVED
    assert payload["stage"] == "skipped"


def test_challenge_under_a_proxy_skips_byparr_because_the_egress_differs(monkeypatch, capsys):
    code, payload = _run(
        monkeypatch, capsys, {"status": "challenge"}, "--proxy", "http://127.0.0.1:9"
    )
    assert code == fetch.CHALLENGE_UNRESOLVED
    assert "proxy egress" in payload["detail"]


def test_failed_vpn_verify_refuses_before_touching_the_browser(monkeypatch, capsys):
    def explode(*_a, **_k):
        raise AssertionError("the driver must not run when the egress gate fails")

    monkeypatch.setattr(fetch.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1))
    monkeypatch.setattr(fetch, "_run_driver", explode)
    code = fetch.run(_args("--netns"))
    payload = json.loads(capsys.readouterr().out.strip())
    assert code == fetch.EGRESS_VERIFY_FAILED
    assert "egress verify failed" in payload["error"]


def test_proxy_and_resproxy_are_exclusive(monkeypatch):
    monkeypatch.setenv("ASTROLABE_RESPROXY_USER", "u")
    monkeypatch.setenv("ASTROLABE_RESPROXY_PASS", "p")
    with pytest.raises(SystemExit):
        fetch.run(_args("--proxy", "http://127.0.0.1:9", "--resproxy"))


# ---- exit-code passthrough through the CLI -----------------------------------


def test_fetch_exit_code_survives_the_cli_remap(monkeypatch):
    """1 is a fetch failure; the CLI's own enum would have renamed it 10."""
    monkeypatch.setattr(fetch, "run", lambda _a: fetch.FETCH_ERROR)
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["fetch", "https://example.test/page"])
    assert excinfo.value.code == fetch.FETCH_ERROR


# ---- driver classification ---------------------------------------------------


def test_vendor_header_is_decisive_on_a_wall_status():
    assert fetch_driver.vendor_wall(403, {"x-datadome": "x"}, "", "") == "datadome"
    assert fetch_driver.vendor_wall(429, {"server": "AkamaiGhost"}, "", "") == "akamai"
    assert fetch_driver.vendor_wall(403, {"x-kpsdk-ct": "1"}, "", "") == "kasada"


def test_small_interstitial_names_the_vendor_but_a_content_page_does_not():
    assert fetch_driver.vendor_wall(200, {}, "dd.js captcha-delivery.com", "") == "datadome"
    large = "dd.js " + ("padding " * 20_000)
    assert fetch_driver.vendor_wall(200, {}, large, "") is None


def test_no_marker_means_no_vendor():
    assert fetch_driver.vendor_wall(200, {}, "<html>ordinary page</html>", "Shop") is None


def test_proxy_dict_unquotes_the_credentials():
    proxy = fetch_driver.parse_proxy("http://u%40x:p%3Aw@host:1234")
    assert proxy == {
        "server": "http://host:1234",
        "username": "u@x",
        "password": "p:w",
    }


def test_bad_header_is_rejected_rather_than_silently_dropped():
    with pytest.raises(SystemExit):
        fetch_driver.parse_headers(["no-colon-here"])


class _Recorder:
    def __init__(self):
        self.calls = []

    def locator(self, selector):
        recorder = self

        class _Locator:
            def __init__(self):
                self.first = self

            def wait_for(self, timeout=None):
                recorder.calls.append(("wait_for", selector, timeout))

            def fill(self, text):
                recorder.calls.append(("fill", selector, text))

            def click(self, timeout=None):
                recorder.calls.append(("click", selector, timeout))

        return _Locator()

    def wait_for_timeout(self, ms):
        self.calls.append(("wait", ms))

    def wait_for_selector(self, selector, timeout=None):
        self.calls.append(("waitfor", selector))

    @property
    def keyboard(self):
        recorder = self

        class _Keyboard:
            def press(self, key):
                recorder.calls.append(("press", key))

            def type(self, text, delay=None):
                recorder.calls.append(("type", text))

        return _Keyboard()


def test_actions_run_in_order():
    page = _Recorder()
    fetch_driver.run_actions(
        page, ["fill:#q=shoes", "click:#go", "press:Enter", "wait:10"], timeout=1000
    )
    assert page.calls == [
        ("wait_for", "#q", 1000),
        ("fill", "#q", "shoes"),
        ("click", "#go", 1000),
        ("press", "Enter"),
        ("wait", 10),
    ]


def test_an_unknown_action_is_an_error_not_a_no_op():
    with pytest.raises(SystemExit):
        fetch_driver.run_actions(_Recorder(), ["teleport:#q"], timeout=1000)

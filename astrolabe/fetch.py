"""``astrolabe fetch`` — the agentic fetch ladder, ported from ``cffetch``.

This is the controller half; the browser work lives in :mod:`astrolabe.fetch_driver`
so that VPN-namespace mode can re-exec it under ``ip netns exec`` without dragging
the controller's egress resolution into the namespace.

Ladder: ``[warm pages] -> fetch -> on Cloudflare challenge solve via byparr ->
re-fetch with the derived cookies+UA -> verify``. Non-Cloudflare bot walls are
reported as ``soft_block`` with the vendor named, because byparr cannot clear
them and sending one there wastes a solve.

The exit-code contract is the one the existing ``cffetch`` call-sites already
depend on and is deliberately *not* the CLI-wide :class:`astrolabe.cli.ExitCode`
enum:

===== ==================================================================
0     request served (JSON on stdout)
1     browser or navigation error
2     VPN egress verification failed (``--netns`` only)
3     ``CHALLENGE_UNRESOLVED`` — a Cloudflare challenge survived the handoff
4     ``SOFT_BLOCK`` — a non-Cloudflare bot wall
===== ==================================================================

Egress selection (``--netns``, ``--proxy``, ``--resproxy``) is operator config:
it lives on the CLI, which the operator runs, and is never a tool argument. The
credentials it uses come from a gitignored ``.env`` via :mod:`astrolabe.envfile`.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import string
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from urllib.parse import quote

from . import envfile

OK = 0
FETCH_ERROR = 1
EGRESS_VERIFY_FAILED = 2
CHALLENGE_UNRESOLVED = 3
SOFT_BLOCK = 4

DEFAULT_BYPARR_URL = "http://127.0.0.1:8191/v1"
DEFAULT_EGRESS_VERIFY_CMD = "/usr/local/sbin/vpn-egress-verify.sh"
DEFAULT_BROWSER_PATH = "~/.local/bin/cloakbrowser-chromium"


class FetchExit(SystemExit):
    """Exit with a fetch-contract code that the CLI must pass through unchanged.

    ``cli.main`` remaps bare ``SystemExit`` codes onto its own enum, which would
    turn a challenge (3) into a configuration error and a fetch failure (1) into
    an upstream one. ``passthrough`` marks the one exception to that remap.
    """

    passthrough = True


def _pick(env: dict[str, str], name: str) -> str | None:
    """Read ``ASTROLABE_<name>`` then the legacy ``BASTILLE_<name>`` spelling."""
    return env.get(f"ASTROLABE_{name}") or env.get(f"BASTILLE_{name}")


def resproxy_url(
    env: dict[str, str],
    *,
    state: str | None = None,
    city: str | None = None,
    session: str | None = None,
    lifetime: str = "1h",
) -> str:
    """Build an IPRoyal residential URL from operator config.

    Selectors ride on the password: ``_country-us_state-<name>[_city-x]
    [_session-K_lifetime-L]``. The username and password are URL-quoted so a
    credential containing ``@`` or ``:`` does not corrupt the authority.
    """
    user = _pick(env, "RESPROXY_USER")
    password = _pick(env, "RESPROXY_PASS")
    gateway = _pick(env, "RESPROXY_GATEWAY") or "geo.iproyal.com:12321"
    if not user or not password:
        raise ValueError(
            "--resproxy needs ASTROLABE_RESPROXY_USER/PASS (or the BASTILLE_ "
            "spelling) in the environment or the .env file"
        )
    gateway = gateway.split("://")[-1].rstrip("/")
    selector = "_country-us"
    if state:
        selector += f"_state-{state.lower().replace(' ', '')}"
    elif not city:
        selector = _pick(env, "RESPROXY_GEO") or "_country-us_state-virginia"
    if city:
        selector += f"_city-{city.lower().replace(' ', '')}"
    if session:
        key = (
            session
            if session != "new"
            else "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        )
        selector += f"_session-{key}_lifetime-{lifetime}"
    return f"http://{quote(user, safe='')}:{quote(password + selector, safe='')}@{gateway}"


def _redact_header(value: str) -> str:
    """Keep the header name, hide the value when it is a credential carrier."""
    name, separator, _ = value.partition(":")
    if separator and any(
        marker in name.upper() for marker in ("AUTH", "COOKIE", "TOKEN", "SECRET", "KEY")
    ):
        return f"{name}: <redacted>"
    return value


def redact(cmd: list[str]) -> list[str]:
    """Redact the values that carry credentials from a command line before logging.

    ``--proxy`` embeds the residential password; a ``--header`` may carry an
    ``Authorization`` or session cookie. Both are replaced, not truncated.
    """
    out: list[str] = []
    pending: str | None = None
    for token in cmd:
        if pending == "value":
            out.append("<redacted>")
            pending = None
            continue
        if pending == "header":
            out.append(_redact_header(token))
            pending = None
            continue
        out.append(token)
        if token == "--proxy":
            pending = "value"
        elif token == "--header":
            pending = "header"
    return out


def _driver_argv(args: argparse.Namespace, url: str, **overrides: str | None) -> list[str]:
    """Everything the driver understands, passed straight through."""
    argv = [url, "--timeout", str(args.timeout)]

    def add(flag: str, value: object) -> None:
        if value is None or value is False:
            return
        argv.extend([flag] if value is True else [flag, str(value)])

    add("--cookies", overrides.get("cookies_path") or args.cookies)
    add("--ua", overrides.get("ua") or args.ua)
    add("--out", overrides.get("out_path", args.out))
    add("--proxy", args.proxy)
    add("--headful", args.headful)
    add("--profile", args.profile)
    add("--method", args.method)
    for header in args.header:
        argv += ["--header", header]
    add("--data", args.data)
    add("--mode", args.mode)
    add("--wait-until", args.wait_until)
    add("--wait-for", args.wait_for)
    add("--settle-ms", args.settle_ms or None)
    for warm in args.warm:
        argv += ["--warm", warm]
    add("--warm-settle-ms", args.warm_settle_ms)
    add("--locale", args.locale)
    add("--timezone", args.timezone)
    add("--geolocation", args.geolocation)
    add("--viewport", args.viewport)
    for browser_arg in args.browser_arg:
        argv += [f"--browser-arg={browser_arg}"]
    add("--browser-path", args.browser_path)
    add("--dump-cookies", args.dump_cookies)
    add("--screenshot", args.screenshot)
    add("--capture", args.capture)
    add("--capture-out", args.capture_out)
    add("--exit-ip", args.exit_ip)
    for action in args.action:
        argv += [f"--action={action}"]
    return argv


def _run_driver(args: argparse.Namespace, url: str, **overrides: str | None) -> dict:
    """Run the driver on the host or inside the operator's network namespace."""
    driver = [args.python, "-m", "astrolabe.fetch_driver", *_driver_argv(args, url, **overrides)]
    home = os.path.expanduser("~")
    environment: dict[str, str] | None = dict(os.environ, CLOAKBROWSER_PATH=args.browser_path)
    if args.netns:
        command = [
            "sudo",
            "-n",
            "ip",
            "netns",
            "exec",
            args.netns,
            "setpriv",
            f"--reuid={os.getuid()}",
            f"--regid={os.getgid()}",
            "--init-groups",
            "--no-new-privs",
            "env",
            f"HOME={home}",
            f"CLOAKBROWSER_PATH={args.browser_path}",
        ]
        if args.headful:
            command += [f"DISPLAY={os.environ.get('DISPLAY', ':0')}"]
        command += driver
        environment = None
    else:
        command = driver
    if args.print_cmd:
        _log(args, "[fetch] " + " ".join(redact(command)))
    budget = args.timeout / 1000 * (2 + len(args.warm)) + (args.settle_ms or 0) / 1000 + 30
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=budget, env=environment
        )
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": f"browser exceeded {int(budget)}s"}
    return _parse_driver_output(completed)


def _parse_driver_output(completed: subprocess.CompletedProcess[str]) -> dict:
    """Take the last stdout line as the verdict; never let a traceback through."""
    stdout = (completed.stdout or "").strip()
    if not stdout:
        return {"status": "error", "error": (completed.stderr or "no output").strip()[-500:]}
    try:
        return json.loads(stdout.splitlines()[-1])
    except json.JSONDecodeError as exc:
        return {"status": "error", "error": f"driver emitted non-JSON: {exc}"}


def _byparr_solve(args: argparse.Namespace, url: str) -> tuple[list[dict], str | None]:
    """Ask byparr for a clearance cookie set. Returns ``(cookies, user_agent)``."""
    request = urllib.request.Request(
        args.byparr_url,
        method="POST",
        headers={"Content-Type": "application/json"},
        data=json.dumps(
            {"cmd": "request.get", "url": url, "maxTimeout": args.byparr_timeout}
        ).encode(),
    )
    with urllib.request.urlopen(request, timeout=args.byparr_timeout / 1000 + 30) as response:
        payload = json.load(response)
    solution = payload.get("solution", {}) if payload.get("status") == "ok" else {}
    return solution.get("cookies") or [], solution.get("userAgent")


def _to_playwright_cookies(cookies: list[dict]) -> list[dict]:
    """Translate byparr's cookie set into the shape ``add_cookies`` accepts."""
    out = []
    for cookie in cookies:
        converted = {
            key: cookie[key] for key in ("name", "value", "domain", "path") if key in cookie
        }
        if "expires" in cookie and cookie["expires"] not in (None, -1):
            converted["expires"] = cookie["expires"]
        if "secure" in cookie:
            converted["secure"] = bool(cookie["secure"])
        if "httpOnly" in cookie:
            converted["httpOnly"] = bool(cookie["httpOnly"])
        if converted.get("name") and "domain" in converted:
            out.append(converted)
    return out


def _egress_verified(args: argparse.Namespace) -> bool:
    """Fail-closed VPN gate. Not run outside ``--netns``."""
    if not args.netns or args.no_egress_verify:
        return True
    completed = subprocess.run(["sudo", "-n", args.egress_verify_cmd], capture_output=True)
    return completed.returncode == 0


def _log(args: argparse.Namespace, message: str) -> None:
    """Progress goes to stderr, and ``--quiet`` is the switch that stops it."""
    if not getattr(args, "quiet", False):
        print(message, file=sys.stderr)


def _apply_env_defaults(args: argparse.Namespace, environment: dict[str, str]) -> None:
    """Fill the knobs whose default is 'read from operator config'.

    argparse bakes a default at build time, which is before the ``.env`` is read,
    so leaving the value in the parser would make the file silently ineffective
    for exactly the settings it exists to hold.
    """
    args.byparr_url = (
        args.byparr_url
        or environment.get("ASTROLABE_BYPARR_URL")
        or environment.get("BYPARR_URL")
        or DEFAULT_BYPARR_URL
    )
    args.egress_verify_cmd = (
        args.egress_verify_cmd
        or _pick(environment, "EGRESS_VERIFY_CMD")
        or DEFAULT_EGRESS_VERIFY_CMD
    )
    args.browser_path = os.path.expanduser(
        args.browser_path or environment.get("CLOAKBROWSER_PATH") or DEFAULT_BROWSER_PATH
    )
    args.python = args.python or sys.executable


def run(args: argparse.Namespace) -> int:
    """Execute the ladder once and print exactly one JSON verdict."""
    environment = envfile.resolve(args.env_file)
    _apply_env_defaults(args, environment)
    if args.resproxy:
        if args.proxy:
            raise SystemExit("fetch: --proxy and --resproxy are exclusive")
        args.proxy = resproxy_url(
            environment,
            state=args.rp_state,
            city=args.rp_city,
            session=args.rp_session,
            lifetime=args.rp_lifetime,
        )
    where = f"netns {args.netns}" if args.netns else "host"
    if args.proxy:
        where += " via proxy"

    if not _egress_verified(args):
        print(
            json.dumps({"status": "error", "error": "VPN egress verify failed; refusing to fetch"})
        )
        return EGRESS_VERIFY_FAILED

    verdict = _run_driver(args, args.url, out_path=args.out)
    status = verdict.get("status")
    if status == "ok":
        _log(args, f"[fetch] ok via {where} cloakbrowser (no challenge)")
        verdict["via"] = "cloakbrowser"
        print(json.dumps(verdict))
        return OK
    if status == "error":
        print(json.dumps(verdict))
        return FETCH_ERROR
    if status == "soft_block":
        print(
            json.dumps(
                {
                    "status": "soft_block",
                    "marker": verdict.get("soft_block_marker"),
                    "vendor": verdict.get("vendor"),
                    "http_status": verdict.get("http_status"),
                    "final_url": verdict.get("final_url"),
                    "title": verdict.get("title"),
                    "headers": verdict.get("headers"),
                    "exit_ip": verdict.get("exit_ip"),
                    "cookie_names": verdict.get("cookie_names"),
                    "body_path": verdict.get("body_path"),
                    "hint": (
                        "non-Cloudflare bot wall; byparr cannot clear it. Try --headful, "
                        "--warm <homepage>, --profile DIR, a pinned --resproxy session, "
                        "or astrolabe challenge / map --solve."
                    ),
                }
            )
        )
        return SOFT_BLOCK

    # Challenged: solve on the same host (same egress IP) so the clearance transfers.
    if args.no_byparr or (args.proxy and not args.byparr_with_proxy):
        reason = "--no-byparr" if args.no_byparr else "proxy egress differs from byparr's"
        print(
            json.dumps(
                {
                    "status": "challenge_unresolved",
                    "stage": "skipped",
                    "detail": reason,
                    "http_status": verdict.get("http_status"),
                    "final_url": verdict.get("final_url"),
                }
            )
        )
        return CHALLENGE_UNRESOLVED

    _log(args, "[fetch] Cloudflare challenge; solving via host byparr")
    try:
        cookies, user_agent = _byparr_solve(args, args.url)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(
            json.dumps(
                {"status": "challenge_unresolved", "stage": "byparr", "detail": str(exc)[:200]}
            )
        )
        return CHALLENGE_UNRESOLVED
    if not cookies:
        print(
            json.dumps(
                {
                    "status": "challenge_unresolved",
                    "stage": "byparr",
                    "detail": "no cookies from byparr",
                }
            )
        )
        return CHALLENGE_UNRESOLVED

    descriptor, cookie_path = tempfile.mkstemp(suffix=".json")
    os.close(descriptor)
    os.chmod(cookie_path, 0o600)
    try:
        with open(cookie_path, "w", encoding="utf-8") as handle:
            json.dump(_to_playwright_cookies(cookies), handle)
        second = _run_driver(
            args, args.url, cookies_path=cookie_path, ua=user_agent, out_path=args.out
        )
    finally:
        os.unlink(cookie_path)
    if second.get("status") == "ok":
        _log(args, "[fetch] ok after byparr clearance transfer")
        second["via"] = "byparr"
        print(json.dumps(second))
        return OK

    print(
        json.dumps(
            {
                "status": "challenge_unresolved",
                "stage": "cookie_transfer",
                "hint": (
                    "challenge survived the byparr handoff; use the chrome-devtools MCP "
                    "or astrolabe challenge for an interactive solve"
                ),
            }
        )
    )
    return CHALLENGE_UNRESOLVED


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Attach the fetch surface. Kept here so the feature owns its own flags."""
    parser.add_argument("url")
    egress = parser.add_argument_group("egress")
    egress.add_argument(
        "--netns",
        nargs="?",
        const="vpn",
        default=None,
        metavar="NAME",
        help="fetch inside a network namespace (default name: vpn)",
    )
    egress.add_argument(
        "--no-egress-verify",
        action="store_true",
        help="skip the fail-closed VPN gate under --netns",
    )
    egress.add_argument(
        "--egress-verify-cmd",
        default=None,
        help="override the egress gate command (default: operator config)",
    )
    egress.add_argument("--proxy", help="browser proxy, http://user:pass@host:port")
    egress.add_argument(
        "--resproxy", action="store_true", help="IPRoyal residential from operator .env"
    )
    egress.add_argument("--rp-state", help="full US state name, e.g. virginia")
    egress.add_argument("--rp-city", help="best-effort city selector")
    egress.add_argument("--rp-session", metavar="KEY", help="pin one exit IP (8 alnum, or 'new')")
    egress.add_argument("--rp-lifetime", default="1h")
    egress.add_argument(
        "--env-file", help="read credentials from this file (default $ASTROLABE_ENV_FILE or ./.env)"
    )

    request = parser.add_argument_group("request")
    request.add_argument("--method")
    request.add_argument("--header", action="append", default=[], metavar="'K: V'")
    request.add_argument("--data", help="request body (implies fetch mode)")
    request.add_argument(
        "--mode",
        choices=("auto", "nav", "fetch"),
        help="nav = page navigation; fetch = window.fetch from the warmed origin",
    )

    browser = parser.add_argument_group("browser")
    browser.add_argument("--headful", action="store_true", help="show a real window")
    browser.add_argument("--profile", help="persistent user-data dir")
    browser.add_argument("--ua")
    browser.add_argument("--cookies", help="JSON list of Playwright cookies to preload")
    browser.add_argument("--locale")
    browser.add_argument("--timezone", help="e.g. America/New_York")
    browser.add_argument("--geolocation", metavar="LAT,LON")
    browser.add_argument("--viewport", metavar="WxH")
    browser.add_argument("--browser-arg", action="append", default=[])
    browser.add_argument(
        "--browser-path",
        default=None,
        help="stealth Chromium binary (default: operator config)",
    )

    timing = parser.add_argument_group("timing")
    timing.add_argument("--timeout", type=int, default=45000)
    timing.add_argument(
        "--wait-until",
        default="domcontentloaded",
        choices=("commit", "domcontentloaded", "load", "networkidle"),
    )
    timing.add_argument("--wait-for", metavar="SELECTOR")
    timing.add_argument("--settle-ms", type=int, default=0)
    timing.add_argument(
        "--warm",
        action="append",
        default=[],
        metavar="URL",
        help="visit first (repeatable) so sensor/session cookies are set",
    )
    timing.add_argument("--warm-settle-ms", type=int, default=2500)
    timing.add_argument(
        "--action",
        action="append",
        default=[],
        metavar="STEP",
        help=(
            "ordered page step after load: fill:SEL=TEXT, type:SEL=TEXT, click:SEL, "
            "press:KEY, wait:MS, waitfor:SEL"
        ),
    )

    output = parser.add_argument_group("output")
    output.add_argument("--out", help="write the rendered page (or fetch) body here")
    output.add_argument("--dump-cookies", metavar="FILE")
    output.add_argument("--screenshot", metavar="FILE")
    output.add_argument("--capture", metavar="REGEX", help="record matching responses")
    output.add_argument("--capture-out", metavar="FILE", help="JSONL of captured responses")
    output.add_argument("--exit-ip", action="store_true", help="report the browser's exit IP")
    output.add_argument("--quiet", action="store_true")
    output.add_argument(
        "--print-cmd", action="store_true", help="log the driver command (proxy redacted)"
    )

    solver = parser.add_argument_group("solver")
    solver.add_argument("--no-byparr", action="store_true")
    solver.add_argument(
        "--byparr-url",
        default=None,
        help="challenge solver endpoint (default: operator config)",
    )
    solver.add_argument("--byparr-timeout", type=int, default=60000)
    solver.add_argument(
        "--byparr-with-proxy",
        action="store_true",
        help="hand off even under a proxy (the solve runs from the host IP)",
    )

    plumbing = parser.add_argument_group("plumbing")
    plumbing.add_argument("--python", default=sys.executable)


def build_parser() -> argparse.ArgumentParser:
    """Standalone parser, so ``python -m astrolabe.fetch`` works like ``cffetch``."""
    parser = argparse.ArgumentParser(
        prog="astrolabe fetch",
        description="fetch a page through the CloakBrowser/byparr ladder",
    )
    add_arguments(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())

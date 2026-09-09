#!/usr/bin/env python3
"""astrolabe — orchestrate authenticated API/GraphQL recon.

Pipeline (glue over reused engines):
  cookies(local file) -> preflight(host) -> capture(cloakbrowser+Burp, byparr fallback)
  -> [clairvoyance schema] -> [har-to-openapi] -> analyze -> map.md + endpoints.json

Capture, schema recovery and any live replay run on the pipeline HOST (residential
egress, where cloakbrowser/Burp/byparr live). Authentication comes from an exported
cookie file or explicit domain-scoped Linux browser import via --browser.
"""

from __future__ import annotations
import argparse, contextlib, functools, hashlib, io, json, os, re, shutil, signal, subprocess, sys, shlex, tempfile, time, types, uuid
from collections.abc import Callable
from enum import IntEnum
from typing import Any
from . import analyze as az
from . import mcpgen as mg
from . import contract as ct
from . import profile as prof
from . import browser as br
from .artifact import atomic_write_json
from .security import normalize_host, safe_text

HERE = os.path.dirname(os.path.abspath(__file__))
_CLEANUP_STACK: list[list[Callable[[], Any]]] = []


def _guaranteed_cleanup(func):
    """Run registered secret/tmpfs cleanup callbacks on every exit path."""

    @functools.wraps(func)
    def wrapped(*args, **kwargs):
        callbacks: list[Callable[[], Any]] = []
        _CLEANUP_STACK.append(callbacks)
        primary_error: BaseException | None = None
        result = None
        try:
            result = func(*args, **kwargs)
        except BaseException as exc:
            primary_error = exc
        finally:
            cleanup_errors: list[Exception] = []
            for callback in reversed(callbacks):
                try:
                    callback()
                except Exception as exc:
                    cleanup_errors.append(exc)
            _CLEANUP_STACK.pop()
        if primary_error is not None:
            if cleanup_errors:
                primary_error.add_note(
                    "cleanup also failed: "
                    + "; ".join(safe_text(error) for error in cleanup_errors)
                )
            raise primary_error
        if cleanup_errors:
            raise CommandExecutionError(
                "required cleanup failed: "
                + "; ".join(safe_text(error) for error in cleanup_errors)
            )
        return result

    return wrapped


def _register_cleanup(callback) -> None:
    if _CLEANUP_STACK:
        _CLEANUP_STACK[-1].append(callback)


def _track_local_secret(path: str) -> None:
    absolute = os.path.abspath(path)
    if os.path.basename(absolute) not in {"cookies.json", "_cookies.json"}:
        raise ValueError("refusing to register an ambiguous secret path")

    def cleanup() -> None:
        _remove_local_secret(absolute)

    _register_cleanup(cleanup)


def _track_remote_tmpfs(hp, path: str) -> None:
    if not path.startswith("/dev/shm/astrolabe-") or any(c in path for c in "\r\n*?[]"):
        raise ValueError("refusing to register an ambiguous remote cleanup path")
    _register_cleanup(lambda: ssh_argv(hp, ["rm", "-rf", "--", path], timeout=20))


def _track_staging_dir(path: str, *, preserve_as: str | None = None) -> None:
    """Register a staging dir for teardown.

    With `preserve_as`, a staging dir that still exists at teardown (i.e. the run
    failed before promoting it) is *kept* under that path instead of deleted. A live
    authenticated capture is expensive and hard to repeat; throwing its PII-safe
    artifacts away because a downstream analysis step raised leaves the operator with
    nothing to diagnose from and forces another hit on the target account. Secrets are
    registered separately and shredded first — cleanup callbacks run in reverse
    registration order, so nothing preserved here has been left holding a cookie jar.
    """
    absolute = os.path.abspath(path)
    if not os.path.basename(absolute).startswith(".astrolabe-stage-"):
        raise ValueError("refusing to register an ambiguous staging directory")

    def teardown():
        if not os.path.isdir(absolute):
            return
        if preserve_as and os.listdir(absolute):
            destination = os.path.abspath(preserve_as)
            if os.path.exists(destination):
                shutil.rmtree(destination)
            shutil.move(absolute, destination)
            print(f"[cleanup] run did not complete — artifacts kept at {destination}")
            return
        shutil.rmtree(absolute)

    _register_cleanup(teardown)


def _remove_local_secret(path: str) -> None:
    if not os.path.isfile(path):
        return
    try:
        result = run(["shred", "-u", path], timeout=10)
        if result.returncode == 0 and not os.path.exists(path):
            return
    except (OSError, subprocess.SubprocessError):
        pass
    os.remove(path)


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _new_run_id() -> str:
    return uuid.uuid4().hex


def _target_slug(value: str) -> str:
    readable = re.sub(r"[^A-Za-z0-9_-]", "_", value)[:64]
    return f"{readable}-{hashlib.sha256(value.encode()).hexdigest()[:12]}"


def _verify_transfer_manifest(directory: str, expected_run_id: str) -> dict:
    path = os.path.join(directory, "transfer-manifest.json")
    try:
        with open(path, encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise PartialCaptureError("capture transfer manifest is missing or invalid") from exc
    if manifest.get("run_id") != expected_run_id:
        raise PartialCaptureError("capture transfer run ID does not match the requested run")
    checksums = manifest.get("sha256")
    if not isinstance(checksums, dict) or not checksums:
        raise PartialCaptureError("capture transfer manifest has no checksums")
    for name, expected in checksums.items():
        if name not in {"capture.jsonl", "meta.json", "graphql-names.txt"}:
            raise PartialCaptureError("capture transfer manifest names an unexpected artifact")
        artifact_path = os.path.join(directory, name)
        if not os.path.isfile(artifact_path) or _sha256_file(artifact_path) != expected:
            raise PartialCaptureError(f"capture transfer checksum mismatch for {name}")
    return manifest


def _promote_staging_directory(staging: str, destination: str) -> None:
    staging = os.path.abspath(staging)
    destination = os.path.abspath(destination)
    parent = os.path.dirname(destination) or "."
    if os.path.dirname(staging) != parent or not os.path.basename(staging).startswith(
        ".astrolabe-stage-"
    ):
        raise ValueError("staging directory is not a validated sibling of the destination")
    if not os.path.isdir(staging):
        raise PartialCaptureError("validated staging directory disappeared before promotion")
    if os.path.exists(destination) and not os.path.isdir(destination):
        raise ValidationError("output destination exists and is not a directory")
    backup = os.path.join(parent, f".astrolabe-backup-{_new_run_id()}")
    had_destination = os.path.isdir(destination)
    try:
        if had_destination:
            os.replace(destination, backup)
        os.replace(staging, destination)
    except Exception:
        if had_destination and os.path.isdir(backup) and not os.path.exists(destination):
            os.replace(backup, destination)
        raise
    if had_destination:
        shutil.rmtree(backup)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


class ExitCode(IntEnum):
    SUCCESS = 0
    USAGE = 2
    CONFIGURATION = 3
    SAFETY_REFUSAL = 4
    PARTIAL_CAPTURE = 5
    AUTHENTICATION = 6
    DRIFT = 7
    GENERATION = 8
    VALIDATION = 9
    UPSTREAM = 10
    INTERRUPTED = 130


class CLIError(RuntimeError):
    exit_code = ExitCode.UPSTREAM
    category = "upstream"


class CommandExecutionError(CLIError):
    """A required local/remote command or artifact transfer failed."""


class ConfigurationError(CLIError):
    exit_code = ExitCode.CONFIGURATION
    category = "configuration"


class SafetyRefusalError(CLIError):
    exit_code = ExitCode.SAFETY_REFUSAL
    category = "safety_refusal"


class PartialCaptureError(CLIError):
    exit_code = ExitCode.PARTIAL_CAPTURE
    category = "partial_capture"


class AuthenticationError(CLIError):
    exit_code = ExitCode.AUTHENTICATION
    category = "authentication"


class DriftDetectedError(CLIError):
    exit_code = ExitCode.DRIFT
    category = "drift"


class GenerationError(CLIError):
    exit_code = ExitCode.GENERATION
    category = "generation"


class ValidationError(CLIError):
    exit_code = ExitCode.VALIDATION
    category = "validation"


class InterruptedCLIError(CLIError):
    exit_code = ExitCode.INTERRUPTED
    category = "interrupted"


def _result_detail(result) -> str:
    detail = (getattr(result, "stderr", "") or "").strip() or (
        getattr(result, "stdout", "") or ""
    ).strip()
    return detail[-800:] if detail else "no diagnostic output"


def _require_success(result, label: str):
    if getattr(result, "returncode", 1) != 0:
        raise CommandExecutionError(
            f"{label} failed with exit {getattr(result, 'returncode', 'unknown')}: "
            f"{_result_detail(result)}"
        )
    return result


# Helpers copied flat into the capture host's tmpfs staging dir. They are executed
# there as top-level modules with no `astrolabe` package on sys.path, so every one of
# them must import cleanly without a package-relative import. See
# tests/test_cli.py::test_deployed_helpers_import_flat — a `from .x import y` in a
# deployed helper breaks `astrolabe map` at runtime and nowhere earlier.
CAPTURE_HELPERS = (
    "capture.py",
    "capture_parallel.py",
    "browser.py",
    "security.py",
    "operation.py",
    "media.py",
    "recipe.py",
    "recipe_runtime.py",
    "recipe_worker.py",
    "graphql_doc.py",
    "persisted.py",
    "relay.py",
    "payloads.py",
    "schema_recover.py",
)
# The per-site recipe is staged into the same directory as the helpers above, so its
# name must not collide with any of them. It used to be written as `recipe.py`, which
# overwrote astrolabe's own recipe.py helper — capture.py then could not import
# recipe_safety_findings and every Python-recipe run died at load. The recipe is loaded
# by explicit path, so this stem is free to be anything that isn't a helper name.
SITE_RECIPE_STEM = "site_recipe"
CONTRACT_HELPERS = (
    "contract_verify.py",
    "browser.py",
    "security.py",
    "payloads.py",
    "operation.py",
    "validation.py",
    "recipe.py",
    "recipe_runtime.py",
    "recipe_worker.py",
)


def _validate_remote_path(path: str) -> str:
    """Accept only the two remote staging namespaces owned by astrolabe.

    scp interprets its remote path through a shell. Keeping this allowlist
    narrow prevents whitespace, option, metacharacter, traversal, and colon
    injection even when a future caller accidentally passes user input.
    """
    if any(character in path for character in '\x00\r\n\t *?[]{}$`;&|<>!\\"'):
        raise ValueError("remote path contains unsafe characters")
    normalized = path.rstrip("/")
    if normalized.startswith("/dev/shm/astrolabe-") and "/../" not in f"{normalized}/":
        return path
    if normalized.startswith("~/astrolabe-tools/") and "/../" not in f"{normalized}/":
        return path
    raise ValueError("remote path is outside astrolabe-owned staging namespaces")


def _remote_word(value: str) -> str:
    """Quote one argv word for the remote shell, keeping a leading `~/` expandable.

    shlex.quote('~/x') yields a quoted word, which suppresses tilde expansion —
    so a `~`-prefixed *argument* would reach the remote command as a literal
    tilde. Expanding it here (rather than locally) keeps the home directory the
    remote host's, which is the whole point of deferring it."""
    if value.startswith("~/"):
        return '"$HOME"/' + shlex.quote(value[2:])
    return shlex.quote(value)


def ssh_argv(hp, argv, *, cwd=None, timeout=None, check=True):
    """Execute an argv without local shell parsing; quote once for remote ssh.

    A `~/` prefix is expanded on whichever machine actually runs the command, for
    every word — not just the executable. Engine paths (`hp.clairvoyance`, staging
    dirs) are configured tilde-relative and are routinely passed as arguments."""
    if not argv or not all(isinstance(value, str) and "\x00" not in value for value in argv):
        raise ValueError("command argv must contain non-NUL strings")
    if timeout is None:
        timeout = hp.ssh_timeout
    if hp.local:
        local_argv = [
            os.path.expanduser(value) if value.startswith("~/") else value for value in argv
        ]
        result = run(
            local_argv,
            cwd=os.path.expanduser(cwd) if cwd else None,
            timeout=timeout,
        )
    else:
        command = " ".join(_remote_word(value) for value in argv)
        if cwd:
            remote_cwd = (
                '"$HOME"/' + shlex.quote(cwd[2:]) if cwd.startswith("~/") else shlex.quote(cwd)
            )
            command = f"cd {remote_cwd} && exec {command}"
        result = run(["ssh", hp.host, command], timeout=timeout)
    return _require_success(result, f"command {argv[0]}") if check else result


def put(hp, src, dst):
    """Deploy a file to the work dir (scp remote; cp when the host is local)."""
    if not os.path.isfile(src):
        raise FileNotFoundError(f"deployment source does not exist: {src}")
    if hp.local:
        d = os.path.expanduser(dst)
        os.makedirs(os.path.dirname(d) or ".", exist_ok=True)
        return _require_success(run(["cp", src, d]), f"copy {src}")
    safe_dst = _validate_remote_path(dst)
    return _require_success(
        run(["scp", "-q", "--", src, f"{hp.host}:{safe_dst}"]),
        f"upload {os.path.basename(src)}",
    )


def get(hp, src, dst):
    """Pull a required artifact back, failing closed if it is unavailable."""
    if hp.local:
        s = os.path.expanduser(src)
        if not os.path.isfile(s):
            raise FileNotFoundError(f"required remote artifact does not exist locally: {s}")
        return _require_success(run(["cp", s, dst]), f"copy artifact {src}")
    safe_src = _validate_remote_path(src)
    return _require_success(
        run(["scp", "-q", "--", f"{hp.host}:{safe_src}", dst]),
        f"download {os.path.basename(src)}",
    )


def run_capture_argv(hp, argv, timeout, *, cwd=None, grace=None):
    """Run a capture argv with bounded graceful cancellation and no local shell."""
    if grace is None:
        grace = hp.grace_s
    if not hp.local:
        return ssh_argv(hp, argv, cwd=cwd, timeout=timeout, check=False)
    local_argv = list(argv)
    local_argv[0] = os.path.expanduser(local_argv[0])
    p = subprocess.Popen(
        local_argv,
        cwd=os.path.expanduser(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    timed_out = False
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        with contextlib.suppress(ProcessLookupError):
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        try:
            out, _ = p.communicate(timeout=grace)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            out, _ = p.communicate()
    if timed_out:
        out = (out or "") + (
            f"\n[capture] exceeded {timeout}s → SIGTERM (graceful flush); "
            "artifacts salvaged from partial run\n"
        )
    return types.SimpleNamespace(
        stdout=out or "", stderr="", returncode=p.returncode if p.returncode is not None else 1
    )


def _require_recipe_sandbox(hp) -> None:
    result = ssh_argv(hp, ["bwrap", "--version"], timeout=15, check=False)
    if result.returncode != 0:
        raise ConfigurationError(
            "Python recipe isolation requires bubblewrap on the capture host; use a "
            "declarative JSON recipe or explicitly acknowledge the in-process fallback"
        )


def _capture_concurrency_argv(cap: list[str], a) -> list[str]:
    browser_concurrency = getattr(a, "browser_concurrency", 1)
    if not 1 <= browser_concurrency <= 8:
        raise ConfigurationError("browser concurrency must be between 1 and 8")
    for label, value in (
        ("total request budget", a.max_total_requests),
        ("origin request budget", a.max_origin_requests),
        ("operation request budget", a.max_operation_requests),
    ):
        if value < browser_concurrency:
            raise ConfigurationError(
                f"{label} must be at least browser concurrency so every shard has a budget"
            )
    if a.rate_limit_reserve < 0:
        raise ConfigurationError("rate-limit reserve must be non-negative")
    if browser_concurrency == 1:
        return cap
    if a.rate_limit_reserve < browser_concurrency:
        raise ConfigurationError(
            "parallel browser capture requires a rate-limit reserve at least equal to "
            "browser concurrency"
        )
    if not a.no_auth and not getattr(a, "allow_auth_concurrency", False):
        raise SafetyRefusalError(
            "authenticated browser concurrency requires --allow-auth-concurrency and "
            "target-specific request budgets"
        )
    return [
        cap[0],
        "capture_parallel.py",
        "--concurrency",
        str(browser_concurrency),
        "--",
        *cap[1:],
    ]


def wan_ip(hp=None):
    ua = "Mozilla/5.0 (compatible; astrolabe/1.0)"
    argv = ["curl", "-fsS", "-m", "8", "--user-agent", ua, "https://api.ipify.org"]
    r = ssh_argv(hp, argv, timeout=30, check=False) if hp else run(argv, timeout=15)
    return (r.stdout or "").strip()


def preflight(hp, verbose=True):
    info = {"host": hp.host}
    # Burp proxy listener port. The config's `running` flag is Burp's *saved* state,
    # not liveness — a closed Burp still leaves it true. Reporting a proxy that
    # nothing is listening on is worse than reporting none: capture then routes every
    # navigation into ERR_PROXY_CONNECTION_FAILED and the run dies with zero calls.
    # So the discovered port is TCP-probed on the host before it is believed.
    discovery_code = (
        "import glob,json,os,socket,sys;port=None\n"
        "for f in glob.glob(os.path.expanduser(sys.argv[1])):\n"
        " try:\n"
        "  d=json.load(open(f))\n"
        "  for listener in d.get('proxy',{}).get('request_listeners',[]) or []:\n"
        "   if listener.get('running'): port=listener.get('listener_port')\n"
        " except (OSError,ValueError,TypeError): pass\n"
        "if port is not None:\n"
        " try:\n"
        "  socket.create_connection(('127.0.0.1', int(port)), 1.5).close()\n"
        " except OSError: port=None\n"
        "print(port or '')"
    )
    r = ssh_argv(
        hp,
        [hp.http_py, "-c", discovery_code, hp.burp_config_glob],
        timeout=30,
        check=False,
    )
    port = (r.stdout or "").strip().splitlines()[-1] if r.stdout.strip() else ""
    info["burp_proxy"] = f"http://127.0.0.1:{port}" if port else None
    # Engine checks use the same structured argv path as every remote command.
    engines = prof.probe(
        hp, runner=lambda argv, timeout: ssh_argv(hp, argv, timeout=timeout, check=False)
    )
    info["byparr"] = hp.byparr if engines["byparr"]["present"] else None
    info["cloakbrowser"] = engines["cloakbrowser"]["detail"]
    info["clairvoyance"] = engines["clairvoyance"]["present"]
    info["engines"] = engines
    info["capture_dependencies"] = engines.get("capture_dependencies", {}).get("present", False)
    info["tls_http"] = engines.get("tls_http", {}).get("present", False)
    info["openapi_capability"] = engines.get("openapi", {}).get("present", False)
    engine_states = {entry.get("status") for entry in engines.values()}
    info["host_status"] = (
        "unreachable"
        if "unreachable" in engine_states
        else "timeout"
        if "timeout" in engine_states
        else "reachable"
    )
    # egress safety
    li, hi = wan_ip(), wan_ip(None if hp.local else hp)
    info["egress_local"], info["egress_host"] = li, hi
    info["egress_match"] = bool(li and li == hi)
    info["egress_status"] = (
        "match" if info["egress_match"] else "unavailable" if not li or not hi else "mismatch"
    )
    if verbose:
        print("── preflight ──────────────────────────────")
        for k in (
            "host",
            "burp_proxy",
            "byparr",
            "cloakbrowser",
            "clairvoyance",
            "capture_dependencies",
            "tls_http",
            "openapi_capability",
            "host_status",
            "egress_local",
            "egress_host",
            "egress_match",
            "egress_status",
        ):
            print(f"  {k:14} {info[k]}")
        if not info["egress_match"]:
            print("  ⚠ egress IP differs from where cookies were minted → CF/anti-fraud risk")
        print("───────────────────────────────────────────")
    return info


def _resolve(a):
    """Resolve the HostProfile for a subcommand's parsed args. --local is only
    present on commands that expose it (map, scan, contract); everything else
    falls straight through to profile.py's own resolution layers."""
    return prof.resolve_profile(host=getattr(a, "host", None), local=getattr(a, "local", None))


def cmd_preflight(a):
    hp = _resolve(a)
    info = preflight(hp, verbose=not a.json)
    return info


def _resolve_capture_backend(hp) -> str:
    """Which browser backend will drive capture.py for this run.

    Remote capture keeps requiring cloakbrowser exactly as before -- the
    stealth engine only exists on the capture host's pipx venv, and
    ASTROLABE_BROWSER is a local-process concern. On a local host, defer to
    astrolabe.browser.resolve_backend() (env ASTROLABE_BROWSER, default
    auto), the same resolution capture.py will make in-process."""
    return br.resolve_backend() if hp.local else "cloakbrowser"


def _probe_local_playwright(timeout: int = 30) -> tuple[bool, str]:
    """Verify plain Playwright + a Chromium binary actually launch on this
    machine (the same interpreter that will run capture.py locally)."""
    code = (
        "from playwright.sync_api import sync_playwright\n"
        "p = sync_playwright().start()\n"
        "b = p.chromium.launch(headless=True)\n"
        "b.close()\n"
        "p.stop()\n"
    )
    r = run([sys.executable, "-c", code], timeout=timeout)
    return r.returncode == 0, _result_detail(r)


@_guaranteed_cleanup
def cmd_map(a):
    hp = _resolve(a)
    dom = normalize_host(a.domain)
    if getattr(a, "browser", None) and (
        not hp.local or a.no_auth or a.cookies_file or a.recipe or a.openapi
    ):
        raise SafetyRefusalError(
            "native browser import requires local capture and cannot combine with "
            "--no-auth, --cookies-file, recipes, or HAR/OpenAPI export"
        )
    if getattr(a, "browser", None):
        # Bound an authenticated import even when general capture defaults are larger.
        a.max_total_requests = min(a.max_total_requests, 100)
        a.max_origin_requests = min(a.max_origin_requests, 100)
        a.max_operation_requests = min(a.max_operation_requests, 20)
        a.browser_concurrency = 1
        a.no_burp = True  # No TLS interception of native credentials.
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    final_out = os.path.abspath(a.out or f"./astrolabe-{dom}")
    os.makedirs(os.path.dirname(final_out) or ".", exist_ok=True)
    out = tempfile.mkdtemp(prefix=".astrolabe-stage-", dir=os.path.dirname(final_out) or ".")
    _track_staging_dir(out, preserve_as=f"{final_out}.partial")
    pf = preflight(hp)
    backend = _resolve_capture_backend(hp)
    pf["backend"] = backend
    print(f"  {'backend':14} {backend}")
    if backend == "cloakbrowser":
        if not pf["cloakbrowser"]:
            raise ConfigurationError("capture host has no cloakbrowser capability")
        if not pf.get("capture_dependencies", True):
            raise ConfigurationError(
                "capture host is missing required graphql-core/jsonschema dependencies"
            )
    else:
        ok, detail = _probe_local_playwright()
        if not ok:
            raise ConfigurationError(
                "local playwright backend selected but playwright+chromium is not "
                "available (pip install -e . && playwright install chromium): " + detail
            )
        # capture_dependencies (graphql-core, jsonschema) are astrolabe's own core
        # deps -- the interpreter running this CLI, which also runs capture.py
        # locally under the playwright backend, already satisfies them.
    proxy = pf["burp_proxy"] if not a.no_burp else None
    byparr = pf["byparr"]

    # Native decryption goes straight to the private local tmpfs capture directory.
    run_id = _new_run_id()
    rdir = f"/dev/shm/astrolabe-{_target_slug(dom)}-{run_id}"
    _track_remote_tmpfs(hp, rdir)
    ssh_argv(hp, ["mkdir", "-m", "700", "-p", rdir], timeout=20)
    cookies_local = (
        f"{rdir}/cookies.json" if getattr(a, "browser", None) else os.path.join(out, "cookies.json")
    )
    _track_local_secret(cookies_local)
    if not a.no_auth:
        if not a.cookies_file and not getattr(a, "browser", None):
            raise ConfigurationError(
                "--cookies-file or --browser is required for an authenticated map (or pass --no-auth)"
            )
        from .credentials import browser_cookies

        if getattr(a, "browser", None):
            if a.cookies_file:
                raise ConfigurationError("choose --browser or --cookies-file, not both")
            from .browser_cookies import export_cookies

            cks = export_cookies(a.browser, dom, a.profile)
            print(f"[cookies] {len(cks)} domain-scoped cookies from {a.browser}")
        else:
            cks = browser_cookies(json.load(open(os.path.expanduser(a.cookies_file))))
            print(f"[cookies] {len(cks)} cookies from file")
        atomic_write_json(cookies_local, cks, mode=0o600)

    # 2. deploy to host tmpfs
    for helper in CAPTURE_HELPERS:
        put(hp, os.path.join(HERE, helper), f"{rdir}/{helper}")
    recipe_argv: list[str] = []
    if a.recipe:
        declarative = a.recipe.lower().endswith(".json")
        if not declarative and not a.trusted_recipe:
            raise SafetyRefusalError(
                "Python recipes require --trusted-recipe; they run in an isolated worker "
                "unless --allow-inprocess-python-recipe is also supplied"
            )
        if not declarative and not getattr(a, "allow_inprocess_python_recipe", False):
            _require_recipe_sandbox(hp)
        remote_recipe = (
            f"{rdir}/{SITE_RECIPE_STEM}.json" if declarative else f"{rdir}/{SITE_RECIPE_STEM}.py"
        )
        put(hp, a.recipe, remote_recipe)
        recipe_argv = ["--recipe", remote_recipe]
        if not declarative:
            recipe_argv += ["--trusted-recipe"]
            if getattr(a, "allow_inprocess_python_recipe", False):
                recipe_argv += ["--allow-inprocess-python-recipe"]
    if not a.no_auth:
        if not getattr(a, "browser", None):
            put(hp, cookies_local, f"{rdir}/cookies.json")
        ssh_argv(hp, ["chmod", "600", f"{rdir}/cookies.json"], timeout=15)

    # 3. capture (cloakbrowser venv on remote/explicit-stealth; this CLI's own
    #    interpreter for the local playwright backend)
    capture_py = sys.executable if hp.local else hp.cloak_py
    cap = [
        capture_py,
        "capture.py",
        "--base-domain",
        dom,
        "--outdir",
        rdir,
        "--run-id",
        run_id,
        *recipe_argv,
        *([] if getattr(a, "browser", None) else ["--har"]),
        "--introspect",
    ]
    if not a.no_auth:
        cap += ["--cookies", f"{rdir}/cookies.json"]
    if proxy:
        cap += ["--proxy", proxy]
    if byparr:
        cap += ["--byparr", byparr]
    if a.seeds:
        cap += ["--seeds", a.seeds]
    if getattr(a, "recover_persisted", False):
        cap.append("--recover-persisted")
    if a.crawl:
        cap += ["--crawl", str(a.crawl)]
    if getattr(a, "block_assets", False):
        cap.append("--block-assets")
    cap += [
        "--max-total-requests",
        str(getattr(a, "max_total_requests", 10_000)),
        "--max-origin-requests",
        str(getattr(a, "max_origin_requests", 5_000)),
        "--max-operation-requests",
        str(getattr(a, "max_operation_requests", 500)),
        "--rate-limit-reserve",
        str(getattr(a, "rate_limit_reserve", 1)),
    ]
    cap = _capture_concurrency_argv(cap, a)
    print(f"[capture] running on {hp.host} …")
    r = run_capture_argv(hp, cap, a.timeout, cwd=rdir)
    print(r.stdout[-2000:] if r.stdout else "")
    _require_success(r, "capture")

    # 4. pull PII-safe artifacts only. NOT cookies, NOT auth.headers.json, and NOT
    #    capture.har — the full HAR holds response bodies (PII) + Bearer tokens in
    #    request headers, so it stays on the host tmpfs and is processed there (step 6).
    for f in ("capture.jsonl", "meta.json", "graphql-names.txt", "transfer-manifest.json"):
        get(hp, f"{rdir}/{f}", os.path.join(out, f))

    _verify_transfer_manifest(out, run_id)

    meta = (
        json.load(open(os.path.join(out, "meta.json")))
        if os.path.exists(os.path.join(out, "meta.json"))
        else {}
    )
    if meta.get("run_id") != run_id:
        raise PartialCaptureError("capture metadata run ID does not match the requested run")
    if meta.get("partial"):
        raise PartialCaptureError("capture host marked the run partial")
    if normalize_host(str(meta.get("base_domain") or "")) != dom:
        raise PartialCaptureError("capture metadata target does not match the requested domain")
    intro = (meta.get("events", {}) or {}).get("introspection") or {}
    gql_eps = list(meta.get("graphql_endpoints", {}))

    # 5. GraphQL schema — introspection if enabled, else clairvoyance (opt-in, gated)
    if intro.get("enabled"):
        print("[schema] introspection ENABLED — full schema available via introspection")
    elif a.schema and pf["clairvoyance"] and gql_eps:
        ep = f"https://{dom}{gql_eps[0]}"
        recover_result = ssh_argv(
            hp,
            [
                hp.cloak_py,
                "schema_recover.py",
                "--endpoint",
                ep,
                "--allowed-host",
                dom,
                "--headers",
                f"{rdir}/auth.headers.json",
                "--clairvoyance",
                hp.clairvoyance,
                "--wordlist",
                f"{rdir}/graphql-names.txt",
                "--schema-out",
                f"{rdir}/schema.json",
                "--concurrency",
                str(a.schema_conc),
                "--timeout",
                str(a.schema_timeout),
            ],
            cwd=rdir,
            timeout=a.schema_timeout + 60,
            check=False,
        )
        _require_success(recover_result, "GraphQL schema recovery")
        try:
            recovery = json.loads((recover_result.stdout or "").strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError) as exc:
            raise CommandExecutionError("schema recovery returned an invalid status") from exc
        if not recovery.get("suggestions"):
            print(
                "[schema] clairvoyance SKIPPED — endpoint returns no field suggestions "
                "(introspection off + suggestions off = hardened). Avoiding needless probing."
            )
        elif recovery.get("recovered"):
            print(f"[schema] suggestions LEAK — running clairvoyance conc={a.schema_conc} slow …")
            get(hp, f"{rdir}/schema.json", os.path.join(out, "schema.json"))
    elif a.schema:
        print("[schema] skipped (no clairvoyance / no gql endpoint)")

    # 6. REST -> OpenAPI (opt-in). Processed HOST-SIDE so the token/PII-laden HAR
    #    never leaves the capture host; only the first-party openapi.json is pulled.
    if a.openapi:
        if not pf.get("openapi_capability"):
            raise ConfigurationError(
                "OpenAPI generation requested but node/har-to-openapi capability is unavailable"
            )
        put(hp, os.path.join(HERE, "har2oas.mjs"), "~/astrolabe-tools/node/_har2oas.mjs")
        print("[openapi] har-to-openapi (host-side, first-party only) …")
        orr = ssh_argv(
            hp,
            [hp.node, "_har2oas.mjs", f"{rdir}/capture.har", f"{rdir}/openapi.json", dom],
            cwd="~/astrolabe-tools/node",
            timeout=300,
            check=False,
        )
        print((orr.stdout or orr.stderr or "")[-400:])
        _require_success(orr, "OpenAPI generation")
        get(hp, f"{rdir}/openapi.json", os.path.join(out, "openapi.json"))

    # 7. analyze -> map.md + endpoints.json
    recs, meta = az.load(out)
    prior_graph = os.path.join(final_out, "graph.json")
    nops, nrest = az.render(
        out,
        recs,
        meta,
        prior_graph=prior_graph if os.path.exists(prior_graph) else None,
    )
    print(f"[analyze] {nops} gql ops, {nrest} rest -> {out}/map.md")

    # 7b. durable typed contract (observed proof) — merges the prior contract in this
    #     out dir so the map completes across runs and drift is surfaced. The contract,
    #     not the map, is the artifact downstream active tooling depends on.
    prior = os.path.join(final_out, "contract.json")
    import sys as _s

    _s.argv = ["contract", out] + (["--merge", prior] if os.path.exists(prior) else [])
    ct.main()

    # 8. cleanup — remote tmpfs (cookies + auth headers + captures) AND local cookies
    ssh_argv(hp, ["rm", "-rf", "--", rdir], timeout=20)
    _remove_local_secret(cookies_local)
    print(f"[cleanup] removed {hp.host}:{rdir} + local cookies")
    required = (
        "capture.jsonl",
        "meta.json",
        "graphql-names.txt",
        "transfer-manifest.json",
        "graph.json",
        "map.md",
        "endpoints.json",
        "contract.json",
        "contract.md",
    )
    missing = [name for name in required if not os.path.isfile(os.path.join(out, name))]
    if missing:
        raise PartialCaptureError(
            f"run is partial; required staged artifacts missing: {', '.join(missing)}"
        )
    promoted = list(required) + [
        name for name in ("schema.json", "openapi.json") if os.path.isfile(os.path.join(out, name))
    ]
    from .artifact import build_manifest, utc_now, write_manifest

    meta = json.load(open(os.path.join(out, "meta.json")))
    now = utc_now()
    manifest = build_manifest(
        out,
        artifact_type="capture-pipeline",
        artifact_schema_version=1,
        run_id=str(meta.get("run_id") or run_id),
        target=dom,
        completeness="complete",
        started_at=str(meta.get("started_at") or meta.get("captured_at") or now),
        completed_at=str(meta.get("completed_at") or meta.get("captured_at") or now),
        artifact_names=promoted,
        profile=getattr(a, "profile", None),
        failures=list(meta.get("failures") or []),
        truncations=dict(meta.get("truncations") or {}),
        safety_mode="read-only",
    )
    write_manifest(os.path.join(out, "artifact-manifest.json"), manifest)
    promoted.append("artifact-manifest.json")
    _promote_staging_directory(out, final_out)
    print(
        f"\n✓ {final_out}/contract.md (contract of record) | map.md | endpoints.json"
        + ("  |  schema.json" if "schema.json" in promoted else "")
        + ("  |  openapi.json" if "openapi.json" in promoted else "")
    )


@_guaranteed_cleanup
def cmd_replay(a):
    hp = _resolve(a)
    dom = normalize_host(a.domain)
    final_out = os.path.abspath(a.out or f"./astrolabe-replay-{dom}")
    os.makedirs(os.path.dirname(final_out) or ".", exist_ok=True)
    out = tempfile.mkdtemp(prefix=".astrolabe-stage-", dir=os.path.dirname(final_out) or ".")
    _track_staging_dir(out)
    json.load(open(a.op))  # validate op-file is well-formed JSON before staging
    pf = preflight(hp)
    if not pf["egress_match"]:
        print("  ⚠ proceeding despite egress mismatch")

    # 1. cookies + scoped auth headers — bring your own: a pre-made Playwright-format
    #    cookie JSON export and a pre-made auth.map.json credential bundle (see
    #    astrolabe.credentials for the schema). This tool never reads a browser's cookie
    #    store and never mints tokens itself.
    if not a.cookies_file:
        raise ConfigurationError("--cookies-file is required for replay")
    if not a.auth_file:
        raise ConfigurationError("--auth-file is required for replay")
    cookies_local = os.path.join(out, "cookies.json")
    _track_local_secret(cookies_local)
    atomic_write_json(
        cookies_local,
        json.load(open(os.path.expanduser(a.cookies_file))),
        mode=0o600,
    )

    # 2. deploy (put()/get() route through cp locally, scp remotely — see profile.local)
    rdir = f"/dev/shm/astrolabe-replay-{_target_slug(dom)}-{_new_run_id()}"
    _track_remote_tmpfs(hp, rdir)
    ssh_argv(hp, ["mkdir", "-m", "700", "-p", rdir], timeout=20)
    for f in ("replay.py", "security.py", "payloads.py", "credentials.py"):
        put(hp, os.path.join(HERE, f), f"{rdir}/{f}")
    put(hp, cookies_local, f"{rdir}/cookies.json")
    put(hp, os.path.expanduser(a.auth_file), f"{rdir}/auth.map.json")
    put(hp, a.op, f"{rdir}/op.json")
    ssh_argv(hp, ["chmod", "600", f"{rdir}/cookies.json", f"{rdir}/auth.map.json"], timeout=15)

    # 3. replay via curl_cffi (browserless, TLS-matched, high-frequency)
    rep = [
        hp.http_py,
        "replay.py",
        "--cookies",
        f"{rdir}/cookies.json",
        "--auth",
        f"{rdir}/auth.map.json",
        "--op-file",
        f"{rdir}/op.json",
        "--outdir",
        rdir,
        "--repeat",
        str(a.repeat),
        "--interval",
        str(a.interval),
    ]
    if a.vary:
        rep += ["--vary", a.vary]
    print("[replay] curl_cffi replay …")
    rr = ssh_argv(hp, rep, cwd=rdir, timeout=a.timeout, check=False)
    print((rr.stdout or "")[-1500:])
    _require_success(rr, "TLS-matched replay")

    # 5. pull results only (no tokens), cleanup
    get(hp, f"{rdir}/replay.json", os.path.join(out, "replay.json"))
    staged_replay = os.path.join(out, "replay.json")
    if not os.path.isfile(staged_replay):
        raise PartialCaptureError("replay run is partial; staged replay.json is missing")
    # Parsing before promotion rejects truncated output and prevents reuse of a
    # prior replay.json after a failed transfer.
    json.load(open(staged_replay))
    ssh_argv(hp, ["rm", "-rf", "--", rdir], timeout=20)
    _remove_local_secret(cookies_local)
    _promote_staging_directory(out, final_out)
    print(f"[cleanup] removed {hp.host}:{rdir} + local cookies")
    print(f"\n✓ {final_out}/replay.json")


def cmd_mcpgen(a):
    import sys as _s

    _s.argv = (
        ["mcpgen", a.capture_dir]
        + (["--out", a.out] if a.out else [])
        + (["--include-mutations"] if a.include_mutations else [])
        + (["--overrides", a.overrides] if a.overrides else [])
        + (["--noise-pattern", a.noise_pattern] if a.noise_pattern else [])
        + (["--read-pattern", a.read_pattern] if a.read_pattern else [])
    )
    mg.main()


def cmd_import_openapi(a):
    import sys as _s

    from . import openapi_import as oi

    _s.argv = (
        ["import-openapi", a.doc]
        + (["--out", a.out] if a.out else [])
        + (["--base-domain", a.base_domain] if a.base_domain else [])
        + [value for spec in a.external_ref for value in ("--external-ref", spec)]
    )
    oi.main()


@_guaranteed_cleanup
def cmd_scan(a):
    """Deterministic source-scan → recipe scaffold.

    Runs on the pipeline host (needs cloakbrowser for the live-DOM evidence
    pass). Respects the resolved profile's local/remote setting; proxies
    through Burp unless --no-burp. The scan is read-only (navigation + DOM
    inspection only, never clicks)."""
    hp = _resolve(a)
    pf = preflight(hp)
    proxy = pf["burp_proxy"] if not a.no_burp else None

    final_out = os.path.abspath(a.out or f"./scan-{up_urlparse(a.url).netloc}")
    os.makedirs(os.path.dirname(final_out) or ".", exist_ok=True)
    out = tempfile.mkdtemp(prefix=".astrolabe-stage-", dir=os.path.dirname(final_out) or ".")
    _track_staging_dir(out)
    rdir = f"/dev/shm/astrolabe-scan-{_new_run_id()}"
    _track_remote_tmpfs(hp, rdir)
    ssh_argv(hp, ["mkdir", "-m", "700", "-p", rdir], timeout=20)
    put(hp, os.path.join(HERE, "scan.py"), f"{rdir}/scan.py")
    put(hp, os.path.join(HERE, "discovery.py"), f"{rdir}/discovery.py")
    put(hp, os.path.join(HERE, "security.py"), f"{rdir}/security.py")
    put(hp, os.path.join(HERE, "payloads.py"), f"{rdir}/payloads.py")
    put(hp, os.path.join(HERE, "browser.py"), f"{rdir}/browser.py")

    cmd = [
        hp.cloak_py,
        "scan.py",
        a.url,
        "--outdir",
        rdir,
        "--max-surfaces",
        str(a.max_surfaces),
        "--static-concurrency",
        str(getattr(a, "static_concurrency", 4)),
        "--max-static-requests",
        str(getattr(a, "max_static_requests", 50)),
        "--max-origin-requests",
        str(getattr(a, "max_origin_requests", 25)),
        "--max-total-requests",
        str(getattr(a, "max_total_requests", 100)),
        "--max-static-resources",
        str(getattr(a, "max_static_resources", 25)),
        "--max-static-bytes",
        str(getattr(a, "max_static_bytes", 20_000_000)),
        "--max-static-resource-bytes",
        str(getattr(a, "max_static_resource_bytes", 4_000_000)),
        "--delay-ms",
        str(getattr(a, "delay_ms", 250)),
        "--account-risk",
        str(getattr(a, "account_risk", "standard")),
    ]
    if getattr(a, "working_hours_utc", None):
        cmd += ["--working-hours-utc", a.working_hours_utc]
    for host in getattr(a, "allowed_static_host", []):
        cmd += ["--allowed-static-host", host]
    for path in getattr(a, "authorized_path", []):
        cmd += ["--authorized-path", path]
    for path in getattr(a, "prohibited_path", []):
        cmd += ["--prohibited-path", path]
    for action in getattr(a, "prohibited_action", []):
        cmd += ["--prohibited-action", action]
    for seed in getattr(a, "operator_seed", []):
        cmd += ["--operator-seed", seed]
    if proxy:
        cmd += ["--proxy", proxy]
    if pf.get("byparr") and not a.no_byparr:
        cmd += ["--byparr", pf["byparr"]]
    if a.no_js_mine:
        cmd += ["--no-js-mine"]
    print(f"[scan] running on {hp.host} …")
    r = run_capture_argv(hp, cmd, a.timeout, cwd=rdir)
    # show scan progress lines, drop scan.py's own trailing success block
    # (cli prints the location-correct version after pulling artifacts)
    for line in (r.stdout or "").splitlines():
        if line.startswith(("[scan]", "[sitemap]", "[scan-ERR]")):
            print(line)
    _require_success(r, "source scan")

    # pull the three artifacts (all PII-safe — no tokens, no response bodies)
    for f in ("scan.json", "scan.md", "recipe.py"):
        get(hp, f"{rdir}/{f}", os.path.join(out, f))
    required = ("scan.json", "scan.md", "recipe.py")
    missing = [name for name in required if not os.path.isfile(os.path.join(out, name))]
    if missing:
        raise PartialCaptureError(
            f"scan is partial; staged artifacts missing: {', '.join(missing)}"
        )
    json.load(open(os.path.join(out, "scan.json")))
    ssh_argv(hp, ["rm", "-rf", "--", rdir], timeout=20)
    _promote_staging_directory(out, final_out)
    host = up_urlparse(a.url).netloc
    print(f"\n✓ {final_out}/scan.json | scan.md | recipe.py")
    print(f"  review scan.md, then: cp {final_out}/recipe.py surfaces/{host}.recipe.py")
    print(
        f"  next: astrolabe map {host} --recipe surfaces/{host}.recipe.py --no-auth --no-burp --schema"
    )


def up_urlparse(u):
    import urllib.parse as _u

    return _u.urlparse(u)


@_guaranteed_cleanup
def cmd_contract(a):
    hp = _resolve(a)
    cap = os.path.abspath(a.capture_dir)
    verify_local = None
    if a.execute:
        dom = normalize_host(
            a.domain or json.load(open(os.path.join(cap, "endpoints.json")))["base_domain"]
        )
        preflight(hp)
        if not a.cookies_file:
            raise ConfigurationError("--cookies-file is required for --execute")
        cookies_local = os.path.join(cap, "_cookies.json")
        _track_local_secret(cookies_local)
        atomic_write_json(
            cookies_local,
            json.load(open(os.path.expanduser(a.cookies_file))),
            mode=0o600,
        )
        rdir = f"/dev/shm/astrolabe-contract-{_target_slug(dom)}-{_new_run_id()}"
        _track_remote_tmpfs(hp, rdir)
        ssh_argv(hp, ["mkdir", "-m", "700", "-p", rdir], timeout=20)
        for helper in CONTRACT_HELPERS:
            put(hp, os.path.join(HERE, helper), f"{rdir}/{helper}")
        put(hp, cookies_local, f"{rdir}/cookies.json")
        validation_contract = os.path.join(cap, "_validation-contract.json")
        _register_cleanup(
            lambda: os.path.exists(validation_contract) and os.unlink(validation_contract)
        )
        atomic_write_json(validation_contract, ct.build_from_capture(cap))
        put(hp, validation_contract, f"{rdir}/contract.json")
        rec: list[str] = []
        if a.recipe:
            declarative = a.recipe.lower().endswith(".json")
            if not declarative and not a.trusted_recipe:
                raise SafetyRefusalError(
                    "Python recipes require --trusted-recipe; they run in an isolated worker "
                    "unless --allow-inprocess-python-recipe is also supplied"
                )
            if not declarative and not getattr(a, "allow_inprocess_python_recipe", False):
                _require_recipe_sandbox(hp)
            remote_recipe = (
                f"{rdir}/{SITE_RECIPE_STEM}.json"
                if declarative
                else f"{rdir}/{SITE_RECIPE_STEM}.py"
            )
            put(hp, a.recipe, remote_recipe)
            rec = [
                "--recipe",
                remote_recipe,
            ]
            if not declarative:
                rec.append("--trusted-recipe")
                if getattr(a, "allow_inprocess_python_recipe", False):
                    rec.append("--allow-inprocess-python-recipe")
        cmd = [
            hp.cloak_py,
            "contract_verify.py",
            "--cookies",
            f"{rdir}/cookies.json",
            "--outdir",
            rdir,
            "--base-domain",
            dom,
            "--gql-marker",
            "/graphql",
            "--contract",
            f"{rdir}/contract.json",
            *rec,
        ]
        for operation_id in a.allow_mutation:
            cmd += ["--allow-mutation", operation_id]
        if a.enable_mutation_execution:
            cmd += ["--enable-mutation-execution"]
        print("[contract] active verification via warm browser …")
        r = run_capture_argv(hp, cmd, a.timeout, cwd=rdir)
        print((r.stdout or "")[-1600:])
        _require_success(r, "active contract verification")
        fd, verify_local = tempfile.mkstemp(prefix=".astrolabe-verify-", suffix=".json", dir=cap)
        os.close(fd)
        os.unlink(verify_local)
        _register_cleanup(lambda: os.path.exists(verify_local) and os.unlink(verify_local))
        get(hp, f"{rdir}/verify.json", verify_local)
        if not os.path.isfile(verify_local):
            raise PartialCaptureError(
                "active verification is partial; staged verify.json is missing"
            )
        json.load(open(verify_local))
        ssh_argv(hp, ["rm", "-rf", "--", rdir], timeout=20)
        _remove_local_secret(cookies_local)
    argv = ["contract", cap]
    if a.merge:
        argv += ["--merge", a.merge]
    if verify_local:
        argv += ["--active", verify_local]
    import sys as _s

    _s.argv = argv
    ct.main()


def cmd_recipe(a):
    """Lint a per-site recipe .py, delegating to astrolabe.recipe exactly the way
    cmd_mcpgen/cmd_contract delegate to their modules (build sys.argv, call
    main()). Imported locally (not at module scope) because astrolabe/recipe.py
    is owned by a concurrent workstream and may not exist yet on this
    checkout -- the subcommand must still register and cli.py must still
    import cleanly either way."""
    try:
        from . import recipe as rc
    except ImportError as e:
        raise GenerationError(f"astrolabe.recipe is unavailable: {safe_text(e)}") from e

    import sys as _s

    _s.argv = ["recipe", a.recipe_file]
    rc.main()


def cmd_check(_a):
    """Run the same mandatory local quality gates as CI."""
    commands = (
        [sys.executable, "-m", "ruff", "check", "tests/", "astrolabe/"],
        [sys.executable, "-m", "ruff", "format", "--check", "tests/"],
        [sys.executable, "-m", "mypy", "tests", "astrolabe"],
        [sys.executable, "-m", "pytest"],
    )
    for command in commands:
        result = subprocess.run(command)
        if result.returncode:
            raise ValidationError(
                f"quality gate {command[3] if len(command) > 3 else command[-1]} failed"
            )


def cmd_inspect_artifact(a):
    from .artifact import load_manifest, verify_manifest
    from .ir import load_graph

    path = os.path.abspath(a.path)
    manifest_path = os.path.join(path, "artifact-manifest.json") if os.path.isdir(path) else path
    if os.path.basename(manifest_path) == "graph.json":
        graph = load_graph(manifest_path)
        report = {
            "valid": True,
            "artifact_type": "backend-graph",
            "schema_version": graph["schema_version"],
            "target": graph["target"],
            "runs": len(graph["runs"]),
            "operations": len(graph["operations"]),
            "evidence": len(graph["evidence"]),
        }
    else:
        manifest = load_manifest(manifest_path)
        failures = verify_manifest(os.path.dirname(manifest_path), manifest)
        report = {
            "valid": not failures,
            "artifact_type": manifest.artifact_type,
            "schema_version": manifest.schema_version,
            "artifact_schema_version": manifest.artifact_schema_version,
            "run_id": manifest.run_id,
            "target": manifest.target,
            "completeness": manifest.completeness,
            "checksum_failures": failures,
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["valid"]:
        raise ValidationError("artifact checksum or schema validation failed")


def cmd_migrate_artifact(a):
    from .artifact import atomic_write_json, read_json_artifact
    from .ir import migrate_graph

    source = os.path.abspath(a.path)
    value = read_json_artifact(source, label="backend graph")
    migrated = migrate_graph(value)
    destination = os.path.abspath(a.out or f"{source}.migrated.json")
    atomic_write_json(destination, migrated)
    print(f"[migrate-artifact] schema v{migrated['schema_version']} -> {destination}")


def build_parser():
    ap = argparse.ArgumentParser(
        prog="astrolabe", description="Authenticated API/GraphQL recon orchestrator"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    machine = argparse.ArgumentParser(add_help=False)
    machine.add_argument(
        "--json", action="store_true", help="emit one stable machine-readable result envelope"
    )
    p = sub.add_parser(
        "preflight", parents=[machine], help="health-check the pipeline host + egress safety"
    )
    p.add_argument(
        "--host", default=None, help="pipeline host alias (default: resolved via profile)"
    )
    p.add_argument(
        "--local",
        action="store_true",
        default=None,
        help="run in-process on THIS machine (it is the host; no ssh/scp)",
    )
    p.set_defaults(func=cmd_preflight)

    m = sub.add_parser("map", parents=[machine], help="map a site's API surface")
    m.add_argument("domain")
    m.add_argument(
        "--host", default=None, help="pipeline host alias (default: resolved via profile)"
    )
    m.add_argument(
        "--local",
        action="store_true",
        default=None,
        help="run the pipeline in-process on THIS machine (it is the host; no ssh/scp)",
    )
    m.add_argument("--recipe", help="declarative recipe .json or trusted Python recipe .py")
    m.add_argument(
        "--trusted-recipe",
        action="store_true",
        help="acknowledge that the Python recipe is trusted executable code",
    )
    m.add_argument(
        "--allow-inprocess-python-recipe",
        action="store_true",
        help="second acknowledgement for unconstrained Python recipe execution",
    )
    m.add_argument("--seeds", default="", help="comma-separated seed URLs")
    m.add_argument("--crawl", type=int, default=0)
    m.add_argument(
        "--block-assets",
        action="store_true",
        help="skip images/media/fonts to reserve bounded requests for APIs",
    )
    m.add_argument(
        "--recover-persisted",
        action="store_true",
        help="recover exact APQ documents from browser Web Crypto hash inputs",
    )
    m.add_argument(
        "--browser",
        choices=("vivaldi", "chrome", "chromium", "brave", "edge"),
        help="explicitly import this domain's cookies from a local Linux browser",
    )
    m.add_argument("--profile", default="Default", help="browser profile name (with --browser)")
    m.add_argument("--max-total-requests", type=int, default=10_000)
    m.add_argument("--max-origin-requests", type=int, default=5_000)
    m.add_argument("--max-operation-requests", type=int, default=500)
    m.add_argument("--rate-limit-reserve", type=int, default=1)
    m.add_argument(
        "--browser-concurrency",
        type=int,
        default=1,
        help="independent browser-process shards (1-8; authenticated targets require opt-in)",
    )
    m.add_argument(
        "--allow-auth-concurrency",
        action="store_true",
        help="acknowledge target-specific account/rate risk for authenticated browser shards",
    )
    m.add_argument("--out")
    m.add_argument(
        "--cookies-file",
        help="Playwright-format cookie JSON export (bring your own; required unless --no-auth)",
    )
    m.add_argument("--no-auth", action="store_true", help="unauthenticated map (skip cookies)")
    m.add_argument("--no-burp", action="store_true", help="don't proxy through Burp")
    m.add_argument(
        "--schema", action="store_true", help="recover schema via clairvoyance if introspection off"
    )
    m.add_argument(
        "--schema-conc",
        type=int,
        default=1,
        help="clairvoyance concurrency (keep low on live accts)",
    )
    m.add_argument("--schema-timeout", type=int, default=900)
    m.add_argument(
        "--openapi", action="store_true", help="also emit REST OpenAPI via har-to-openapi"
    )
    m.add_argument("--timeout", type=int, default=600, help="capture timeout (s)")
    m.set_defaults(func=cmd_map)

    r = sub.add_parser(
        "replay", parents=[machine], help="browserless TLS-matched high-frequency op replay"
    )
    r.add_argument("domain")
    r.add_argument("--op", required=True, help="op-file JSON (alias, query, variables, extract)")
    r.add_argument(
        "--host", default=None, help="pipeline host alias (default: resolved via profile)"
    )
    r.add_argument(
        "--local",
        action="store_true",
        default=None,
        help="run the pipeline in-process on THIS machine (it is the host; no ssh/scp)",
    )
    r.add_argument(
        "--cookies-file",
        required=True,
        help="Playwright-format cookie JSON export (bring your own)",
    )
    r.add_argument(
        "--auth-file",
        required=True,
        help="pre-made auth.map.json credential bundle (scoped headers per operation alias)",
    )
    r.add_argument("--vary", default="", help="dotpath=v1,v2,... variable sweep")
    r.add_argument("--repeat", type=int, default=1)
    r.add_argument("--interval", type=float, default=0.0)
    r.add_argument("--out")
    r.add_argument("--timeout", type=int, default=300)
    r.set_defaults(func=cmd_replay)

    g = sub.add_parser(
        "mcp-gen", parents=[machine], help="generate a typed MCP toolpack from a capture dir"
    )
    g.add_argument("capture_dir")
    g.add_argument("--out")
    g.add_argument("--include-mutations", action="store_true")
    g.add_argument(
        "--overrides",
        help="dir of <alias>.op.json files whose (minimal, proven) query replaces the "
        "captured verbose one — more reliable to execute",
    )
    g.add_argument(
        "--noise-pattern",
        help="extra regex of site-specific telemetry/UI-chrome aliases to gate, applied "
        "in addition to the generic defaults",
    )
    g.add_argument(
        "--read-pattern",
        help="regex of REST paths to force-classify as reads (e.g. a POST-based search)",
    )
    g.set_defaults(func=cmd_mcpgen)

    io_p = sub.add_parser(
        "import-openapi",
        parents=[machine],
        help="build endpoints.json from an OpenAPI/Swagger doc (no capture)",
    )
    io_p.add_argument("doc", help="path to an OpenAPI 3.x / Swagger 2.0 JSON file")
    io_p.add_argument("--out", help="endpoints.json (default: alongside the doc)")
    io_p.add_argument("--base-domain", help="override the target host (else read from the doc)")
    io_p.add_argument(
        "--external-ref",
        action="append",
        default=[],
        metavar="URI=LOCAL_PATH",
        help="authorize one exact external $ref URI using a bounded local document",
    )
    io_p.set_defaults(func=cmd_import_openapi)

    sc = sub.add_parser(
        "scan", parents=[machine], help="deterministic source-scan → recipe scaffold"
    )
    sc.add_argument("url", help="seed URL (any page on the target site)")
    sc.add_argument(
        "--host", default=None, help="pipeline host alias (default: resolved via profile)"
    )
    sc.add_argument(
        "--local",
        action="store_true",
        default=None,
        help="run in-process on THIS machine (no ssh/scp)",
    )
    sc.add_argument("--out", help="output dir (default ./scan-<host>)")
    sc.add_argument("--no-burp", action="store_true", help="don't proxy through Burp")
    sc.add_argument("--no-byparr", action="store_true", help="don't use byparr CF fallback")
    sc.add_argument(
        "--max-surfaces", type=int, default=20, help="cap on number of surfaces to deep-scan"
    )
    sc.add_argument("--static-concurrency", type=int, default=4)
    sc.add_argument("--max-static-requests", type=int, default=50)
    sc.add_argument("--max-origin-requests", type=int, default=25)
    sc.add_argument("--max-total-requests", type=int, default=100)
    sc.add_argument("--max-static-resources", type=int, default=25)
    sc.add_argument("--max-static-bytes", type=int, default=20_000_000)
    sc.add_argument("--max-static-resource-bytes", type=int, default=4_000_000)
    sc.add_argument("--allowed-static-host", action="append", default=[])
    sc.add_argument("--delay-ms", type=int, default=250)
    sc.add_argument("--working-hours-utc", metavar="START-END")
    sc.add_argument(
        "--account-risk",
        choices=("anonymous", "low", "standard", "sensitive", "privileged"),
        default="standard",
    )
    sc.add_argument("--authorized-path", action="append", default=[])
    sc.add_argument("--prohibited-path", action="append", default=[])
    sc.add_argument("--prohibited-action", action="append", default=[])
    sc.add_argument("--operator-seed", action="append", default=[])
    sc.add_argument(
        "--no-js-mine",
        action="store_true",
        help="skip JS-bundle endpoint mining (faster, less complete)",
    )
    sc.add_argument("--timeout", type=int, default=420, help="scan timeout (s)")
    sc.set_defaults(func=cmd_scan)

    ct_p = sub.add_parser(
        "contract",
        parents=[machine],
        help="build a durable executable typed contract from a capture",
    )
    ct_p.add_argument("capture_dir")
    ct_p.add_argument("--merge", help="prior contract.json (completeness + drift)")
    ct_p.add_argument("--execute", action="store_true", help="actively verify ops via warm browser")
    ct_p.add_argument(
        "--domain", help="target domain for --execute (default: capture's base_domain)"
    )
    ct_p.add_argument("--recipe", help="recipe to warm surfaces for --execute")
    ct_p.add_argument(
        "--trusted-recipe",
        action="store_true",
        help="acknowledge that the Python recipe is trusted executable code",
    )
    ct_p.add_argument(
        "--allow-inprocess-python-recipe",
        action="store_true",
        help="second acknowledgement for unconstrained Python recipe execution",
    )
    ct_p.add_argument(
        "--allow-mutation",
        action="append",
        default=[],
        metavar="EXACT_OPERATION_ID",
        help="allow exactly one mutation during verification (repeatable)",
    )
    ct_p.add_argument(
        "--enable-mutation-execution",
        action="store_true",
        help="second runtime acknowledgement required with --allow-mutation",
    )
    ct_p.add_argument(
        "--host", default=None, help="pipeline host alias (default: resolved via profile)"
    )
    ct_p.add_argument(
        "--local",
        action="store_true",
        default=None,
        help="run --execute verification in-process on THIS machine (no ssh/scp)",
    )
    ct_p.add_argument(
        "--cookies-file",
        help="Playwright-format cookie JSON export for --execute (bring your own; required)",
    )
    ct_p.add_argument("--timeout", type=int, default=400)
    ct_p.set_defaults(func=cmd_contract)

    rp = sub.add_parser(
        "recipe", parents=[machine], help="lint a per-site recipe .py (SURFACES + drive())"
    )
    rp.add_argument("recipe_file", help="path to the recipe .py to lint")
    rp.set_defaults(func=cmd_recipe)

    inspect = sub.add_parser(
        "inspect-artifact", parents=[machine], help="validate an artifact and its checksums"
    )
    inspect.add_argument("path", help="graph.json, artifact-manifest.json, or artifact directory")
    inspect.set_defaults(func=cmd_inspect_artifact)

    migrate = sub.add_parser(
        "migrate-artifact", parents=[machine], help="migrate a backend graph artifact"
    )
    migrate.add_argument("path", help="source graph.json")
    migrate.add_argument("--out", help="output path (default: <source>.migrated.json)")
    migrate.set_defaults(func=cmd_migrate_artifact)

    check = sub.add_parser("check", parents=[machine], help="run the complete local CI gate")
    check.set_defaults(func=cmd_check)

    return ap


def _emit_cli_failure(
    *, machine: bool, command: str | None, category: str, code: int, error
) -> None:
    message = safe_text(error)
    if machine:
        print(
            json.dumps(
                {
                    "ok": False,
                    "command": command,
                    "error": {"category": category, "code": code, "message": message},
                },
                sort_keys=True,
            )
        )
    else:
        print(f"astrolabe: {category}: {message}", file=sys.stderr)


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    machine_requested = "--json" in arguments
    try:
        a = build_parser().parse_args(arguments)
    except SystemExit as exc:
        if machine_requested:
            code = int(exc.code) if isinstance(exc.code, int) else int(ExitCode.USAGE)
            _emit_cli_failure(
                machine=True,
                command=next((v for v in arguments if not v.startswith("-")), None),
                category="usage",
                code=code,
                error="invalid command arguments",
            )
        raise
    previous_term = signal.getsignal(signal.SIGTERM)

    def terminate(_signum, _frame):
        raise InterruptedCLIError("terminated")

    signal.signal(signal.SIGTERM, terminate)
    try:
        progress = io.StringIO() if a.json else None
        try:
            if progress is None:
                result = a.func(a)
            else:
                with contextlib.redirect_stdout(progress):
                    result = a.func(a)
        except BaseException:
            if progress is not None and progress.getvalue():
                print(progress.getvalue(), end="", file=sys.stderr)
            raise
        if progress is not None:
            if progress.getvalue():
                print(progress.getvalue(), end="", file=sys.stderr)
            print(
                json.dumps(
                    {
                        "ok": True,
                        "command": a.cmd,
                        "result": result if result is not None else {},
                    },
                    sort_keys=True,
                )
            )
    except CLIError as exc:
        _emit_cli_failure(
            machine=a.json,
            command=a.cmd,
            category=exc.category,
            code=int(exc.exit_code),
            error=exc,
        )
        raise SystemExit(int(exc.exit_code)) from None
    except KeyboardInterrupt:
        code = int(ExitCode.INTERRUPTED)
        _emit_cli_failure(
            machine=a.json,
            command=a.cmd,
            category="interrupted",
            code=code,
            error="interrupted",
        )
        raise SystemExit(code) from None
    except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        code = int(ExitCode.VALIDATION)
        _emit_cli_failure(
            machine=a.json,
            command=a.cmd,
            category="validation",
            code=code,
            error=exc,
        )
        raise SystemExit(code) from None
    except (ValueError, TypeError) as exc:
        code = int(ExitCode.CONFIGURATION)
        _emit_cli_failure(
            machine=a.json,
            command=a.cmd,
            category="configuration",
            code=code,
            error=exc,
        )
        raise SystemExit(code) from None
    except SystemExit as exc:
        raw_code = exc.code if isinstance(exc.code, int) else int(ExitCode.UPSTREAM)
        stable_codes = {int(value) for value in ExitCode}
        code = raw_code if raw_code in stable_codes else int(ExitCode.UPSTREAM)
        _emit_cli_failure(
            machine=a.json,
            command=a.cmd,
            category="upstream",
            code=code,
            error=exc.code or "upstream command failed",
        )
        raise SystemExit(code) from None
    except Exception as exc:
        code = int(ExitCode.UPSTREAM)
        _emit_cli_failure(
            machine=a.json,
            command=a.cmd,
            category="upstream",
            code=code,
            error=exc,
        )
        raise SystemExit(code) from None
    finally:
        signal.signal(signal.SIGTERM, previous_term)


if __name__ == "__main__":
    main()

"""Browser driver behind :mod:`astrolabe.fetch`.

Ported from ``cffetch``'s ``netns_fetch.py``. It is a separate process on
purpose: ``astrolabe fetch --netns`` re-execs exactly this module inside
``ip netns exec``, so egress selection must not depend on state held by the
controller.

It drives Playwright directly rather than going through
:func:`astrolabe.browser.launch_context`. That abstraction is built for the
in-process capture engines, which need a *context*; this driver also has to
support ``launch_persistent_context`` (``--profile``), where the browser and the
context are the same object and the profile directory is the point. Reaching
for the lower-level API here keeps one capability that the abstraction would
have to grow anyway.

Emits exactly one JSON verdict on stdout:

``ok``
    the requested content was served (a 4xx with no recognised wall is still
    ``ok``; the caller classifies it).
``challenge``
    a Cloudflare interstitial; the controller hands it to byparr.
``soft_block``
    a non-Cloudflare bot wall (PerimeterX, DataDome, Akamai, Kasada, or a
    generic "are you a robot" page). ``vendor`` names it when recognised.
``error``
    launch, proxy or navigation failure.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from urllib.parse import urlsplit, unquote

CF_MARKERS = (
    "just a moment",
    "__cf_chl",
    "cf-chl",
    "challenge-platform",
    "turnstile",
    "enable javascript and cookies to continue",
    "cf_chl_opt",
)

# Non-Cloudflare walls. Deliberately separate from CF_MARKERS: byparr cannot
# clear these, so sending one there spends a solve and fails anyway. Narrow on
# purpose — a loose list would fire the solver at ordinary content pages.
SOFT_BLOCK_MARKERS = (
    "prove your humanity",
    "are you a robot",
    "checking your browser",
    "one more step",
    "unusual traffic from your computer",
    "verify you are human",
    "confirm you are human",
    "robot or human?",
)

# Matched against a small page (an interstitial, not a content page that merely
# loads the vendor's sensor script). Order matters: first hit wins.
VENDOR_MARKERS = (
    (
        "perimeterx",
        ("px-captcha", "_pxcaptcha", "perimeterx", "blockscript", "/px/captcha", "press & hold"),
    ),
    ("datadome", ("captcha-delivery.com", "geo.captcha-delivery", "dd.js", "datadome")),
    (
        "akamai",
        (
            "access denied",
            "errors.edgesuite.net",
            "reference&#32;&#35;",
            "sec-if-cpt",
            "/_sec/cp_challenge",
        ),
    ),
    ("kasada", ("x-kpsdk", "kpsdk")),
)
WALL_STATUSES = (401, 403, 405, 412, 418, 429, 435, 503)
WALL_MAX_BYTES = 60_000


def verdict(**fields: object) -> None:
    """Emit the verdict and stop. Exit 0: the verdict carries the status."""
    print(json.dumps(fields))
    raise SystemExit(0)


def vendor_wall(code: int, headers: dict[str, str], body: str, title: str) -> str | None:
    """Name the vendor of a bot wall, or ``None``.

    Headers are decisive on a wall status; body markers only count on a small
    page, so a product page that embeds a sensor script is not mistaken for a
    block.
    """
    if code in WALL_STATUSES:
        if "x-datadome" in headers or "x-dd-b" in headers:
            return "datadome"
        if any(name.startswith("x-kpsdk") for name in headers):
            return "kasada"
        if "akamaighost" in headers.get("server", "").lower() and code in (403, 429):
            return "akamai"
    small = len(body) < WALL_MAX_BYTES
    if not (small or code in WALL_STATUSES):
        return None
    haystack = body + " " + title.lower()
    for name, markers in VENDOR_MARKERS:
        # Reaching here already means the page is small or the status says wall,
        # so a content page that merely loads the sensor script was filtered out.
        if any(marker in haystack for marker in markers):
            return name
    return None


def parse_proxy(url: str) -> dict[str, str]:
    """``http://user:pass@host:port`` -> Playwright proxy dict (creds unquoted)."""
    parts = urlsplit(url if "://" in url else "http://" + url)
    authority = f"{parts.scheme}://{parts.hostname}"
    if parts.port:
        authority += f":{parts.port}"
    proxy = {"server": authority}
    if parts.username:
        proxy["username"] = unquote(parts.username)
    if parts.password:
        proxy["password"] = unquote(parts.password)
    return proxy


def parse_headers(items: list[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in items or []:
        key, separator, value = item.partition(":")
        if not separator:
            raise SystemExit(f"bad --header {item!r}; want 'Name: value'")
        headers[key.strip()] = value.strip()
    return headers


def run_actions(page, actions: list[str], timeout: int) -> None:
    """Ordered page steps, for UIs whose API fires only on input.

    ``fill:SEL=TEXT``, ``type:SEL=TEXT`` (key by key), ``click:SEL``,
    ``press:KEY``, ``wait:MS``, ``waitfor:SEL``.
    """
    for action in actions:
        kind, _, argument = action.partition(":")
        if kind in ("fill", "type"):
            selector, _, text = argument.rpartition("=")
            locator = page.locator(selector).first
            locator.wait_for(timeout=timeout)
            if kind == "fill":
                locator.fill(text)
            else:
                locator.click()
                page.keyboard.type(text, delay=90)
        elif kind == "click":
            page.locator(argument).first.click(timeout=timeout)
        elif kind == "press":
            page.keyboard.press(argument)
        elif kind == "wait":
            page.wait_for_timeout(int(argument))
        elif kind == "waitfor":
            page.wait_for_selector(argument, timeout=timeout)
        else:
            raise SystemExit(f"bad --action {action!r}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="astrolabe.fetch_driver")
    parser.add_argument("url")
    parser.add_argument("--cookies")
    parser.add_argument("--ua")
    parser.add_argument("--timeout", type=int, default=45000)
    parser.add_argument("--out")
    parser.add_argument("--proxy")
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--profile")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--data")
    parser.add_argument("--mode", choices=("auto", "nav", "fetch"), default="auto")
    parser.add_argument(
        "--wait-until",
        default="domcontentloaded",
        choices=("commit", "domcontentloaded", "load", "networkidle"),
    )
    parser.add_argument("--wait-for")
    parser.add_argument("--settle-ms", type=int, default=0)
    parser.add_argument("--warm", action="append", default=[])
    parser.add_argument("--warm-settle-ms", type=int, default=2500)
    parser.add_argument("--locale")
    parser.add_argument("--timezone")
    parser.add_argument("--geolocation")
    parser.add_argument("--viewport")
    parser.add_argument("--browser-arg", action="append", default=[])
    parser.add_argument("--browser-path", default=os.environ.get("CLOAKBROWSER_PATH"))
    parser.add_argument("--dump-cookies")
    parser.add_argument("--screenshot")
    parser.add_argument("--capture")
    parser.add_argument("--capture-out")
    parser.add_argument("--exit-ip", action="store_true")
    parser.add_argument("--action", action="append", default=[])
    return parser


def _launch_kwargs(args: argparse.Namespace) -> dict:
    # Fall back to Playwright's own Chromium when the stealth binary is absent,
    # so the driver still works on a clone without the `stealth` extra.
    executable = (
        args.browser_path if args.browser_path and os.path.exists(args.browser_path) else None
    )
    kwargs: dict = {
        "headless": not args.headful,
        "ignore_default_args": ["--enable-automation"],
        # --class lets Hyprland park a headful window on the invisible
        # special:cloakscratch workspace; it must never surface.
        "args": ["--no-sandbox", "--class=cloakbrowser", *args.browser_arg],
    }
    if executable:
        kwargs["executable_path"] = executable
    if args.proxy:
        kwargs["proxy"] = parse_proxy(args.proxy)
    return kwargs


def _context_kwargs(args: argparse.Namespace, headers: dict[str, str], mode: str) -> dict:
    options: dict = {}
    if args.ua:
        options["user_agent"] = args.ua
    if args.locale:
        options["locale"] = args.locale
    if args.timezone:
        options["timezone_id"] = args.timezone
    if args.geolocation:
        latitude, longitude = (float(value) for value in args.geolocation.split(","))
        options["geolocation"] = {"latitude": latitude, "longitude": longitude}
        options["permissions"] = ["geolocation"]
    if args.viewport:
        width, height = (int(value) for value in args.viewport.lower().split("x"))
        options["viewport"] = {"width": width, "height": height}
    if headers and mode == "nav":
        options["extra_http_headers"] = headers
    return options


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    headers = parse_headers(args.header)
    mode = args.mode
    if mode == "auto":
        mode = "fetch" if (args.method.upper() != "GET" or args.data is not None) else "nav"

    from playwright.sync_api import sync_playwright

    launch = _launch_kwargs(args)
    context_options = _context_kwargs(args, headers, mode)
    with sync_playwright() as playwright:
        try:
            if args.profile:
                context = playwright.chromium.launch_persistent_context(
                    args.profile, **launch, **context_options
                )
                browser = None
            else:
                browser = playwright.chromium.launch(**launch)
                context = browser.new_context(**context_options)
        except Exception as exc:
            verdict(status="error", error=f"launch: {str(exc)[:400]}")

        if args.cookies:
            try:
                with open(args.cookies, encoding="utf-8") as handle:
                    context.add_cookies(json.load(handle))
            except Exception as exc:
                verdict(status="error", error=f"cookie load: {exc}")

        captured: list[dict] = []
        if args.capture:
            pattern = re.compile(args.capture)

            def on_response(response) -> None:
                if not pattern.search(response.url):
                    return
                try:
                    body = response.text()
                except Exception:
                    body = None
                captured.append(
                    {
                        "url": response.url,
                        "status": response.status,
                        "method": response.request.method,
                        "content_type": response.headers.get("content-type"),
                        "body": body,
                    }
                )

            context.on("response", on_response)

        page = context.pages[0] if context.pages else context.new_page()
        warmed: list[dict] = []
        for warm_url in args.warm:
            try:
                response = page.goto(warm_url, timeout=args.timeout, wait_until="domcontentloaded")
                # Judge the first response, not the settled page: DataDome's
                # device check reloads into the real site once it sets its cookie.
                try:
                    warm_body = (response.text() if response else "") or ""
                except Exception:
                    warm_body = ""
                page.wait_for_timeout(args.warm_settle_ms)
                warm_code = response.status if response else 0
                warm_headers = {
                    key.lower(): value
                    for key, value in (response.headers.items() if response else [])
                }
                warmed.append(
                    {
                        "url": warm_url,
                        "http_status": warm_code,
                        "vendor": vendor_wall(warm_code, warm_headers, warm_body.lower(), ""),
                    }
                )
            except Exception as exc:
                warmed.append({"url": warm_url, "error": str(exc)[:200]})

        code, response_headers, final_url, text = 0, {}, args.url, ""
        try:
            if mode == "nav":
                response = page.goto(args.url, timeout=args.timeout, wait_until=args.wait_until)
                if args.wait_for:
                    page.wait_for_selector(args.wait_for, timeout=args.timeout)
                run_actions(page, args.action, args.timeout)
                if args.settle_ms:
                    page.wait_for_timeout(args.settle_ms)
                code = response.status if response else 0
                response_headers = {
                    key.lower(): value
                    for key, value in (response.headers.items() if response else [])
                }
                final_url = response.url if response else args.url
                text = page.content() or ""
            else:
                # In-page fetch: the real browser's TLS, cookies and sensor state,
                # from the origin the page sits on (warm it first).
                if not args.warm:
                    origin = urlsplit(args.url)
                    page.goto(
                        f"{origin.scheme}://{origin.netloc}/",
                        timeout=args.timeout,
                        wait_until="domcontentloaded",
                    )
                    page.wait_for_timeout(args.warm_settle_ms)
                result = page.evaluate(
                    """async ([url, method, headers, body]) => {
                        const r = await fetch(url, {method, headers, body: body ?? undefined,
                                                    credentials: 'include'});
                        const h = {}; r.headers.forEach((v, k) => { h[k] = v; });
                        return {status: r.status, url: r.url, headers: h, text: await r.text()};
                    }""",
                    [args.url, args.method.upper(), headers, args.data],
                )
                code, response_headers, final_url, text = (
                    result["status"],
                    result["headers"],
                    result["url"],
                    result["text"],
                )
        except Exception as exc:
            verdict(status="error", error=f"navigate: {str(exc)[:400]}", warmed=warmed)

        body = text.lower()
        body_path = None
        if args.out:
            descriptor = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(text)
            body_path = args.out

        if args.screenshot:
            try:
                page.screenshot(path=args.screenshot, full_page=False)
            except Exception:
                pass

        title = (page.title() if mode == "nav" else "") or ""
        exit_ip = None
        if args.exit_ip:
            try:
                ip_page = context.new_page()
                ip_page.goto("https://api.ipify.org?format=json", timeout=20000)
                exit_ip = json.loads(ip_page.inner_text("body")).get("ip")
            except Exception as exc:
                exit_ip = f"error: {str(exc)[:100]}"

        output_cookies = context.cookies()
        if args.dump_cookies:
            descriptor = os.open(args.dump_cookies, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(output_cookies, handle)
        if args.capture_out:
            descriptor = os.open(args.capture_out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                for record in captured:
                    handle.write(json.dumps(record) + "\n")

        user_agent = page.evaluate("navigator.userAgent")
        context.close()
        if browser:
            browser.close()

        challenged = ("cf-mitigated" in response_headers or code in (403, 503)) and any(
            marker in body for marker in CF_MARKERS
        )
        soft, vendor = None, None
        if not challenged:
            vendor = vendor_wall(code, response_headers, body, title)
            for marker in SOFT_BLOCK_MARKERS:
                if marker in body or marker in title.lower():
                    soft = marker
                    break
            if vendor and not soft:
                soft = f"vendor:{vendor}"
        verdict(
            status="challenge" if challenged else ("soft_block" if soft else "ok"),
            soft_block_marker=soft,
            vendor=vendor,
            http_status=code,
            final_url=final_url,
            rate_limited=code == 429,
            warm_vendor=next((entry["vendor"] for entry in warmed if entry.get("vendor")), None),
            title=title,
            html_len=len(body),
            body_path=body_path,
            mode=mode,
            headers=response_headers,
            exit_ip=exit_ip,
            user_agent=user_agent,
            warmed=warmed,
            captured=len(captured) if args.capture else None,
            cookie_names=sorted({cookie["name"] for cookie in output_cookies}),
            cookies=output_cookies,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

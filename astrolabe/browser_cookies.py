"""Explicit, domain-scoped Linux Chromium cookie import for authorized sessions.

Read the live SQLite database in read-only mode (including committed WAL records).
Never dump the browser database, log cookie values, or read unrelated credentials.
"""

from __future__ import annotations

import hashlib
import hmac
from contextlib import closing
from pathlib import Path
import sqlite3
import sys
import time
import os
import stat
from typing import Any

from .security import normalize_host

BROWSERS = {
    "vivaldi": ("vivaldi", ("Vivaldi Safe Storage", "Chrome Safe Storage")),
    "chrome": ("google-chrome", ("Chrome Safe Storage",)),
    "chromium": ("chromium", ("Chromium Safe Storage",)),
    "brave": ("BraveSoftware/Brave-Browser", ("Brave Safe Storage",)),
    "edge": ("microsoft-edge", ("Microsoft Edge Safe Storage",)),
}


class BrowserCookieError(ValueError):
    """Cookie import failed; diagnostics must never include secret material."""


def keyring_passwords(labels: tuple[str, ...]) -> list[bytes]:
    """Read only matching browser Safe Storage entries from unlocked collections."""
    try:
        import secretstorage
    except ImportError as exc:
        raise BrowserCookieError(
            "install astrolabe[browser-auth] for Linux keyring support"
        ) from exc
    bus = None
    try:
        bus = secretstorage.dbus_init()
        found = []
        for collection in secretstorage.get_all_collections(bus):
            if collection.is_locked():
                continue
            for item in collection.get_all_items():
                # KWallet can expose a folder prefix on its Secret Service labels.
                if item.get_label().rsplit("/", 1)[-1] not in labels or item.is_locked():
                    continue
                value = item.get_secret()
                if value not in found:
                    found.append(value)
        return found
    except Exception as exc:
        raise BrowserCookieError("browser Safe Storage keyring is unavailable or locked") from exc
    finally:
        if bus is not None:
            bus.close()


def decrypt_cookie(encrypted: bytes, host: str, version: int, passwords: list[bytes]) -> str:
    """Decrypt v10/v11 with strict PKCS#7 and schema-v24 host binding validation."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise BrowserCookieError("install astrolabe[browser-auth] for cookie decryption") from exc
    prefix, body = encrypted[:3], encrypted[3:]
    if prefix not in {b"v10", b"v11"}:
        raise BrowserCookieError("unsupported Chromium cookie encryption version")
    if not body or len(body) % 16:
        raise BrowserCookieError("invalid encrypted cookie length")
    candidates = [b"peanuts"] if prefix == b"v10" else passwords
    for password in candidates:
        key = hashlib.pbkdf2_hmac("sha1", password, b"saltysalt", 1, dklen=16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(b" " * 16)).decryptor()
        plaintext = cipher.update(body) + cipher.finalize()
        padding = plaintext[-1]
        if not 1 <= padding <= 16 or plaintext[-padding:] != bytes([padding]) * padding:
            continue
        plaintext = plaintext[:-padding]
        if version >= 24:
            if not hmac.compare_digest(plaintext[:32], hashlib.sha256(host.encode()).digest()):
                continue
            plaintext = plaintext[32:]
        try:
            return plaintext.decode("utf-8")
        except UnicodeError:
            continue
    raise BrowserCookieError("no matching browser key or cookie domain binding")


def export_cookies(browser: str, domain: str, profile: str = "Default") -> list[dict[str, Any]]:
    """Import only this domain and its subdomains; no all-host export exists."""
    if sys.platform != "linux":
        raise BrowserCookieError("native browser import currently supports Linux only")
    if browser not in BROWSERS:
        raise BrowserCookieError("unsupported Chromium browser")
    if not profile or profile in {".", ".."} or "/" in profile or "\\" in profile:
        raise BrowserCookieError("profile must be a single browser profile name")
    domain = normalize_host(domain)
    try:
        from publicsuffixlist import PublicSuffixList  # type: ignore[import-untyped]
    except ImportError as exc:
        raise BrowserCookieError(
            "install astrolabe[browser-auth] for domain scope validation"
        ) from exc
    if not PublicSuffixList().privatesuffix(domain):
        raise BrowserCookieError(
            "browser import requires a registrable domain, not a public suffix"
        )
    folder, labels = BROWSERS[browser]
    root = Path.home() / ".config" / folder / profile
    database = next(
        (p for p in (root / "Cookies", root / "Network" / "Cookies") if p.is_file()), None
    )
    if database is None:
        raise BrowserCookieError("browser profile has no cookie database")
    # Refuse redirected profiles/databases and files belonging to another OS user.
    paths = [database, *database.parents]
    paths = paths[: paths.index(Path.home()) + 1]
    for path in paths:
        info = path.lstat()
        if path.is_symlink() or info.st_uid != os.getuid():
            raise BrowserCookieError("browser profile must be owned by this user and not symlinked")
    if not stat.S_ISREG(database.lstat().st_mode):
        raise BrowserCookieError("cookie database must be a regular file")
    try:
        with closing(
            sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=5)
        ) as connection:
            connection.execute("PRAGMA query_only=ON")
            version = int(
                connection.execute("SELECT value FROM meta WHERE key='version'").fetchone()[0]
            )
            rows = connection.execute(
                "SELECT host_key,name,value,encrypted_value,path,is_secure,is_httponly,"
                "expires_utc,samesite,is_persistent FROM cookies "
                "WHERE host_key=? OR host_key=? OR host_key LIKE ?",
                (domain, "." + domain, "%." + domain),
            ).fetchmany(513)
    except (sqlite3.Error, TypeError, ValueError) as exc:
        raise BrowserCookieError("cannot read browser cookie database") from exc
    if len(rows) > 512 or any(len(r[2]) + len(r[3]) > 65536 for r in rows):
        raise BrowserCookieError("domain-scoped cookie import exceeds its size budget")
    passwords = keyring_passwords(labels) if any(r[3][:3] == b"v11" for r in rows) else []
    result = []
    failed = 0
    now = time.time()
    for (
        host,
        name,
        plain,
        encrypted,
        path,
        secure,
        http_only,
        expiry,
        same_site,
        persistent,
    ) in rows:
        expires = expiry / 1_000_000 - 11644473600 if persistent and expiry else -1
        if expires != -1 and expires <= now:
            continue
        try:
            value = decrypt_cookie(encrypted, host, version, passwords) if encrypted else plain
        except BrowserCookieError:
            failed += 1
            continue
        cookie = {
            "name": name,
            "value": value,
            "domain": host,
            "path": path or "/",
            "secure": bool(secure),
            "httpOnly": bool(http_only),
            "expires": expires,
        }
        if same_site in {0, 1, 2}:
            cookie["sameSite"] = {0: "None", 1: "Lax", 2: "Strict"}[same_site]
        result.append(cookie)
    if failed:
        raise BrowserCookieError(
            f"{failed} domain-scoped cookies failed decryption; capture not started"
        )
    if not result:
        raise BrowserCookieError("no unexpired cookies found for the requested domain")
    return result

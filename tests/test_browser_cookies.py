from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from astrolabe.browser_cookies import BrowserCookieError, decrypt_cookie, export_cookies


def encrypt(value: bytes, host: str, password: bytes = b"test-key", version: int = 24) -> bytes:
    plain = (hashlib.sha256(host.encode()).digest() if version >= 24 else b"") + value
    padding = 16 - len(plain) % 16
    plain += bytes([padding]) * padding
    key = hashlib.pbkdf2_hmac("sha1", password, b"saltysalt", 1, dklen=16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(b" " * 16)).encryptor()
    return b"v11" + cipher.update(plain) + cipher.finalize()


def test_v11_requires_correct_key_and_exact_domain_binding():
    encrypted = encrypt(b"session-secret", ".example.com")
    assert (
        decrypt_cookie(encrypted, ".example.com", 24, [b"wrong", b"test-key"]) == "session-secret"
    )
    for host, keys in [(".other.com", [b"test-key"]), (".example.com", [b"wrong"])]:
        with pytest.raises(BrowserCookieError):
            decrypt_cookie(encrypted, host, 24, keys)


def test_old_v10_and_invalid_ciphertext():
    encrypted = b"v10" + encrypt(b"old-session", ".example.com", b"peanuts", 23)[3:]
    assert decrypt_cookie(encrypted, ".example.com", 23, []) == "old-session"
    for raw in [b"v20cipher", b"v11short", b"v11" + bytes(32)]:
        with pytest.raises(BrowserCookieError):
            decrypt_cookie(raw, ".example.com", 24, [b"test-key"])


def test_export_filters_domains_and_preserves_plaintext_cookies(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("astrolabe.browser_cookies.keyring_passwords", lambda labels: [b"test-key"])
    root = tmp_path / ".config/vivaldi/Default"
    root.mkdir(parents=True)
    with closing(sqlite3.connect(root / "Cookies")) as c:
        c.execute("CREATE TABLE meta(key TEXT,value TEXT)")
        c.execute("INSERT INTO meta VALUES('version','24')")
        c.execute(
            "CREATE TABLE cookies(host_key,name,value,encrypted_value,path,is_secure,is_httponly,expires_utc,samesite,is_persistent)"
        )
        for host in ["x.com", ".x.com", "api.x.com", "notx.com", ".x.com.attacker.test"]:
            c.execute(
                "INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    host,
                    "session",
                    "",
                    encrypt(b"secret", host),
                    "/",
                    1,
                    1,
                    0,
                    1,
                    0,
                ),
            )
        c.execute(
            "INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                "x.com",
                "plain",
                "visible",
                b"",
                "/",
                1,
                0,
                0,
                -1,
                0,
            ),
        )
        c.commit()
    cookies = export_cookies("vivaldi", "x.com")
    assert {c["domain"] for c in cookies} == {"x.com", ".x.com", "api.x.com"}
    assert len(cookies) == 4
    assert next(c["value"] for c in cookies if c["name"] == "plain") == "visible"
    with pytest.raises(BrowserCookieError):
        export_cookies("vivaldi", "x.com", "../Default")


@pytest.mark.parametrize("domain", ["com", "co.uk", "github.io"])
def test_public_suffix_import_fails_before_keyring_access(domain, monkeypatch):
    def forbidden(*args):
        pytest.fail("public suffix reached keyring")

    monkeypatch.setattr("astrolabe.browser_cookies.keyring_passwords", forbidden)
    with pytest.raises(BrowserCookieError, match="public suffix"):
        export_cookies("vivaldi", domain)


def test_profile_symlink_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "Cookies").write_bytes(b"not a database")
    root = tmp_path / ".config/vivaldi"
    root.mkdir(parents=True)
    (root / "Default").symlink_to(actual, target_is_directory=True)
    with pytest.raises(BrowserCookieError, match="symlinked"):
        export_cookies("vivaldi", "example.com")


def test_keyring_reads_only_matching_unlocked_items_and_closes_bus(monkeypatch):
    import sys
    from types import SimpleNamespace

    from astrolabe.browser_cookies import keyring_passwords

    read = []
    closed = []

    class Item:
        def __init__(self, label, locked=False):
            self.label, self.locked = label, locked

        def get_label(self):
            return self.label

        def is_locked(self):
            return self.locked

        def get_secret(self):
            read.append(self.label)
            return b"private-test-key"

    items = [
        Item("unrelated account password"),
        Item("Vivaldi Safe Storage", True),
        Item("folder/Vivaldi Safe Storage"),
    ]
    collection = SimpleNamespace(is_locked=lambda: False, get_all_items=lambda: items)
    locked = SimpleNamespace(
        is_locked=lambda: True, get_all_items=lambda: pytest.fail("locked keyring read")
    )
    bus = SimpleNamespace(close=lambda: closed.append(True))
    module = SimpleNamespace(
        dbus_init=lambda: bus, get_all_collections=lambda _: [locked, collection]
    )
    monkeypatch.setitem(sys.modules, "secretstorage", module)
    assert keyring_passwords(("Vivaldi Safe Storage",)) == [b"private-test-key"]
    assert read == ["folder/Vivaldi Safe Storage"]
    assert closed == [True]

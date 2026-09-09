from __future__ import annotations

import base64
import bz2
import gzip
import io
import json
import lzma
import urllib.parse
import zipfile
import zlib

import pytest

from astrolabe.payloads import PackagingError, decode_payload

RAW = b'{"data":{"items":[1,2]}}'


@pytest.mark.parametrize(
    ("raw", "layer"),
    [
        (RAW, "json"),
        (gzip.compress(RAW), "gzip"),
        (zlib.compress(RAW), "deflate"),
        (bz2.compress(RAW), "bzip2"),
        (lzma.compress(RAW), "xz"),
        (base64.b64encode(RAW), "base64"),
        (base64.urlsafe_b64encode(RAW).rstrip(b"="), "base64"),
        (RAW.hex().encode(), "hex"),
        (urllib.parse.quote_from_bytes(RAW).encode(), "percent-encoding"),
        (json.dumps(RAW.decode()).encode(), "json-string"),
        (b")]}'\n" + RAW, "xssi-guard"),
        (b"for(;;);" + RAW, "xssi-guard"),
        (b"app.callback(" + RAW + b");", "jsonp"),
    ],
)
def test_common_packaging(raw, layer):
    decoded = decode_payload(raw, media_type="text/plain")
    assert decoded.value == json.loads(RAW)
    assert layer in decoded.layers


def test_layered_compression_and_encoding():
    raw = json.dumps(base64.b64encode(gzip.compress(RAW)).decode()).encode()
    result = decode_payload(raw)
    assert result.value == json.loads(RAW)
    assert result.layers == ("json-string", "base64", "gzip", "json")


@pytest.mark.parametrize("value", ["hello", "1234", "true", "null", "YWJjZA=="])
def test_scalar_strings_preserve_meaning(value):
    assert decode_payload(json.dumps(value).encode()).value == value


def test_raw_deflate_requires_explicit_encoding():
    raw = zlib.compress(RAW)[2:-4]
    assert decode_payload(raw, content_encoding="deflate").value == json.loads(RAW)
    with pytest.raises(PackagingError):
        decode_payload(raw)


def test_single_zip_entry_never_extracts_paths(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("../../escape.json", RAW)
    assert decode_payload(buffer.getvalue()).value == json.loads(RAW)
    assert not list(tmp_path.iterdir())


def test_ndjson_and_multipart_preserve_parts():
    assert decode_payload(RAW + b"\n" + RAW).value == [json.loads(RAW)] * 2
    body = b"--test\r\nContent-Type: application/json\r\n\r\n" + RAW + b"\r\n--test--\r\n"
    result = decode_payload(body, media_type='multipart/mixed; boundary="test"')
    assert result.value == [json.loads(RAW)]
    assert result.layers == ("multipart-json",)
    with pytest.raises(PackagingError):
        decode_payload(body[:-12], media_type="multipart/mixed; boundary=test")


@pytest.mark.parametrize("encoder", [gzip.compress, zlib.compress, bz2.compress, lzma.compress])
def test_compression_bombs_fail_closed(encoder):
    with pytest.raises(PackagingError):
        decode_payload(encoder(b" " * 100_000 + RAW), max_bytes=1024)


def test_unsupported_encryption_and_executable_wrappers_are_not_evaluated():
    for raw in [b"eval('secret')", b"encrypted:abcdef", b"callback({});evil()"]:
        with pytest.raises(PackagingError):
            decode_payload(raw)
    with pytest.raises(PackagingError, match="unsupported content encoding"):
        decode_payload(RAW, content_encoding="unknown")


def test_layer_budget_and_truncated_compression():
    with pytest.raises(PackagingError):
        decode_payload(base64.b64encode(gzip.compress(RAW)), max_layers=1)
    with pytest.raises(PackagingError):
        decode_payload(gzip.compress(RAW)[:-4])

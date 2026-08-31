"""Typed, read-only Shopify Storefront GraphQL catalog capture.

This is the producer contract for downstream consumers (e.g. an arbitrage or price-monitoring pipeline).
Every product variant is retained.  Analysis outputs (spreads, samples, or
arbitrage candidates) are deliberately separate and must never be re-ingested
as if they were the source observation set.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import urlsplit

from curl_cffi import requests as curl_requests

API_VERSION = "2024-10"
PAGE_SIZE = 250
VARIANT_PAGE_SIZE = 250
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)

PRODUCTS_QUERY = """query AstrolabeCatalog($first:Int!,$after:String){
  products(first:$first,after:$after,sortKey:UPDATED_AT){
    edges{cursor node{
      id handle title productType vendor publishedAt updatedAt tags
      variants(first:250){edges{node{
        id title sku availableForSale quantityAvailable
        price{amount currencyCode} compareAtPrice{amount currencyCode}
      }} pageInfo{hasNextPage endCursor}}
    }}
    pageInfo{hasNextPage endCursor}
  }
}"""


class StorefrontContractError(ValueError):
    """The response is incomplete or has drifted from the capture contract."""


@dataclass(frozen=True)
class Observation:
    schema_version: int
    capture_id: str
    observed_at: str
    host: str
    endpoint: str
    api_version: str
    product_id: str
    variant_id: str
    product_handle: str | None
    product_title: str
    variant_title: str | None
    product_type: str | None
    vendor: str | None
    published_at: str | None
    product_updated_at: str | None
    sku: str | None
    tags: tuple[str, ...]
    price: str
    currency: str
    compare_at: str | None
    available: bool | None
    qty_available: int | None

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True)
class CaptureResult:
    host: str
    capture_id: str
    observed_at: str
    pages: int
    products: int
    observations: tuple[Observation, ...]


def normalize_host(value: str) -> str:
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or any(char.isspace() for char in host):
        raise ValueError(f"invalid storefront host: {value!r}")
    return host


def endpoint_for(host: str, api_version: str = API_VERSION) -> str:
    return f"https://{normalize_host(host)}/api/{api_version}/graphql.json"


def stable_seed(seed: int, host: str) -> int:
    digest = hashlib.sha256(f"{seed}\0{normalize_host(host)}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def _money(value, *, required: bool) -> tuple[str | None, str | None]:
    if value is None and not required:
        return None, None
    if not isinstance(value, dict):
        raise StorefrontContractError("money field is not an object")
    try:
        amount = Decimal(str(value["amount"]))
        currency = str(value["currencyCode"]).upper()
    except (KeyError, InvalidOperation, TypeError) as exc:
        raise StorefrontContractError("invalid money field") from exc
    if not amount.is_finite() or amount < 0 or len(currency) != 3:
        raise StorefrontContractError("invalid money amount or currency")
    return str(amount), currency


def parse_page(
    payload, *, host: str, endpoint: str, api_version: str, observed_at: str, capture_id: str
):
    if not isinstance(payload, dict):
        raise StorefrontContractError("GraphQL response is not an object")
    if payload.get("errors"):
        raise StorefrontContractError(f"GraphQL errors: {payload['errors']!r}")
    try:
        products = payload["data"]["products"]
        edges = products["edges"]
        page_info = products["pageInfo"]
    except (KeyError, TypeError) as exc:
        raise StorefrontContractError("missing data.products contract") from exc
    if not isinstance(edges, list) or not isinstance(page_info, dict):
        raise StorefrontContractError("invalid products connection")
    output = []
    for edge in edges:
        try:
            product = edge["node"]
            variants = product["variants"]
            variant_edges = variants["edges"]
        except (KeyError, TypeError) as exc:
            raise StorefrontContractError("invalid product connection") from exc
        if variants.get("pageInfo", {}).get("hasNextPage"):
            raise StorefrontContractError(
                f"product {product.get('id')!r} exceeds {VARIANT_PAGE_SIZE} variants"
            )
        for variant_edge in variant_edges:
            variant = variant_edge.get("node")
            if not isinstance(variant, dict):
                raise StorefrontContractError("invalid variant node")
            price, currency = _money(variant.get("price"), required=True)
            compare_at, compare_currency = _money(variant.get("compareAtPrice"), required=False)
            if compare_currency is not None and compare_currency != currency:
                raise StorefrontContractError("compare-at currency differs from price currency")
            product_id = str(product.get("id") or "")
            variant_id = str(variant.get("id") or "")
            title = str(product.get("title") or "").strip()
            if not product_id or not variant_id or not title or price is None or currency is None:
                raise StorefrontContractError("product/variant identity is incomplete")
            qty = variant.get("quantityAvailable")
            if qty is not None and (not isinstance(qty, int) or isinstance(qty, bool)):
                raise StorefrontContractError("quantityAvailable must be integer or null")
            available = variant.get("availableForSale")
            if available is not None and not isinstance(available, bool):
                raise StorefrontContractError("availableForSale must be boolean or null")
            output.append(
                Observation(
                    schema_version=1,
                    capture_id=capture_id,
                    observed_at=observed_at,
                    host=host,
                    endpoint=endpoint,
                    api_version=api_version,
                    product_id=product_id,
                    variant_id=variant_id,
                    product_handle=product.get("handle"),
                    product_title=title,
                    variant_title=variant.get("title"),
                    product_type=product.get("productType"),
                    vendor=product.get("vendor"),
                    published_at=product.get("publishedAt"),
                    product_updated_at=product.get("updatedAt"),
                    sku=variant.get("sku"),
                    tags=tuple(str(tag) for tag in (product.get("tags") or [])),
                    price=price,
                    currency=currency,
                    compare_at=compare_at,
                    available=available,
                    qty_available=qty,
                )
            )
    return output, bool(page_info.get("hasNextPage")), page_info.get("endCursor"), len(edges)


class Collector:
    def __init__(
        self,
        *,
        api_version: str = API_VERSION,
        timeout: float = 30,
        retries: int = 3,
        max_pages: int | None = None,
        session=None,
    ):
        self.api_version = api_version
        self.timeout = timeout
        self.retries = retries
        self.max_pages = max_pages
        self.session = session

    async def collect(self, host: str) -> CaptureResult:
        host = normalize_host(host)
        endpoint = endpoint_for(host, self.api_version)
        observed_at = datetime.now(UTC).isoformat()
        capture_id = hashlib.sha256(f"{host}\0{observed_at}".encode()).hexdigest()[:24]
        owned_session = self.session is None
        session = self.session or curl_requests.AsyncSession()
        after = None
        pages = products = 0
        output = []
        try:
            while True:
                payload = None
                for attempt in range(self.retries + 1):
                    try:
                        response = await session.post(
                            endpoint,
                            impersonate="chrome",
                            timeout=self.timeout,
                            headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
                            json={
                                "query": PRODUCTS_QUERY,
                                "variables": {"first": PAGE_SIZE, "after": after},
                            },
                        )
                        if response.status_code != 200:
                            raise StorefrontContractError(f"HTTP {response.status_code}")
                        payload = response.json()
                        break
                    except Exception:
                        if attempt >= self.retries:
                            raise
                        await asyncio.sleep(min(4, 0.25 * 2**attempt))
                rows, has_next, end_cursor, product_count = parse_page(
                    payload,
                    host=host,
                    endpoint=endpoint,
                    api_version=self.api_version,
                    observed_at=observed_at,
                    capture_id=capture_id,
                )
                output.extend(rows)
                pages += 1
                products += product_count
                if not has_next:
                    break
                if not end_cursor or end_cursor == after:
                    raise StorefrontContractError("pagination cursor did not advance")
                if self.max_pages is not None and pages >= self.max_pages:
                    raise StorefrontContractError("configured page limit truncated capture")
                after = end_cursor
        finally:
            if owned_session:
                await session.close()
        return CaptureResult(host, capture_id, observed_at, pages, products, tuple(output))


def write_jsonl_atomic(path: str | Path, observations) -> None:
    target = Path(path)
    tmp = target.with_name(f".{target.name}.tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        for observation in observations:
            handle.write(observation.to_json() + "\n")
        handle.flush()
    tmp.replace(target)

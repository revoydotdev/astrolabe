from datetime import UTC, datetime

import pytest

from astrolabe.storefront import (
    Collector,
    StorefrontContractError,
    normalize_host,
    parse_page,
    stable_seed,
    write_jsonl_atomic,
)


def payload(*, variant_more=False, product_more=False, cursor=None):
    return {
        "data": {
            "products": {
                "edges": [
                    {
                        "cursor": "p1",
                        "node": {
                            "id": "gid://shopify/Product/1",
                            "handle": "bolt",
                            "title": "Lightning Bolt",
                            "productType": "MTG Single",
                            "vendor": "Wizards of the Coast",
                            "publishedAt": "2026-01-01T00:00:00Z",
                            "updatedAt": "2026-01-02T00:00:00Z",
                            "tags": ["MTG"],
                            "variants": {
                                "edges": [
                                    {
                                        "node": {
                                            "id": "gid://shopify/ProductVariant/2",
                                            "title": "Near Mint Foil",
                                            "sku": "BOLT",
                                            "availableForSale": True,
                                            "quantityAvailable": None,
                                            "price": {"amount": "12.50", "currencyCode": "USD"},
                                            "compareAtPrice": {
                                                "amount": "15.00",
                                                "currencyCode": "USD",
                                            },
                                        }
                                    }
                                ],
                                "pageInfo": {"hasNextPage": variant_more, "endCursor": None},
                            },
                        },
                    }
                ],
                "pageInfo": {"hasNextPage": product_more, "endCursor": cursor},
            }
        }
    }


def parse(value):
    return parse_page(
        value,
        host="cards.example",
        endpoint="https://cards.example/api/2024-10/graphql.json",
        api_version="2024-10",
        observed_at=datetime.now(UTC).isoformat(),
        capture_id="cap",
    )


def test_parse_page_preserves_raw_variant_contract():
    rows, more, cursor, products = parse(payload())
    assert products == 1
    assert not more and cursor is None
    assert len(rows) == 1
    row = rows[0]
    assert row.product_id == "gid://shopify/Product/1"
    assert row.variant_id == "gid://shopify/ProductVariant/2"
    assert row.price == "12.50"
    assert row.qty_available is None
    assert row.available is True


def test_parse_page_rejects_silent_variant_truncation():
    with pytest.raises(StorefrontContractError, match="exceeds"):
        parse(payload(variant_more=True))


def test_parse_page_rejects_graphql_errors_and_currency_mismatch():
    with pytest.raises(StorefrontContractError, match="GraphQL errors"):
        parse({"errors": [{"message": "drift"}]})
    value = payload()
    variant = value["data"]["products"]["edges"][0]["node"]["variants"]["edges"][0]["node"]
    variant["compareAtPrice"]["currencyCode"] = "CAD"
    with pytest.raises(StorefrontContractError, match="currency"):
        parse(value)


def test_host_normalization_and_seed_are_stable():
    assert normalize_host("HTTPS://Cards.Example/path") == "cards.example"
    assert stable_seed(42, "cards.example") == stable_seed(42, "https://CARDS.example/")
    assert stable_seed(42, "cards.example") != stable_seed(43, "cards.example")


class Response:
    status_code = 200

    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


class Session:
    def __init__(self):
        self.calls = []

    async def post(self, endpoint, **kwargs):
        self.calls.append((endpoint, kwargs))
        after = kwargs["json"]["variables"]["after"]
        return Response(
            payload(product_more=after is None, cursor="next" if after is None else None)
        )


@pytest.mark.asyncio
async def test_collector_pages_and_atomic_writer(tmp_path):
    session = Session()
    result = await Collector(session=session, retries=0).collect("Cards.Example")
    assert result.pages == 2
    assert result.products == 2
    assert len(result.observations) == 2
    assert session.calls[1][1]["json"]["variables"]["after"] == "next"
    target = tmp_path / "capture.jsonl"
    write_jsonl_atomic(target, result.observations)
    lines = target.read_text().splitlines()
    assert len(lines) == 2
    assert '"schema_version":1' in lines[0]

# shop.example.test — executable typed contract

_Durable contract of record. Endpoints: `/graphql`._

## Coverage scorecard

| metric | count | % |
|---|---|---|
| operations | 28 | 100% |
| typed input schema | 2 | 7% |
| typed return schema | 20 | 71% |
| **verified — observed** (real 200 captured) | 19 | 67% |
| **verified — active** (re-executed by astrolabe) | 0 | 0% |

## Coverage by transport

| transport | ops | typed return | verified observed | verified active |
|---|---|---|---|---|
| graphql | 3 | 2 | 2 | 0 |
| rest | 23 | 18 | 15 | 0 |
| websocket | 2 | 0 | 2 | 0 |

## Operations

| op | type | transport | status | in | return |
|---|---|---|---|---|---|
| `AddToCart` | mutation | graphql | 🟢 observed | ✓ | ✓ |
| `GET /api/blobs/{hash}` | query | rest | 🟡 typed | — | — |
| `GET /api/cart` | query | rest | 🟢 observed | — | ✓ |
| `GET /api/checkout` | mutation | rest | 🟢 observed | — | ✓ |
| `GET /api/invoice` | query | rest | 🟢 observed | — | ✓ |
| `GET /api/invoice/{id}` | query | rest | 🟡 typed | — | — |
| `GET /api/legacy/{id}` | query | rest | 🟡 typed | — | ✓ |
| `GET /api/orders` | query | rest | 🟢 observed | — | ✓ |
| `GET /api/products/{id}` | query | rest | 🟡 typed | — | ✓ |
| `GET /api/public/getCaseDetails` | query | rest | 🟢 observed | — | ✓ |
| `GET /api/public/getVersion` | query | rest | 🟢 observed | — | ✓ |
| `GET /api/public/search` | query | rest | 🟢 observed | — | ✓ |
| `GET /api/session/~{uid}` | query | rest | 🟡 typed | — | ✓ |
| `GET /api/team` | query | rest | 🟢 observed | — | ✓ |
| `GET /api/team/{id}/members` | query | rest | 🟡 typed | — | — |
| `GET /api/team/{id}/profile` | query | rest | 🟡 typed | — | — |
| `GET /api/v1/catalog` | query | rest | 🟢 observed | — | ✓ |
| `GET /api/v2/catalog` | query | rest | 🟢 observed | — | ✓ |
| `GET /api/widgets/{uuid}` | query | rest | 🟡 typed | — | — |
| `POST /api/public/createThing` | mutation | rest | 🟢 observed | — | ✓ |
| `POST /api/public/dropThing` | mutation | rest | 🟢 observed | — | ✓ |
| `POST /api/public/findThing` | mutation | rest | 🟢 observed | — | ✓ |
| `POST /api/public/listAll` | mutation | rest | 🟢 observed | — | ✓ |
| `POST /api/public/reindex` | mutation | rest | 🟢 observed | — | ✓ |
| `ProductQuery` | query | graphql | 🟢 observed | ✓ | ✓ |
| `WS wss://shop.example.test/live::received::priceUpdate` | subscription | websocket | 🟢 observed | — | — |
| `WS wss://shop.example.test/live::sent::subscribe` | mutation | websocket | 🟢 observed | — | — |
| `persisted:9f8e7d6c5b4a` | query | graphql | 🟡 typed | — | — |
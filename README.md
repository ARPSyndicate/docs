# A.R.P. Syndicate — API Documentation

Public API reference for **[Subdomain Center](https://www.subdomain.center)** (Shadow IT / Subdomain Intelligence) and **[Exploit Observer](https://www.exploit.observer)** (Vulnerability / Exploit Intelligence).

Both APIs share the same authentication model: requests work with no key at a limited, rate-limited tier, and unlock higher/unlimited access with an API key. Keys are issued on the [pricing page](https://www.arpsyndicate.io/pricing.html).

## Table of Contents

- [Authentication](#authentication)
- [Subdomain Center](#subdomain-center)
  - [Query subdomains — `GET /`](#query-subdomains--get-)
  - [Pagination](#pagination)
  - [Live crawl](#live-crawl)
  - [Service health — `GET /health`](#service-health--get-health)
  - [Response headers](#response-headers)
  - [Rate limits](#rate-limits)
  - [Errors](#errors)
- [Exploit Observer](#exploit-observer)
  - [Query an identifier — `GET /`](#query-an-identifier--get-)
  - [Non-CVE clusters — `GET /noncve/{engine}`](#non-cve-clusters--get-noncveengine)
  - [Watchlists](#watchlists)
  - [Aggregate stats — `GET /stats`](#aggregate-stats--get-stats)
  - [Service health — `GET /health`](#service-health--get-health-1)
  - [Response headers](#response-headers-1)
  - [CORS](#cors)
  - [Rate limits](#rate-limits-1)
  - [Errors](#errors-1)
  - [Supported vulnerability identifiers](#supported-vulnerability-identifiers)
- [Enterprise & partner access](#enterprise--partner-access)

---

## Authentication

| | How | Notes |
|---|---|---|
| **Anonymous** | no header | Limited rate; on Subdomain Center, also a limited sample |
| **Authenticated** | `X-API-Key: <key>` header, or `Authorization: Bearer <key>` | Higher/unlimited rate; on Subdomain Center, complete results |

- Keys are accepted **only** via header — never as a query-string parameter, since URLs are logged by proxies, browsers, and edge infrastructure.
- Both APIs return the **same response shape** for a given query at either tier; the data model never changes with authentication.
- What a key buys differs by product. **Subdomain Center**: anonymous callers get a sample of up to 500 names, authenticated callers get the complete result set with pagination. **Exploit Observer**: a key raises your rate limit and unlocks `/noncve/{engine}`.
- An unrecognized key returns `401` on both products' main query endpoints. Exploit Observer's `/noncve/{engine}` answers `{}` for a missing or invalid key instead. See each product's error table.

---

## Subdomain Center

Discovers and clusters subdomains for a given domain, brand, or keyword.

**Base URL:** `https://api.subdomain.center`

### Query subdomains — `GET /`

```
GET /?domain={DOMAIN}&engine={ENGINE}&keyword={KEYWORD}&match={MATCH}&limit={LIMIT}&offset={OFFSET}&crawl={CRAWL}
```

| Parameter | Type | Required | Notes |
|---|---|---|---|
| `domain` | string | for `cuttlefish`/`octopus`; optional zone scope for `ammonites` | The domain or subdomain to search from |
| `keyword` | string | for `ammonites` | A subdomain label to search for; supplying `keyword` without `engine` implies `engine=ammonites` |
| `engine` | string | no | `cuttlefish` (default), `octopus`, or `ammonites` — see below |
| `match` | string | no | Refines `octopus`/`ammonites` matching — see below |
| `limit` | integer | no — **authenticated only** | Page size for the *first* page. Default and cap: 200,000 rows; an explicit value is capped at 1,000,000 as an absolute sanity bound. **Required on every page after the first** — see [Pagination](#pagination) |
| `offset` | integer | no — **authenticated only** | Rows to skip. Default: `0` |
| `crawl` | boolean | no — **authenticated + `engine=cuttlefish` only** | Supplements results with a live discovery pass — see [Live crawl](#live-crawl) |

#### Engines

| Engine | Trigger | Returns |
|---|---|---|
| `cuttlefish` | default | The queried host and every subdomain beneath it (e.g. `api.example.com` → `api.example.com`, `n1.api.example.com`, …) — querying the apex (`example.com`) returns the whole zone |
| `octopus` | `engine=octopus` | Domains sharing the queried domain's brand/registrable name — useful for surfacing typosquats and brand-impersonation domains (e.g. `paypal.com` → `paypal-secure.com`, `paypalobjects.com`, …) |
| `ammonites` | `engine=ammonites`, or automatically when `keyword` is set | Every domain carrying the given word as a subdomain label (`admin`, `vpn`, `staging`, `git`, …). Pass `domain` alongside `keyword` to scope the search to one zone instead of searching globally |

#### `match` modes

| Engine | `match` value | Behavior |
|---|---|---|
| `octopus` | `prefix` (default) | Brand starts with the keyword |
| `octopus` | `exact` | Brand equals the keyword exactly |
| `octopus` | `substring` | Keyword appears anywhere in the brand |
| `ammonites` | `exact` (default) | Subdomain label equals the keyword exactly |
| `ammonites` | `prefix` | Subdomain label starts with the keyword (`vpn` → `vpn`, `vpngw`, `vpn1`, …) |

#### Examples

```bash
# every subdomain under a host
curl "https://api.subdomain.center/?domain=api.example.com"

# typosquat/brand sweep
curl "https://api.subdomain.center/?domain=paypal.com&engine=octopus"

# every admin.* host anywhere, authenticated
curl -H "X-API-Key: $KEY" "https://api.subdomain.center/?engine=ammonites&keyword=admin"

# admin.* scoped to one zone — no key required
curl "https://api.subdomain.center/?keyword=vpn&domain=example.com"
```

```json
["api.example.com", "n1.api.example.com", "v1.api.example.com"]
```

### Pagination

Anonymous requests always return a shuffled sample of up to 500 results — `limit`/`offset` are ignored at that tier.

Authenticated requests return the complete, sorted result set, retrieved page by page:

```bash
curl -H "X-API-Key: $KEY" "https://api.subdomain.center/?domain=example.com&limit=50000&offset=0"
curl -H "X-API-Key: $KEY" "https://api.subdomain.center/?domain=example.com&limit=50000&offset=50000"
# continue until the response's X-Truncated header is false
```

Advance `offset` by the previous page's `X-Result-Count` (or read `X-Next-Offset` directly) until a response comes back with `X-Truncated: false` — that's the last page.

**`limit` must be repeated on every page after the first.** Pagination is stateless — the server doesn't remember the page size a previous request used — so `offset > 0` without an explicit `limit=` returns `400`. Omitting it wouldn't just fail safe either: without this check, a client that walked pages by following only `X-Next-Offset` would silently fall back to the server's full default page size on page two, which can be orders of magnitude larger than the page size it started with. Always send the exact same `limit=` value you used on page one.

### Live crawl

Authenticated requests to `engine=cuttlefish` can pass `crawl=true` to supplement stored results while live crawling.

```bash
curl -H "X-API-Key: $KEY" "https://api.subdomain.center/?domain=example.com&crawl=true"
```

- A given domain is only actually re-crawled once every **~6 hours**; requests within that window get the cached crawl result instantly.
- Crawl usage has its own rate limit, separate from the standard authenticated limit.
- Live-crawl results are additive on top of `limit`/`offset` — they are not counted against your page size.

| Response header | Meaning |
|---|---|
| `X-Crawl-Status` | `fresh` (live sources answered in time) · `partial` (some still running, check back shortly) · `cooldown` (served a recent cached crawl) · `disabled` (live crawl unavailable) |
| `X-Crawl-New-Count` | Number of newly discovered names added to this response |

### Service health — `GET /health`

No authentication, no rate limit.

```bash
curl "https://api.subdomain.center/health"
```

```json
{"status": "ok", "cuttlefish": true, "octopus": true, "ammonites": true}
```

`cuttlefish` reflects whether the core dataset is queryable; `octopus`/`ammonites` reflect whether those clustering engines are currently available. `status` is `ok` as long as `cuttlefish` works, even if the optional engines are temporarily unavailable.

### Response headers

| Header | Meaning |
|---|---|
| `X-Result-Count` | Number of names in this response |
| `X-Truncated` | `true` if more results exist beyond this page |
| `X-Next-Offset` | Present when truncated — pass as `offset` to continue |
| `X-Engine` | Which engine served the request: `cuttlefish` \| `octopus` \| `ammonites` |
| `X-Tier` | `auth` \| `anonymous` |
| `Cache-Control` | Always `no-store, private` |

### Rate limits

| Tier | Results | Order | Rate limit |
|---|---|---|---|
| Anonymous | up to 500 | shuffled | 5 requests/minute per IP |
| Authenticated | unlimited, paginated | sorted | unlimited by default |
| Authenticated + `crawl=true` | — | — | limited independently from the base rate limit |

Rate-limited requests receive `429` with a `Retry-After` header (seconds until you can retry).

### Errors

| Status | Meaning |
|---|---|
| `400` | Missing/invalid `domain` or `keyword`, unknown `engine`/`match`, invalid/out-of-range `limit`/`offset`, or `offset` set without a `limit` |
| `401` | An API key was supplied but isn't valid |
| `429` | Rate limit exceeded (`Retry-After` header included) |
| `503` | A requested engine's index isn't currently available, or the service is temporarily overloaded |
| `504` | The query took too long to complete |
| `500` | Unexpected server error |

```json
{"error": "<description of the problem>"}
```

**Input validation** — `domain` must be a well-formed public domain (2–8 labels, lowercase, ASCII, valid public suffix; IPs, unicode, and malformed hosts are rejected). `keyword` must be at least 2 characters of valid DNS-label content.

---

## Exploit Observer

Looks up vulnerabilities and exploits by identifier, correlates them across sources, and clusters related activity.

**Base URL:** `https://api.exploit.observer`

### Query an identifier — `GET /`

```
GET /?keyword={VID}&match={MATCH}
```

| Parameter | Type | Required | Notes |
|---|---|---|---|
| `keyword` | string | yes | Any [supported identifier](#supported-vulnerability-identifiers), a `cpe:2.3:` or `pkg:` URI, or a free-text vendor/product search |
| `match` | string | no | Only applies to free-text/vendor-product searches (ignored once `keyword` resolves to a known identifier directly) |

`keyword` is capped at 2048 characters and is not case-sensitive. An unmatched or invalid `keyword` returns an empty result rather than an error.

Fields that carry no data for a given identifier may be omitted from the response — read them with a default rather than by direct indexing.

#### `match` modes (free-text search only)

| Value | Behavior |
|---|---|
| `substring` (default) | Matches anywhere within an indexed entry |
| `prefix` | Matches from the start of an indexed entry |
| `exact` | Matches an indexed entry exactly |

#### Example

```bash
curl "https://api.exploit.observer/?keyword=CVE-2024-1234"
```

```json
{
  "description": "Exploit Observer has 4 entries in 2 file formats related to CVE-2024-1234. <original description text>",
  "products": ["vedaspid:vendor__product@1.2.3"],
  "clusters": ["https://api.exploit.observer/?keyword=VEDAS:ABCDEF"],
  "entries": {
    "python": ["https://github.com/.../poc.py"],
    "unknown": ["https://some-writeup.example.com/..."]
  },
  "related": ["GHSA-xxxx-xxxx-xxxx", "EDB-51234"],
  "aliases": ["GHSA-xxxx-xxxx-xxxx"],
  "scores": {
    "vedas": 0.8421356,
    "epss": 0.00043,
    "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "severity": "CRITICAL"}
  },
  "kev": false,
  "cwe": ["CWE-79"],
  "vedas-timestamp": "2026-07-30 12:00:00.000000"
}
```

| Field | Meaning |
|---|---|
| `description` | Summary of the identifier, including how many related entries exist |
| `products` | Affected products/versions, as `vedaspid:{vendor}__{product}@{version}` identifiers |
| `clusters` | Links to related identifiers grouped under the same underlying issue |
| `entries` | Related links (PoCs, write-ups, exploit code, …), grouped by source language, or `unknown` for plain links |
| `related` | Every identifier reachable through this entry's known relationships — includes both true aliases and advisories the source documents as related-but-distinct issues |
| `aliases` | Narrower than `related`: only identifiers the source explicitly states are **the same vulnerability** under another name. Use this field, not `related`, when you need identity ("is this the same issue as that one") |
| `scores.vedas` | A `0`–`1` confidence score combining every corroborating signal Exploit Observer has for this identifier (this was a bare top-level `maturity` field before it moved under `scores` — same value, same meaning) |
| `scores.epss` | The current EPSS score for the identifier actually queried. `0.0` if none on file. Not aggregated across the cluster the way `products`/`cwe` are — EPSS only ever keys by a real CVE id |
| `scores.cvss` | `{"score", "vector", "severity"}` for the identifier's cluster, or `null` if no CVSS data exists anywhere in it. GHSA/OSSF (OSV-schema) sources never publish a computed numeric base score — only `vector`/`severity` — so `score` is `null` for those even when the rest is present. When a CVE and its GHSA counterpart are clustered together, the CVE's numeric-scored entry is preferred |
| `kev` | Whether the identifier actually queried is listed in CISA's Known Exploited Vulnerabilities catalog. Scoped to that identifier, not aggregated across its cluster |
| `cwe` | Every distinct CWE weakness classification found across the identifier's full cluster, deduped and sorted. `[]` if none exist anywhere in the cluster |
| `vedas-timestamp` | When this entry was last updated |

### Non-CVE clusters — `GET /noncve/{engine}`

**Requires authentication.** An anonymous or invalid key returns `{}` rather than an error.

```
GET /noncve/{ENGINE}
```

| `engine` | Returns |
|---|---|
| `browser` | Identifiers from browser vendor advisories without a CVE assignment |
| `china` | Identifiers from Chinese national vulnerability databases without a CVE assignment |
| `russia` | Identifiers from the Russian vulnerability database without a CVE assignment |
| `europe` | Identifiers from the EU vulnerability database without a CVE assignment |
| `exploitable` | Every clustered issue that has **no** CVE identifier at all |

```bash
curl -H "X-API-Key: $KEY" "https://api.exploit.observer/noncve/exploitable"
```

```json
{"VEDAS:ABCDEF": "", "...": "..."}
```

An unrecognized `engine` returns `404`. Results change only when a new dataset is published, so there is nothing to gain from polling faster than that.

### Watchlists

No authentication and no rate limit on any of the following.

```bash
curl "https://api.exploit.observer/watchlist/identifiers"
curl "https://api.exploit.observer/watchlist/describers"
curl "https://api.exploit.observer/watchlist/technologies"
```

| Endpoint | Returns |
|---|---|
| `/watchlist/identifiers` | The current list of freshly-tracked identifiers |
| `/watchlist/describers` | The same list, each with a short description |
| `/watchlist/technologies` | Currently-trending technologies/products by mention weight |

### Aggregate stats — `GET /stats`

No authentication, no rate limit.

```bash
curl "https://api.exploit.observer/stats"
```

```json
{
  "vulnerabilities": [12345, 234, 987654, 45678, 2345, 6789],
  "exploits":        [12345, 198, 456789, 34567, 1987, 5432]
}
```

Each array buckets counts as `[total clusters, regional-only, uncategorized, open, bounty-eligible, north-american]`. `vulnerabilities` counts distinct issues; `exploits` counts individual pieces of exploit activity across all clusters.

### Service health — `GET /health`

No authentication, no rate limit.

```bash
curl "https://api.exploit.observer/health"
```

```json
{"status": "ok", "last_run": "2026-07-30 12:00:00.000000", "snapshot_age_seconds": 42.3}
```

`last_run` is `null` if the dataset has never completed an initial build. `snapshot_age_seconds` is how long the currently-served dataset has been in use.

### Response headers

| Header | Meaning |
|---|---|
| `X-Result-Count` | On `GET /`: the total number of entries across every language bucket in `entries` |
| `Retry-After` | Present on `429`: seconds until you may retry |
| `Cache-Control` | Always `no-store, private` |

Responses are not cacheable by shared infrastructure. If you want caching, do it on your side, keyed by your own API key.

### CORS

Cross-origin browser requests are allowed from approved origins only. `GET` and `OPTIONS` are permitted, `X-API-Key` and `Authorization` are accepted as request headers, and `X-Result-Count` is exposed so JavaScript can read it. Contact us to have an origin approved.

**Do not put an API key in front-end code.** It is readable by anyone who opens the page. Proxy Exploit Observer through your own backend and keep the key there.

### Rate limits

| Endpoint(s) | Anonymous | Authenticated |
|---|---|---|
| `GET /` (main query) | 2 requests/minute per IP | unlimited by default |
| `/noncve/{engine}` | rate limited per IP; returns `{}` without a valid key | unlimited by default |
| `/watchlist/*`, `/stats`, `/health` | unlimited | unlimited |

Rate-limited requests receive `429` with a `Retry-After` header. Requests carrying an invalid key count against the anonymous limit.

### Errors

| Status | Meaning |
|---|---|
| `401` | An API key was supplied but isn't valid (`GET /`; `/noncve` answers `{}` instead) |
| `404` | Unrecognized `/noncve/{engine}` |
| `429` | Rate limit exceeded (`Retry-After` header included) |
| `504` | The query took too long to complete |

The main query endpoint (`GET /`) never returns a `4xx` for an unmatched or malformed `keyword` — it returns an empty result.

### Supported vulnerability identifiers

50+ sources, including but not limited to:

| Source | Format | Example |
|---|---|---|
| A.R.P. Syndicate VEDAS | `VEDAS:{codename}` | `VEDAS:OBLIVIONHAWK` |
| China National Vulnerability Database (CNVD) | `CNVD-YYYY-NNNNN` | `CNVD-2024-02713` |
| China National Vulnerability Database of Information Security (CNNVD) | `CNNVD-YYYYMM-NNNN` | `CNNVD-202312-2255` |
| Cisco Talos | `TALOS-YYYY-NNNN` | `TALOS-2023-1896` |
| Common Vulnerabilities and Exposures (CVE) | `CVE-YYYY-NNNNN` | `CVE-2021-3450` |
| CXSecurity (WLB) | `WLB-YYYYNNNNNN` | `WLB-2024010058` |
| Defiant Wordfence | `WORDFENCE-{uuid}` | `WORDFENCE-00086b84-c1ec-447a-a536-1c73eac1cc85` |
| European Union Vulnerability Database (EUVD) | `EUVD-YYYY-NNNNN` | `EUVD-2025-14498` |
| GitHub Commits | `GHCOMMIT-{sha}` | `GHCOMMIT-102448040d5132460e3b0013e03ebedec0677e00` |
| GitHub Repositories | `GITHUB/{owner}/{repo}` | `GITHUB/aio-libs/aiohttp` |
| GitHub Security Advisories (GHSA) | `GHSA-xxxx-xxxx-xxxx` | `GHSA-wfh5-x68w-hvw2` |
| Google Bug Hunters VRP | `GBHVRP-{id}` | `GBHVRP-F8GFYGv4g` |
| Google Chromium Issues | `CHROMIUM-NNNNNNNN` | `CHROMIUM-40057791` |
| Google Project Zero | `PROJECTZERO-NNNNNNNN` | `PROJECTZERO-42450487` |
| HackerOne Hacktivity | `H1-NNNNNNN` | `H1-2230915` |
| Japan Vulnerability Notes iPedia (JVNDB) | `JVNDB-YYYY-NNNNNN` | `JVNDB-2023-006199` |
| Knownsec Seebug | `SSVID-NNNNN` | `SSVID-99817` |
| Linux Open Source Security Foundation (OSSF) | `OSSF-OSV-YYYY-NNNN` | `OSSF-OSV-2024-1427` |
| Microsoft CVE | `MSCVE-YYYY-NNNNN` | `MSCVE-2025-21415` |
| Mozilla Foundation Issues | `MOZILLA-NNNNNN` | `MOZILLA-290162` |
| Mozilla Foundation Security Advisories | `MFSAYYYY-NN` | `MFSA2024-51` |
| OffSec Exploit Database (EDB) | `EDB-NNNNN` | `EDB-10102` |
| openSUSE CVE (SUCVE) | `SUCVE-YYYY-NNNNN` | `SUCVE-2023-40547` |
| openSUSE Issues | `SUSE-NNNNNNN` | `SUSE-1183851` |
| Packet Storm Security | `PSS-NNNNNN` | `PSS-170615` |
| Patchstack | `PATCHSTACK/{slug}` | `PATCHSTACK/spectrum/wordpress-spectrum-theme-remote-code-execution` |
| ProjectDiscovery Nuclei | `PD/{template-path}` | `PD/http/cves/2020/CVE-2020-12720` |
| ProtectAI Huntr | `HUNTR-{uuid}` | `HUNTR-001d1c29-805a-4035-93bb-71a0e81da3e5` |
| Rapid7 Metasploit Framework | `MSF/{module-path}` | `MSF/auxiliary_admin/2wire/xslt_password_reset` |
| RedHat CVE | `RHCVE-YYYY-NNNNN` | `RHCVE-2025-27098` |
| RedHat Issues | `REDHAT-NNNNNN` | `REDHAT-290162` |
| RedHat Security Advisories | `RHSA-YYYY:NNNN` | `RHSA-2025:1730` |
| Russian Data Bank of Information Security Threats (BDU) | `BDU:YYYY-NNNNN` | `BDU:2024-00390` |
| Snyk Vulnerability Database | `SNYK-{ecosystem}-{id}` | `SNYK-JAVA-ORGCLOJURE-5740378` |
| Source Incite | `SRC-YYYY-NNNN` | `SRC-2021-0019` |
| Tenable CVE | `TNCVE-YYYY-NNNNN` | `TNCVE-2025-25763` |
| Tenable Security Advisories | `TNS-YYYY-NN` | `TNS-2021-05` |
| Trend Micro Zero Day Initiative | `ZDI-YY-NNNN` | `ZDI-23-1714` |
| VARIoT Exploits | `VAR-E-YYYYMM-NNNN` | `VAR-E-201704-0525` |
| VARIoT Vulnerabilities | `VAR-YYYYMM-NNNN` | `VAR-202404-0085` |
| Veracode SourceClear | `SRCCLR-SID-NNNN` | `SRCCLR-SID-3173` |
| WP Engine WPScan | `WPSCAN-{uuid}` | `WPSCAN-52568abd-c509-411e-8391-c75e7613eb42` |
| YouTube | `YT/{video-id}` | `YT/ccqjhUmwLCk` |
| Zero Science Lab | `ZSL-YYYY-NNNN` | `ZSL-2022-5743` |
| 0Day Today | `0DAY-ID-NNNNN` | `0DAY-ID-24705` |
| Vendor/Product | `{vendor}__{product}` | `grafana` |
| Vendor/Product + Version | `{vendor}__{product}@{version}` | `felixwelberg@1.0.45` |
| Multiple free-text keywords | `{keywordA}__{keywordB}` | `pci__util` |

---

## Enterprise & partner access

Need bulk access, dedicated infrastructure, or higher throughput than the standard authenticated tier? Reach out via the [pricing page](https://www.arpsyndicate.io/pricing.html) to discuss enterprise and partner options.

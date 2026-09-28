# OSINT search depth design

## Goal

Improve public information discovery by combining search indexes, executing planned person queries, reading promising pages, and following bounded pivots.

## Approved behavior

1. Search Bing, DuckDuckGo, and Google independently when available; merge and deduplicate results while retaining each result's provider.
2. Report per-provider outcomes so empty results differ from a block, transport failure, or parser failure.
3. Execute existing person dorks and query variants.
4. Read selected public pages, extract cautious candidate pivots, search those pivots, and report budgets and stopping reason.
5. Reuse specialist collectors through existing agent tools when the target type makes them relevant.

## Limits

- Keep public web lookup passive; do not attempt authentication, access controls, or anti-bot evasion.
- Clamp query count, result count, fetch count, and pivot depth.
- Preserve source URL, provider, query, and page-read outcome with each finding.
- Candidate pivots are leads, not verified identity matches.
- Keep no-key search usable; API-backed providers can be added later without making them mandatory.
- Do not add or run tests in this session; perform non-test static checks only.

## Implementation boundary

Extend the web collector and browser diagnostics, update person and document search to use shared parsing, and add a collector-backed deep-research tool that records its report in the case graph and evidence ledger.

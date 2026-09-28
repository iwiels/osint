# Deep OSINT Search Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve discovery through multi-index search, executed person dorks, page reading, and bounded recursive pivots.

**Architecture:** Keep provider normalization in the web collector, expose block/error details from browser search while preserving its existing list API, and add a deep-research collector for query batches and page reads. An MCP tool ingests the resulting entities and coverage report into the case graph and evidence ledger.

**Tech Stack:** Python 3.12, asyncio, existing Playwright browser wrapper, WebSearchCollector/WebFetchCollector, FastMCP, OSINTGraph, ForensicLedger.

**Spec:** docs/superpowers/specs/osint-search-depth.md

## Global Constraints

- Preserve all pre-existing working-tree changes; edit only relevant search paths.
- Maintain passive public-source collection and existing NetGuard checks.
- Bound query fan-out to 40 queries, page reads to 20, and pivot depth to 2.
- Preserve provider, query, URL, and retrieval outcome in returned evidence.
- Treat extracted names and identifiers as candidate pivots with conservative confidence.
- Do not add or run tests in this session; use syntax and diff checks only.
- Do not commit while the shared checkout contains unrelated uncommitted changes.

## Review Focus

- Accented, multi-part, or ambiguous person names: search variants without claiming a match from a name alone.
- A provider returns a CAPTCHA or block page: report blocked rather than empty.
- Providers return the same URL with tracking parameters: deduplicate and retain all contributing provider/query provenance.
- A page cannot be fetched or is truncated: report the outcome and continue within budget.
- Pivots repeat or exceed budget: skip seen pivots and report why research stopped.

---

### Task 1: Aggregate search providers and report outcomes

**Files:**
- Modify: engine/specter/stealth_browser.py
- Modify: engine/specter/collectors/web.py
- Modify: engine/agent.py

**Interfaces:**
- Add StealthBrowser.search_detailed(query, engine, top_k) returning status, results, and optional reason/error; preserve search(...) returning only results.
- Add WebSearchCollector.collect_many(queries, top_k=5, concurrency=3) returning a CollectorResult with unique results, query/provider diagnostics, and normalized JSON.
- Keep collect(...) compatible with existing callers and include provider diagnostics in raw JSON and metadata.

- [x] Report per-engine outcomes for Bing, DuckDuckGo, and Google: results, no results, blocked, or error.
- [x] Search each query across available engines concurrently; canonicalize URLs, retain all provider/query provenance, and fairly interleave provider results before applying the total cap.
- [x] When browser DuckDuckGo has no usable result, try the existing direct HTML fallback and report it separately.
- [x] Bound collect_many concurrency and update agent instructions to describe merged results and provider coverage.
- [x] Inspect changes and run syntax compilation on modified Python modules.

### Task 2: Execute person dorks and make document search diagnosable

**Files:**
- Modify: engine/specter/collectors/person.py
- Modify: engine/specter/collectors/dorker.py

**Interfaces:**
- PersonInvestigator.collect(..., execute_search=True) uses collect_many for exact, unquoted, accent-folded, presence, document, repository, and country-specific official queries; report attempted queries and provider outcomes.
- DocumentHunter._query_duckduckgo keeps returning URL lists and can append per-query diagnostics.

- [x] Build a deduplicated, bounded person query plan from existing dork families and name variants; execute it through collect_many.
- [x] Preserve query/provider provenance on each result and retain existing graph relations.
- [x] Replace dorker result regexes with parse_ddg_html; surface query outcomes, counts, and errors in report metadata.
- [x] Inspect changes and run syntax compilation on modified Python modules.

### Task 3: Add bounded deep research with page reads and pivots

**Files:**
- Create: engine/specter/collectors/research.py
- Modify: engine/specter/server.py
- Modify: engine/agent.py

**Interfaces:**
- DeepResearchCollector.collect(target, target_type="auto", max_queries=30, max_pages=12, max_depth=2, context="") returns a CollectorResult. Metadata reports target type, queries attempted, provider outcomes, unique results, pages read/errors, pivots found/searched, and stop reason.
- MCP tool deep_research(case_id, target, target_type="auto", max_queries=30, max_pages=12, max_depth=2) ingests the result into graph and ledger, then returns its coverage report.
- The collector reuses WebSearchCollector.collect_many and WebFetchCollector.collect and has no database or ledger dependency.

- [x] Build target-aware query seeds for people, organizations, domains, emails, and usernames; use existing person dorks for people.
- [x] Search bounded query batches, deduplicate result URLs, and fetch a capped, provider-diverse set of pages.
- [x] Extract email/domain/name candidates with source provenance; queue only unseen, non-root candidates for up to two rounds and within max_queries.
- [x] Reserve query budget for pivot rounds, and sample person dorks across query families when the seed list exceeds that budget.
- [x] Add target-to-page and target-to-pivot graph edges with conservative confidence and provenance attributes.
- [x] Register the MCP tool as a case-writing investigation tool and update agent instructions to use it with existing target-specific collectors.
- [x] Report provider coverage, fetch outcomes, pivot counts, and a concrete stop reason; inspect changes, compile modified Python modules, and run git diff --check.

## Execution notes

- The user approved the design and requested implementation inline.
- The shared checkout is on main with substantial pre-existing modifications, including relevant person and document-search enhancements. Preserve them and work in place.
- Do not stage or commit this work because that would mix it with unrelated local changes.
- Static verification only: Python syntax compilation and git diff --check; no tests were added or run.

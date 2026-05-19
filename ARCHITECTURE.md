# Architecture

End-to-end design document for mcp-sentry.

---

## Goals and non-goals

**Goals**
- Audit any MCP server (Streamable HTTP transport) for known security weaknesses
- Cover the documented attack literature: tool poisoning, prompt injection, path traversal, SSRF, credential leakage, rug pull
- Produce reports that are both human-readable (markdown) and machine-readable (JSON)
- Be safe to run against third-party servers (never destructive, opt-in for risky probes)
- Be extensible — new detectors should be a single-file addition

**Non-goals**
- Replace a human security review
- Detect zero-day exploits (we catch known attack patterns)
- Audit MCP clients (this is server-side only)
- Support stdio transport in v1 (Streamable HTTP only)
- Bypass authentication (we support Bearer tokens, never crack credentials)

---

## High-level data flow

```
┌──────────┐    URL    ┌──────────────┐
│   User   │ ────────▶ │  CLI / API   │
└──────────┘           └──────┬───────┘
                              │ run_scan(url, options)
                              ▼
                       ┌──────────────┐
                       │ Orchestrator │
                       └──────┬───────┘
                              │
            ┌─────────────────┼─────────────────┐
            ▼                 ▼                 ▼
     ┌───────────┐    ┌─────────────┐    ┌────────────┐
     │  Client   │    │  Detectors  │    │  Safety    │
     │  (MCP)    │    │  (S/D/L)    │    │  layer     │
     └─────┬─────┘    └──────┬──────┘    └─────┬──────┘
           │ tools           │ findings        │ rules
           └─────────────────┼─────────────────┘
                              ▼
                       ┌──────────────┐
                       │   Report     │
                       │ (markdown +  │
                       │   JSON)      │
                       └──────────────┘
```

---

## Component breakdown

### 1. Client layer (`client.py`)

Thin wrapper over the official MCP Python SDK.

**Responsibilities**
- Open a Streamable HTTP session to the target server
- Initialize the MCP handshake
- Expose `list_tools()` and `call_tool()` operations
- Handle timeouts gracefully (10s default per operation)
- Inject custom User-Agent header for politeness

**Key design choice:** uses `@asynccontextmanager` so connections are guaranteed to close even when scans fail mid-way. No leaked sockets.

### 2. Data models (`models.py`)

Pydantic v2 models. The contract between every component.

Severity (enum)
  - CRITICAL, HIGH, MEDIUM, LOW, INFO


ScanReport
  - target_url: str
  - server_info: dict
  - tool_count: int
  - findings: list[Finding]
  - score: int            (0-100)
  - grade: str            (A+ through F)
  - scan_duration_ms: int
  - timestamp: datetime
```

The `labelled_text_fields` property is the foundation of all static detectors — it returns every text field a detector might want to scan, paired with the field name for accurate reporting.

### 3. Safety layer (`safety.py`)

Six functions, each with a single responsibility.

| Function | Purpose |
|----------|---------|
| `classify_tool(tool)` | Returns "safe" or "destructive" — gates dynamic detection |
| `generate_safe_inputs(tool)` | Reads JSON schema, generates minimal valid inputs |
| `inject_probe(tool, base_inputs, probe, target_names)` | Replaces a specific param value with a probe payload |
| `extract_response_text(result)` | Pulls text from CallToolResult content blocks |
| `rate_limited_call(session, tool, args)` | Wraps tool calls with timeout + rate limit |
| `groq_call(model, messages, key)` | Optional LLM client for semantic layer |

The safety layer is what makes dynamic detection work against any MCP server. Detectors don't need to understand individual tools — they just need the schema, which `safety.py` knows how to interpret.


Each detector is a single Python file in `detectors/static/`, `detectors/dynamic/`, or `detectors/semantic/`. Adding a new detector:

1. Create the file
2. Define the class inheriting from the correct base
3. Register it in the orchestrator's detector list

That's it. No framework registration, no plugin manifest, no decorator magic.

### 5. Detectors (`detectors/`)

Three categories, each with distinct responsibilities and trust levels.

#### Static detectors

Analyze tool metadata (name, description, schema) without calling any tools. Always safe to run. Fast (<100ms per server).

Pattern: iterate `tool.labelled_text_fields`, match against pattern lists, return findings.

Shared pattern lists live in `detectors/patterns.py` so static and dynamic detectors don't duplicate them.

| Detector | Mechanism | Cross-tool? |
|----------|-----------|-------------|
| S1 Injection Phrases | regex IGNORECASE | No |
| S2 Suspicious Tags | regex IGNORECASE + DOTALL | No |
| S3 Hidden Unicode | character-by-character `unicodedata` inspection | No |
| S4 Sensitive Paths | case-insensitive substring | No |
| S5 Secrecy Instructions | regex IGNORECASE | No |
| S6 Schema Validator | JSON schema tree walk | No |
| S7 Tool Shadowing | name comparison + Levenshtein fuzzy match | No |
| S10 Lethal Trifecta | three-bucket classification across all tools | Yes |

#### Dynamic detectors

Actually call tools and analyze responses. Only run on tools classified as safe. Rate-limited to 500ms between calls. Findings get `confirmed=True`.

| Detector | Probe | What we look for |
|----------|-------|------------------|
| D1 Echo Test | Unique UUID marker as string param | Marker in response |
| D2 Response Injection | Safe inputs | Static patterns matching response text |
| D3 Path Traversal | `../../etc/passwd` in path-named params | File content markers in response |
| D4 Credential Probe | `${VAR}` templates, error triggers | Credential patterns in response |
| D5 SSRF | Internal URLs in url-named params | Cloud metadata / service banners |

D5 is gated behind `--enable-ssrf` because it causes the target server to initiate internal network requests.

#### Semantic detector

Optional LLM-as-judge layer. Catches paraphrased attacks that regex misses.

| Detector | Model | Purpose |
|----------|-------|---------|
| L1 Semantic Judge | Meta Prompt Guard 2 (86M) + Llama 3.3 70B reasoning | Verdict + explanation |

Two-tier approach: small classifier for verdicts (cheap, fast, runs on every field), large model for reasoning (only when classifier flags content).


**Scoring algorithm:**
- Start at 100 points
- Each CRITICAL finding: -25 points
- Each HIGH finding: -10 points
- Each MEDIUM finding: -5 points
- Each LOW finding: -1 point
- Clamp at 0 minimum

**Grade thresholds:** A+ (95-100), A (85-94), B (70-84), C (50-69), D (30-49), F (0-29)



Markdown report structure:
1. Header with target, tools, duration, score, grade
2. Severity summary table
3. Findings grouped by severity (descending)
4. Per-tool summary table
5. Disclaimer footer

Each finding renders as:
```
### [<rule_id>] <detector name> — <tool_name>
Field:     <field>
Evidence:  <truncated 200 chars>
Confirmed: Yes/No
Fix:       <suggested_fix>
```


## Detection phase comparison

| Aspect | Static | Dynamic | Semantic |
|--------|--------|---------|----------|
| Safe to run | Always | Only on safe tools | Always |
| Speed | <100ms total | ~500ms per tool | ~2s per scan |
| Cost | Free | Free | ~$0.001 per scan |
| Dependencies | None | None | Groq API key |
| Catches | Documented attack patterns | Confirmed vulnerabilities | Paraphrased attacks |
| Default | On | Off (opt-in) | Off (opt-in) |

**Why dynamic is opt-in by default:** Dynamic detectors call real tools on the target server. While the safety layer prevents calls to destructive tools, the principle of least surprise says: don't make network calls users didn't ask for. CI integrations should explicitly opt in.

**Why semantic is opt-in:** Requires an API key. Adds latency. Costs (tiny) money. Users should consciously enable it.

---

## Threat model coverage

Mapped to OWASP LLM Top 10 (2025):

| OWASP | Threat | Detectors |
|-------|--------|-----------|
| LLM01 | Prompt Injection (direct + indirect) | S1, S2, S3, D1, D2, L1 |
| LLM02 | Sensitive Information Disclosure | S4, D3, D4 |
| LLM05 | Improper Output Handling | S6, D4 |
| LLM06 | Excessive Agency | S5, S10, D5 |
| LLM07 | System Prompt Leakage | S4, D4 |
| LLM08 | Vector and Embedding Weaknesses | — (out of scope) |
| LLM09 | Misinformation | — (model-side, out of scope) |
| LLM10 | Unbounded Consumption | — (planned for v1.1) |

Additionally maps to research-specific threats:

| Research source | Threat | Detectors |
|-----------------|--------|-----------|
| Willison (2025) | Lethal Trifecta | S10 |
| Invariant Labs | Tool Poisoning | S1, S2, S4, S5 |
| Netskope | Rug Pull | (planned for v1.1 — requires diff engine) |
| Embrace The Red | Cross-server shadowing | S7 |

---

## Performance characteristics

**Static phase:** Constant time per tool. ~10ms per tool with 8 detectors. A 50-tool server completes in ~500ms.

**Dynamic phase:** Linear in tool count × applicable detectors. Each tool call takes 500ms (rate limit) + actual response time. Worst case ~3-5s per safe tool with all detectors enabled. 50-tool server: ~2-3 minutes.

**Semantic phase:** Linear in tool count × text fields. Prompt Guard runs ~200ms per field. 50-tool server with 3 fields each: ~30s.

**Memory:** O(n) in findings count. A typical scan produces <100 findings, <100KB of JSON.

---

## Operational concerns

**Logging.** Structured logs via Python's standard `logging`. Default INFO. DEBUG includes request/response payloads (redacted). Configurable via `MCP_SENTRY_LOG_LEVEL`.

**Error handling.** No detector failure should crash a scan. All detector `check()` methods are wrapped in try/except in the orchestrator. Errors become INFO findings: "Detector X errored: <message>".

**Timeouts.** Per-tool timeout default 10s. Configurable via `--timeout`. Whole-scan timeout: 5 minutes (hardcoded, configurable in v1.1).

**Authentication.** v1 supports `Authorization: Bearer <token>` headers via `--token` flag. OAuth 2.1 deferred to v2.

**Privacy.** Target URLs are not logged in plaintext on the hosted version. Findings never include the raw tool description from the target — only matched substrings (truncated). Credentials are redacted to first 6 chars + "...REDACTED".

---

## Future architecture (v1.1+)

**Persistence layer.** SQLite database for scan history. Schema:
```
servers (id, url, first_seen, last_scanned)
scans (id, server_id, timestamp, score, grade, full_report_json)
findings (id, scan_id, rule_id, severity, ...)  -- normalized for querying
```

**Diff engine.** Given two scans of the same URL, compute:
- Tools added / removed / changed
- New findings vs resolved findings
- Score delta over time

This is the foundation for rug pull detection — a clean tool today, a poisoned tool tomorrow, surfaced as a diff.

**Scheduler.** A daemon that periodically rescans registered servers. Initial design: cron-style with `crontab` syntax. APScheduler is a reasonable library choice.

**Alerting.** Webhook publisher. When a diff shows score regression, POST to configured endpoint (Slack, Discord, email, PagerDuty). Templated payload.

**Web dashboard.** A small FastAPI + HTMX app. Lists monitored servers, current grades, scan history, alerts. Optional — most users will consume via API or CLI.

**MCP marketplace integration.** Auto-discover public MCP servers, scan them on a schedule, publish a public leaderboard. This is the project's "platform" mode.

These components are designed not to break the v1 architecture. The orchestrator stays a one-shot function; persistence and scheduling are wrappers around it.

---

## Decisions and tradeoffs

**Why Pydantic v2 instead of dataclasses?** Validation. Untrusted MCP servers return data we don't control. Pydantic catches bad shapes at the boundary instead of crashing detectors mid-run.

**Why async throughout?** The MCP SDK is async. Dynamic detectors need to call tools sequentially with rate limiting, which is natural in async. The cost of async (slight readability overhead) is dwarfed by the benefit of not blocking on I/O.

**Why a single grading algorithm instead of configurable severity weights?** Consistency. Two scans of the same server should produce the same grade regardless of who ran them. Configurable weights would fragment that.

**Why no plugin system in v1?** Plugin systems are easy to ship and hard to maintain. Until there's evidence of real demand from external contributors, file-per-detector is enough.

**Why MIT instead of GPL?** Security tools should be maximally adoptable. MIT lets companies embed mcp-sentry in proprietary security platforms, which expands real-world impact.

**Why opt-in for dynamic detection?** Surprise factor. Users running `mcp-sentry scan https://example.com/mcp` should not, by default, make the scanner cause the target server to do anything beyond responding to `list_tools`. The static phase is fully passive; dynamic is not. Opt-in respects that distinction.

---

## What this doesn't do

Honest limitations worth knowing about:

- **No deobfuscation.** A server can encode malicious text in base64 in its description. We flag long base64 strings as suspicious but don't decode and re-scan. v2 work.

- **No multi-language pattern coverage.** All patterns are English. A description in Chinese saying "ignore previous instructions" won't trigger S1. v2 work.

- **No state across sessions.** Each scan is independent. A server that returns malicious content only after 100 calls won't be detected. Adversarial servers may explicitly behave differently for scanners. Documented limitation, not solvable.

- **No proof of vulnerability beyond confirmation.** D3 confirms path traversal exists. It doesn't enumerate every readable file. Scanner is not a pentest replacement.

- **No remediation enforcement.** We report findings. We don't fix them. Server authors must act on the report.

These limitations are documented because they shape what "passes" mcp-sentry actually means. A clean grade means "no known attack patterns detected in this scan." Not "this server is safe to trust with secrets."

# REA Studio (Reverse Engineer Anything Studio)

REA Studio is a reproducible reverse-engineering platform built on the principles of evidence provenance, cryptographic reproducibility, and strict boundary isolation.

Rather than acting as an opaque guessing tool, REA Studio records verifiable evidence records into a tamper-evident ledger, separates factual observations from derived inferences, and explicitly documents residual unknowns.

---

## Architecture Overview

```text
                         ┌──────────────────────┐
                         │      REA Studio      │
                         │       Web UI         │
                         └──────────┬───────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
              Web Reconnaissance   Artifact Lab   Verification Engine
                    │               │               │
                    └───────────────┼───────────────┘
                                    │
                         Reconnaissance Pipeline
                    ┌───────────────┼───────────────┐
                    │               │               │
               Anti-SSRF Guard  AST & DOM Extractor   Tech Fingerprint
                    │               │               │
                    └───────────────┼───────────────┘
                                    │
                       Evidence & Findings Ledger
                                    │
                       ┌────────────┴────────────┐
                       │                         │
                 SQLite Storage           Export Bundle (.json)
                 (rea_studio.db)                 │
                       │                         │
                       └────────────┬────────────┘
                                    │
                        Offline Replay Engine
```

---

## Target Capability Registry (Phase 3 Status)

| Target Type | Status | Acquisition Method | Available Analysis Stages | Limitations |
| :--- | :--- | :--- | :--- | :--- |
| **`web_url`** | **Supported** | Pinned DNS `safeFetch` with Anti-SSRF | 10 stages (Target, Headers, DOM, Scripts, Tech, Endpoints, Agent, Graph, Sealing) | Static edge reconnaissance; authenticated sessions require interactive state |
| **`local_artifact`** | **Stand-alone in Lab** | Local buffer parser | Dependency extraction, export symbol listing, candidate path discovery | Workspace pipeline disabled in Phase 3; use Artifact Lab tab |
| **`browser_target`** | **Planned (Future)** | Chrome DevTools Protocol (CDP) | DOM snapshots, HAR capture | Browser automation disabled in Phase 3 |
| **`binary`** | **Planned (Future)** | Header parser & symbol extractor | PE/ELF headers, strings extraction | Native decompilation disabled in Phase 3 |
| **`archive`** | **Planned (Future)** | Archive virtual unpacker | ASAR/ZIP indexing | Dynamic unpacking disabled in Phase 3 |

*Unsupported target types are rejected with HTTP 400 Bad Request by the investigation API.*

---

## Security Model & Boundary Enforcement

1. **Anti-SSRF and IP Restrictions (`src/server/networkGuard.ts`)**:
   - Blocks IPv4 loopback (`127.0.0.0/8`, `0.0.0.0/8`).
   - Blocks RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
   - Blocks Cloud Metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
   - Blocks Carrier-Grade NAT (`100.64.0.0/10`) and documentation subnets (`198.51.100.0/24`).
   - Blocks IPv6 loopback (`::1`), ULA (`fc00::/7`), Link-Local (`fe80::/10`), and IPv4-mapped IPv6 bypass attempts (`::ffff:127.0.0.1`).
   - **Connection Pinning**: Validates resolved IP prior to connection and connects directly to the validated IP to eliminate DNS rebinding TOCTOU vulnerabilities.
   - **Redirect Validation**: Re-validates IP and protocol on each redirect hop (up to 5 redirects).

2. **Origin-Bound Endpoint Verification (`POST /api/verify-endpoint`)**:
   - **Normalized Origin Equality**: Compares scheme, hostname, and effective port (`getNormalizedOrigin`).
   - **Discovered Scope Binding**: Rejects probes to endpoints not previously discovered in the investigation session.
   - **Safe Methods Only**: Only idempotent safe methods (`GET`, `HEAD`, `OPTIONS`) are permitted. State-changing methods (`POST`, `PUT`, `DELETE`, `PATCH`) return HTTP 405 Method Not Allowed.
   - **Redirect Scope Enforcement**: Prohibits cross-origin redirects during verification.

---

## Durable Storage & SQLite Persistence

- Backed by native `node:sqlite` in Node 22 (`data/rea_studio.db`).
- Schema migrations track versioned table definitions (`schema_migrations`, `investigations`, `evidence_records`, `findings`).
- Atomic transactions (`BEGIN` ... `COMMIT`) wrap session saves and updates.
- Collision-resistant unique IDs generated via `crypto.randomUUID()`.
- Failed and partially completed investigations are preserved alongside failure evidence.
- Full recovery across process restarts verified by automated test suites.

---

## Versioned Evidence Schema & Replay Contract

Every evidence record is sealed under version `1.0.0`:

```typescript
export interface EvidenceRecord {
  evidence_id: string;
  schema_version: '1.0.0';
  type: 'observation' | 'derivation' | 'runtime_capture';
  phase: string;
  source: {
    kind: 'http_response' | 'http_headers' | 'html_dom' | 'script_ast' | 'config_literal' | 'network_probe';
    location: string;
    sha256: string;
    bytes?: number;
  };
  content: Record<string, any>;
  canonical_digest: string;
  authority: 'direct' | 'derived' | 'heuristic';
  timestamp: string;
  tool: string;
  limitations: string[];
  parent_evidence_ids?: string[];
}
```

- **Deterministic Digesting**: Recursively sorts JSON keys before computing SHA-256 digests.
- **Replay Verification**: Offline replay recomputes each evidence record digest directly against the stored payload, verifying that `declared_digest === recomputed_digest`.
- **Session Manifest Hash**: Calculates session-wide integrity hash to detect added, removed, or modified evidence records.
- **Standalone Export Bundles**: Downloadable `.rea-bundle.json` files can be replayed entirely offline without initiating any network connections.

---

## Getting Started

### Prerequisites

- Node.js 22+
- Bun 1.2+ (Recommended package manager)

### Installation

```bash
bun install --frozen-lockfile
```

### Development

```bash
bun run dev
```

### Running Tests

```bash
bun run test
```

### Static Type Check & Build

```bash
bun run lint
bun run build
```

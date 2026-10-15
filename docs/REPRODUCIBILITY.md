# REA Studio — Reproducibility & Investigation Replay Specification

## 1. Guiding Principle

> **"REA Studio does not tell you what it thinks happened. It records what was observed, shows what can reasonably be inferred, identifies what remains unknown, and makes the investigation reproducible."**

---

## 2. What Replay Guarantees

When an investigation session is replayed using `POST /api/replay-investigation`:

1. **Deterministic Evidence Verification**:
   - Every evidence node preserves an immutable SHA-256 hash computed over its original byte payload.
   - Replay verifies that no content, source location, or metadata was tampered with or modified.
2. **Stable Normalized Findings**:
   - Findings generated from identical evidence sets yield identical classifications (`observation` vs `inference`), confidence scores, and dependency links.
3. **Explicit Scope Preservation**:
   - Declared parameters (timeout, byte limits, user-agent, toolchain versions) are fixed in the manifest.
4. **Offline Ledger Isolation**:
   - Offline replay does **not** make new network calls. It replays analysis strictly against captured, signed evidence nodes.

---

## 3. What Replay CANNOT Guarantee (Inherent Boundaries)

1. **Live Remote Volatility**:
   - Public web servers frequently alter content, rotate deployment hashes (e.g. `app.83f2.js` &rarr; `app.a92c.js`), run A/B experiments, or geo-locate responses.
   - Replay of *live acquisition* (`mode: "live_diff"`) detects changes across time; it cannot guarantee that remote origin servers remain static.
2. **Server-Side Masked Logic**:
   - Replay can only verify observed surface evidence. Logic hidden behind backend gateways (private databases, proprietary LLM prompt templates) remains an explicit **Unknown**.
3. **Authentication-Guarded Flows**:
   - Unauthenticated reconnaissance cannot prove the absence of endpoints or features that require user login or specific multi-factor credentials.

---

## 4. Manifest Schema (`manifest.json`)

```json
{
  "manifest_version": "1.0.0",
  "investigation_id": "INV-2026-00142",
  "target": {
    "type": "web_url",
    "identifier": "https://example.com/",
    "identity_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "capabilities": [
      "http_acquisition",
      "edge_fingerprinting",
      "html_dom_inspection",
      "script_inventory",
      "endpoint_extraction",
      "technology_detection"
    ]
  },
  "toolchain": {
    "rea_version": "6.5.0",
    "studio_version": "1.0.0",
    "node_version": "v22.23.3"
  },
  "parameters": {
    "timeout_ms": 10000,
    "max_response_bytes": 5242880,
    "user_agent": "rea-web-engine@6.5.0"
  },
  "timeline": []
}
```

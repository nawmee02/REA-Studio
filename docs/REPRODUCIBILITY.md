# REA Studio — Reproducibility & Investigation Replay Specification

## 1. Guiding Principle

> **"REA Studio does not tell you what it thinks happened. It records what was observed, shows what can reasonably be inferred, identifies what remains unknown, and makes the investigation reproducible."**

---

## 2. Cryptographic Integrity: Hashes vs. Signatures

A critical distinction enforced in Phase 3 is between **hash verification** and **cryptographic digital signatures**:

- **SHA-256 Payload Digests (`hash-verified`)**:
  - REA Studio computes deterministic SHA-256 digests over normalized, canonical JSON representations of evidence records (`computeEvidenceContentDigest`).
  - SHA-256 digests prove **tamper detection** and **internal consistency**: if a byte of captured evidence or metadata is modified, the recomputed digest will mismatch.
  - A SHA-256 digest alone **does not** prove external authenticity, provenance of the observer, or the truthfulness of origin servers.
  - Therefore, REA Studio labels its integrity status as `hash-verified` or `integrity-check-passed`, strictly avoiding misleading claims like "signed signatures" or "proof of truth".

---

## 3. What Offline Replay Guarantees

When an investigation session or export bundle is replayed using `POST /api/replay-investigation`:

1. **Deterministic Digest Recomputation**:
   - Replay **does not** merely check if `source.sha256` has 64 characters.
   - It re-serializes `ev.content` using recursive canonical key sorting (`canonicalJsonStringify`) and recomputes the SHA-256 digest.
   - Any difference between the declared digest and recomputed digest flags the record as corrupted with `tamper_detected: true`.

2. **Session-Wide Manifest Integrity**:
   - Manifest integrity is verified by hashing the composite tuple:
     `(investigation_id, target_identifier, target_hash, sorted evidence digests, sorted finding claims, unknowns, parameters)`.
   - Any injected, deleted, or unmanifested evidence node causes `manifest_intact: false`.

3. **Finding Citation Integrity**:
   - Every finding must cite one or more valid, existing evidence records in `evidence_ids`.
   - If a finding cites an invalid or corrupted evidence record, replay records an invalid citation error.

4. **Zero Network Calls**:
   - Offline replay operates strictly on the captured evidence ledger and payloads. It makes no HTTP, DNS, or socket calls.

---

## 4. What Replay CANNOT Guarantee (Inherent Boundaries)

1. **Live Remote Volatility**:
   - Public web servers alter deployments, rotate bundler hashes, perform A/B testing, and geolocate traffic.
   - Replay guarantees fidelity to the *captured state*, not that the live third-party origin remains unchanged today.
2. **Server-Side Masked Logic**:
   - Private databases, proprietary backend proxies, and LLM prompt templates remain explicitly documented in `unknowns`.
3. **Authentication-Guarded Surfaces**:
   - Unauthenticated reconnaissance establishes observed surface contracts; it cannot prove absence of unexposed authenticated capabilities.

---

## 5. Versioned Export Bundle Schema (`bundle_version: "1.0.0"`)

REA Studio packages investigations into self-contained, reproducible export bundles (`.rea-bundle.json`):

```json
{
  "bundle_version": "1.0.0",
  "exported_at": "2026-10-15T19:40:00.000Z",
  "investigation": {
    "investigation_id": "INV-2026-c5678a12-...",
    "goal": "Reconnaissance",
    "target": {
      "type": "web_url",
      "identifier": "https://example.com",
      "identity_hash": "...",
      "capabilities": [...]
    },
    "toolchain": {
      "rea_version": "6.5.0",
      "studio_version": "1.0.0",
      "node_version": "v22"
    },
    "status": "COMPLETED",
    "evidence_sources": {
      "static_analysis": true,
      "runtime_observation": false,
      "network_inspection": true,
      "version_comparison": false
    },
    "evidence": [...],
    "findings": [...],
    "unknowns": [...],
    "coverage": {
      "stages_executed": 10,
      "stages_total": 12,
      "stages_skipped": 2,
      "stages_failed": 0
    },
    "timeline": [...],
    "graph": { "nodes": [...], "edges": [...] },
    "manifest": {
      "created_at": "...",
      "completed_at": "...",
      "parameters": { ... },
      "integrity_hash": "..."
    }
  },
  "evidence_payloads": {
    "ev_inv_001_target": { ... },
    "ev_inv_002_headers": { ... }
  },
  "report_markdown": "# REA Investigation Report...",
  "integrity": {
    "evidence_count": 8,
    "findings_count": 5,
    "manifest_hash": "...",
    "bundle_hash": "...",
    "verification_status": "hash-verified"
  }
}
```

---

## 6. How to Replay an Export Bundle

### Via API

```bash
curl -s -X POST http://localhost:3000/api/replay-investigation \
  -H "Content-Type: application/json" \
  -d @exported-session.rea-bundle.json
```

### Response Format

```json
{
  "reproducibility": "DETERMINISTIC_OFFLINE",
  "investigation_id": "INV-2026-...",
  "evidence_integrity": {
    "total": 8,
    "verified_hashes": 8,
    "corrupted": 0,
    "corrupted_evidence_ids": [],
    "verification_items": [...]
  },
  "finding_integrity": {
    "total": 5,
    "valid_citations": 5,
    "invalid_citations": 0,
    "invalid_finding_ids": []
  },
  "manifest_hash": "...",
  "recomputed_manifest_hash": "...",
  "manifest_intact": true
}
```

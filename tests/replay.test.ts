import { test, describe, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'http';
import { 
  replayInvestigationOffline, 
  sha256, 
  computeEvidenceContentDigest,
  computeSessionIntegrityHash 
} from '../src/server/replay';
import { InvestigationSession, EvidenceRecord } from '../src/types/investigation';
import { createInvestigationApp } from '../src/server/app';

describe('Cryptographic Replay & Tamper Detection', () => {
  let server: http.Server;
  let baseUrl: string;

  before(async () => {
    const app = createInvestigationApp();
    server = http.createServer(app);
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as any;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  function createSampleSession(): InvestigationSession {
    const targetUrl = 'https://example.com';
    const target = {
      type: 'web_url' as const,
      identifier: targetUrl,
      identity_hash: sha256(targetUrl),
      capabilities: ['http_acquisition']
    };

    const rawContent = { server: 'nginx', status: 200 };
    const contentDigest = computeEvidenceContentDigest(rawContent);

    const evidence: EvidenceRecord[] = [
      {
        evidence_id: 'ev_001_sample',
        schema_version: '1.0.0',
        type: 'observation',
        phase: 'header_inspection',
        source: {
          kind: 'http_headers',
          location: targetUrl,
          sha256: contentDigest
        },
        content: rawContent,
        canonical_digest: contentDigest,
        authority: 'direct',
        timestamp: '2026-10-15T12:00:00.000Z',
        tool: 'rea-header-inspector',
        limitations: []
      }
    ];

    const findings = [
      {
        finding_id: 'fd_001',
        claim: 'Server reports nginx',
        category: 'server' as const,
        classification: 'observation' as const,
        confidence: 1.0,
        status: 'VERIFIED' as const,
        evidence_ids: ['ev_001_sample'],
        method: 'Direct header match'
      }
    ];

    const manifestParams = { timeout_ms: 10000 };
    const createdAt = '2026-10-15T12:00:00.000Z';

    const integrityHash = computeSessionIntegrityHash({
      investigation_id: 'INV-2026-TEST01',
      target,
      evidence,
      findings,
      unknowns: [],
      manifest: {
        created_at: createdAt,
        parameters: manifestParams
      }
    });

    return {
      investigation_id: 'INV-2026-TEST01',
      goal: 'Replay Test',
      target,
      toolchain: {
        rea_version: '6.5.0',
        studio_version: '1.0.0',
        node_version: 'v22'
      },
      status: 'COMPLETED',
      evidence_sources: {
        static_analysis: true,
        runtime_observation: false,
        network_inspection: true,
        version_comparison: false
      },
      evidence,
      findings,
      unknowns: [],
      coverage: {
        stages_executed: 1,
        stages_total: 12,
        endpoints_discovered: 0,
        endpoints_verified: 0,
        scripts_mapped: 0,
        technologies_confirmed: 0
      },
      timeline: [],
      graph: { nodes: [], edges: [] },
      manifest: {
        created_at: createdAt,
        completed_at: createdAt,
        parameters: manifestParams,
        integrity_hash: integrityHash
      }
    };
  }

  test('validates clean session with 0 corrupted records and intact manifest', () => {
    const session = createSampleSession();
    const report = replayInvestigationOffline(session);

    assert.strictEqual(report.reproducibility, 'DETERMINISTIC_OFFLINE');
    assert.strictEqual(report.evidence_integrity.total, 1);
    assert.strictEqual(report.evidence_integrity.verified_hashes, 1);
    assert.strictEqual(report.evidence_integrity.corrupted, 0);
    assert.strictEqual(report.evidence_integrity.corrupted_evidence_ids.length, 0);
    assert.strictEqual(report.manifest_intact, true);
    assert.strictEqual(report.finding_integrity.invalid_citations, 0);
  });

  test('detects tampered content when evidence payload is modified', () => {
    const session = createSampleSession();

    // Modify the evidence content without updating the declared digest
    session.evidence[0].content.server = 'apache';

    const report = replayInvestigationOffline(session);

    assert.strictEqual(report.evidence_integrity.corrupted, 1, 'Must detect 1 corrupted record');
    assert.strictEqual(report.evidence_integrity.verified_hashes, 0);
    assert.ok(report.evidence_integrity.corrupted_evidence_ids.includes('ev_001_sample'));
    assert.strictEqual(report.manifest_intact, false, 'Manifest must not be intact when evidence is altered');
  });

  test('detects tampered source digest when hash is replaced with mismatched 64-char hex', () => {
    const session = createSampleSession();

    // Replace declared digest with an arbitrary different 64-character hash
    session.evidence[0].source.sha256 = sha256('completely-unrelated-payload');

    const report = replayInvestigationOffline(session);

    assert.strictEqual(report.evidence_integrity.corrupted, 1);
    assert.strictEqual(report.evidence_integrity.verified_hashes, 0);
    assert.ok(report.evidence_integrity.corrupted_evidence_ids.includes('ev_001_sample'));
    assert.strictEqual(report.manifest_intact, false);
  });

  test('detects malformed digest format', () => {
    const session = createSampleSession();

    session.evidence[0].source.sha256 = 'invalid_short_digest';

    const report = replayInvestigationOffline(session);

    assert.strictEqual(report.evidence_integrity.corrupted, 1);
    assert.strictEqual(report.evidence_integrity.verified_hashes, 0);
    assert.strictEqual(report.manifest_intact, false);
  });

  test('detects finding with invalid evidence citation', () => {
    const session = createSampleSession();

    // Citation points to non-existent evidence ID
    session.findings[0].evidence_ids = ['ev_ghost_nonexistent_id'];

    const report = replayInvestigationOffline(session);

    assert.strictEqual(report.finding_integrity.invalid_citations, 1);
    assert.ok(report.finding_integrity.invalid_finding_ids.includes('fd_001'));
  });

  test('detects injected unauthorized evidence node via session integrity hash', () => {
    const session = createSampleSession();

    // Inject an extra unmanifested evidence record
    const injectedContent = { unauthorized: true };
    const injectedDigest = computeEvidenceContentDigest(injectedContent);
    session.evidence.push({
      evidence_id: 'ev_injected_evil',
      schema_version: '1.0.0',
      type: 'observation',
      phase: 'injected',
      source: {
        kind: 'config_literal',
        location: 'https://evil.com',
        sha256: injectedDigest
      },
      content: injectedContent,
      canonical_digest: injectedDigest,
      authority: 'heuristic',
      timestamp: new Date().toISOString(),
      tool: 'attacker',
      limitations: []
    });

    const report = replayInvestigationOffline(session);

    // The individual evidence has a valid internal hash, but the session manifest integrity is broken
    assert.strictEqual(report.manifest_intact, false, 'Manifest integrity must fail when session evidence is altered');
  });

  test('POST /api/replay-investigation endpoint verifies session via API', async () => {
    const cleanSession = createSampleSession();

    const cleanRes = await fetch(`${baseUrl}/api/replay-investigation`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session: cleanSession,
        mode: 'offline_ledger'
      })
    });

    assert.strictEqual(cleanRes.status, 200);
    const cleanBody = await cleanRes.json() as any;
    assert.strictEqual(cleanBody.evidence_integrity.corrupted, 0);
    assert.strictEqual(cleanBody.manifest_intact, true);

    // Now test sending a tampered session to the API
    const tamperedSession = createSampleSession();
    tamperedSession.evidence[0].content.status = 500; // Tampered payload

    const tamperedRes = await fetch(`${baseUrl}/api/replay-investigation`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session: tamperedSession,
        mode: 'offline_ledger'
      })
    });

    assert.strictEqual(tamperedRes.status, 200);
    const tamperedBody = await tamperedRes.json() as any;
    assert.strictEqual(tamperedBody.evidence_integrity.corrupted, 1);
    assert.ok(tamperedBody.evidence_integrity.corrupted_evidence_ids.includes('ev_001_sample'));
    assert.strictEqual(tamperedBody.manifest_intact, false);
  });

  test('replays standalone export bundle offline without network calls', async () => {
    const session = createSampleSession();
    const bundle = {
      bundle_version: '1.0.0',
      exported_at: new Date().toISOString(),
      investigation: session,
      evidence_payloads: {
        ev_001_sample: session.evidence[0].content
      },
      report_markdown: '# Report',
      integrity: {
        evidence_count: 1,
        findings_count: 1,
        manifest_hash: session.manifest.integrity_hash || '',
        bundle_hash: sha256('bundle-hash'),
        verification_status: 'hash-verified' as const
      }
    };

    const res = await fetch(`${baseUrl}/api/replay-investigation`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        bundle,
        mode: 'offline_bundle'
      })
    });

    assert.strictEqual(res.status, 200);
    const report = await res.json() as any;
    assert.strictEqual(report.reproducibility, 'DETERMINISTIC_OFFLINE');
    assert.strictEqual(report.evidence_integrity.corrupted, 0);
    assert.strictEqual(report.manifest_intact, true);
  });

  test('rejects corrupted or unsupported export bundle version with 400', async () => {
    const corruptedBundle = {
      bundle_version: '0.0.1-invalid',
      investigation: null
    };

    const res = await fetch(`${baseUrl}/api/replay-investigation`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        bundle: corruptedBundle,
        mode: 'offline_bundle'
      })
    });

    assert.strictEqual(res.status, 400);
    const body = await res.json() as any;
    assert.ok(body.error.includes('Corrupted or unsupported export bundle'));
  });
});

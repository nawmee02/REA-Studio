import { test, describe } from 'node:test';
import assert from 'node:assert';
import crypto from 'crypto';
import { EvidenceRecord, FindingRecord } from '../src/types/investigation';

describe('Evidence & Finding Truth Model', () => {
  function sha256(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  test('SHA-256 digests are stable and deterministic', () => {
    const payload = '<html><head><title>Test App</title></head></html>';
    const hash1 = sha256(payload);
    const hash2 = sha256(payload);
    assert.strictEqual(hash1, hash2);
    assert.strictEqual(hash1.length, 64);
  });

  test('every finding strictly references valid evidence records', () => {
    const evidence: EvidenceRecord[] = [
      {
        evidence_id: 'ev_001',
        type: 'observation',
        phase: 'header_inspection',
        source: {
          kind: 'http_headers',
          location: 'https://example.com',
          sha256: sha256('headers')
        },
        content: { server: 'Cloudflare' },
        authority: 'direct',
        timestamp: new Date().toISOString(),
        tool: 'rea-header-inspector',
        limitations: []
      }
    ];

    const findings: FindingRecord[] = [
      {
        finding_id: 'fd_001',
        claim: 'Site is served behind Cloudflare edge',
        category: 'server',
        classification: 'observation',
        confidence: 1.0,
        status: 'VERIFIED',
        evidence_ids: ['ev_001'],
        method: 'Header check'
      }
    ];

    const evidenceIdSet = new Set(evidence.map(e => e.evidence_id));

    // Verify citation validity
    for (const f of findings) {
      assert.ok(f.evidence_ids.length > 0, `Finding ${f.finding_id} must cite at least one evidence record`);
      for (const citedId of f.evidence_ids) {
        assert.ok(evidenceIdSet.has(citedId), `Finding ${f.finding_id} cites non-existent evidence ${citedId}`);
      }
    }
  });

  test('inferences cite supporting observations and maintain confidence bounds', () => {
    const inference: FindingRecord = {
      finding_id: 'fd_002',
      claim: 'Application likely uses client-side state machine',
      category: 'architecture',
      classification: 'inference',
      confidence: 0.85,
      status: 'VERIFIED',
      evidence_ids: ['ev_001', 'ev_002'],
      supports: ['ev_001'],
      method: 'Derived from bundle module patterns'
    };

    assert.strictEqual(inference.classification, 'inference');
    assert.ok(inference.confidence >= 0 && inference.confidence <= 1.0);
    assert.ok(inference.supports && inference.supports.length > 0);
  });
});

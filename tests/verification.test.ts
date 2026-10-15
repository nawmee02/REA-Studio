import { test, describe, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'http';
import { createInvestigationApp } from '../src/server/app';
import { getNormalizedOrigin } from '../src/server/networkGuard';
import { saveInvestigation, deleteInvestigation } from '../src/server/persistence';
import { InvestigationSession } from '../src/types/investigation';
import { computeEvidenceContentDigest, computeSessionIntegrityHash } from '../src/server/replay';

describe('Origin-Bound Endpoint Verification Tests', () => {
  let server: http.Server;
  let baseUrl: string;
  const testSessionId = 'INV-2026-VERIFY-SCOPE-01';

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

    // Seed test session with a target and a discovered endpoint
    const targetUrl = 'https://example.com';
    const target = {
      type: 'web_url' as const,
      identifier: targetUrl,
      identity_hash: 'abc123identityhash',
      capabilities: ['http_acquisition', 'endpoint_extraction']
    };

    const epContent = { endpoints: [{ path: '/api/v1/health', type: 'rest', source: 'script_string_literal' }] };
    const epDigest = computeEvidenceContentDigest(epContent);

    const session: InvestigationSession = {
      investigation_id: testSessionId,
      goal: 'Endpoint Verification Scope Test',
      target,
      toolchain: { rea_version: '6.5.0', studio_version: '1.0.0', node_version: 'v22' },
      status: 'COMPLETED',
      evidence_sources: {
        static_analysis: true,
        runtime_observation: false,
        network_inspection: true,
        version_comparison: false
      },
      evidence: [
        {
          evidence_id: 'ev_ep_disc',
          schema_version: '1.0.0',
          type: 'observation',
          phase: 'endpoint_extraction',
          source: {
            kind: 'script_ast',
            location: targetUrl,
            sha256: epDigest
          },
          content: epContent,
          canonical_digest: epDigest,
          authority: 'direct',
          timestamp: new Date().toISOString(),
          tool: 'rea-endpoint-extractor',
          limitations: []
        }
      ],
      findings: [
        {
          finding_id: 'fd_ep_01',
          claim: 'Discovered candidate endpoint: "/api/v1/health"',
          category: 'endpoint',
          classification: 'observation',
          confidence: 0.8,
          status: 'DISCOVERED',
          evidence_ids: ['ev_ep_disc'],
          method: 'Static extraction',
          details: { path: '/api/v1/health', type: 'rest' }
        }
      ],
      unknowns: [],
      coverage: {
        stages_executed: 10,
        stages_total: 12,
        endpoints_discovered: 1,
        endpoints_verified: 0,
        scripts_mapped: 0,
        technologies_confirmed: 0
      },
      timeline: [],
      graph: { nodes: [], edges: [] },
      manifest: {
        created_at: new Date().toISOString(),
        parameters: { timeout_ms: 5000 }
      }
    };

    saveInvestigation(session);
  });

  after(async () => {
    deleteInvestigation(testSessionId);
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  test('getNormalizedOrigin compares scheme, hostname, and effective port correctly', () => {
    assert.strictEqual(getNormalizedOrigin('https://example.com'), 'https://example.com:443');
    assert.strictEqual(getNormalizedOrigin('https://example.com:443'), 'https://example.com:443');
    assert.strictEqual(getNormalizedOrigin('http://example.com'), 'http://example.com:80');
    assert.strictEqual(getNormalizedOrigin('http://example.com:8080'), 'http://example.com:8080');
    assert.strictEqual(getNormalizedOrigin('https://EXAMPLE.COM/path?foo=1'), 'https://example.com:443');

    // Mismatches
    assert.notStrictEqual(getNormalizedOrigin('http://example.com'), getNormalizedOrigin('https://example.com'));
    assert.notStrictEqual(getNormalizedOrigin('https://example.com:8443'), getNormalizedOrigin('https://example.com:443'));
    assert.notStrictEqual(getNormalizedOrigin('https://sub.example.com'), getNormalizedOrigin('https://example.com'));
  });

  test('rejects state-changing HTTP methods (POST, PUT, DELETE) with 405 Method Not Allowed', async () => {
    const unpermittedMethods = ['POST', 'PUT', 'DELETE', 'PATCH'];

    for (const method of unpermittedMethods) {
      const res = await fetch(`${baseUrl}/api/verify-endpoint`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          investigation_id: testSessionId,
          endpoint_path: '/api/v1/health',
          method
        })
      });

      assert.strictEqual(res.status, 405, `Method ${method} should be rejected with 405`);
      const body = await res.json() as any;
      assert.ok(body.error && body.error.includes('Verification probes default to safe idempotent methods'));
    }
  });

  test('rejects endpoint candidate not discovered in session with 403 Forbidden', async () => {
    const res = await fetch(`${baseUrl}/api/verify-endpoint`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        investigation_id: testSessionId,
        endpoint_path: '/api/v1/unauthorized-ghost-endpoint',
        method: 'GET'
      })
    });

    assert.strictEqual(res.status, 403);
    const body = await res.json() as any;
    assert.ok(body.error.includes('Scope violation'));
    assert.ok(body.error.includes('was not discovered in investigation'));
  });

  test('rejects cross-origin endpoint candidate with 403 Forbidden', async () => {
    const res = await fetch(`${baseUrl}/api/verify-endpoint`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        investigation_id: testSessionId,
        endpoint_path: 'https://evil.attacker.com/api/v1/health',
        method: 'GET'
      })
    });

    assert.strictEqual(res.status, 403);
    const body = await res.json() as any;
    assert.ok(body.error.includes('Scope violation'));
  });

  test('rejects alternate scheme (http vs https) with 403 Forbidden', async () => {
    const res = await fetch(`${baseUrl}/api/verify-endpoint`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        investigation_id: testSessionId,
        endpoint_path: 'http://example.com/api/v1/health',
        method: 'GET'
      })
    });

    assert.strictEqual(res.status, 403);
    const body = await res.json() as any;
    assert.ok(body.error.includes('Scope violation'));
  });

  test('rejects alternate port (e.g. :8443 vs :443) with 403 Forbidden', async () => {
    const res = await fetch(`${baseUrl}/api/verify-endpoint`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        investigation_id: testSessionId,
        endpoint_path: 'https://example.com:8443/api/v1/health',
        method: 'GET'
      })
    });

    assert.strictEqual(res.status, 403);
    const body = await res.json() as any;
    assert.ok(body.error.includes('Scope violation'));
  });

  test('returns 404 for non-existent investigation ID', async () => {
    const res = await fetch(`${baseUrl}/api/verify-endpoint`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        investigation_id: 'INV-DOES-NOT-EXIST',
        endpoint_path: '/api/v1/health',
        method: 'GET'
      })
    });

    assert.strictEqual(res.status, 404);
  });
});

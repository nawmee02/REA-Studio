import { test, describe, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'http';
import { createInvestigationApp } from '../src/server/app';
import { saveInvestigation, deleteInvestigation } from '../src/server/persistence';
import { InvestigationSession } from '../src/types/investigation';
import { getRepository, setCustomRepository } from '../src/server/repository';

describe('Authentication, Authorization & Multi-Tenant Ownership Tests', () => {
  let server: http.Server;
  let baseUrl: string;

  const userA = 'operator-alpha';
  const userB = 'operator-bravo';
  const unauthorizedUser = 'unauthorized-intruder';

  const sessionAId = 'INV-AUTH-USER-A-001';
  const sessionBId = 'INV-AUTH-USER-B-002';

  before(async () => {
    process.env.FIREBASE_STORAGE_BACKEND = 'sqlite';
    process.env.NODE_ENV = 'test';
    // Allow userA and userB, exclude unauthorizedUser
    process.env.FIREBASE_ADMIN_UIDS = `${userA},${userB}`;

    const app = createInvestigationApp();
    server = http.createServer(app);
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as any;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // Seed session for user A
    const sessionA: InvestigationSession = {
      investigation_id: sessionAId,
      owner_uid: userA,
      goal: 'Operator Alpha Session',
      target: {
        type: 'web_url',
        identifier: 'https://alpha.internal',
        identity_hash: 'hash-alpha',
        capabilities: ['http_acquisition']
      },
      toolchain: { rea_version: '6.5.0', studio_version: '1.0.0', node_version: 'v22' },
      status: 'COMPLETED',
      evidence_sources: {
        static_analysis: true,
        runtime_observation: false,
        network_inspection: false,
        version_comparison: false
      },
      evidence: [],
      findings: [],
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
        created_at: new Date().toISOString(),
        parameters: {}
      }
    };

    // Seed session for user B
    const sessionB: InvestigationSession = {
      ...sessionA,
      investigation_id: sessionBId,
      owner_uid: userB,
      goal: 'Operator Bravo Session'
    };

    await saveInvestigation(sessionA, userA);
    await saveInvestigation(sessionB, userB);
  });

  after(async () => {
    await deleteInvestigation(sessionAId, userA);
    await deleteInvestigation(sessionBId, userB);
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  // 1. Authentication & Token Verification Tests
  test('rejects request with missing Authorization header with 401', async () => {
    const res = await fetch(`${baseUrl}/api/investigations`);
    assert.strictEqual(res.status, 401);
    const body = await res.json() as any;
    assert.strictEqual(body.code, 'auth/missing-token');
  });

  test('rejects request with invalid or malformed bearer token with 401', async () => {
    const res = await fetch(`${baseUrl}/api/investigations`, {
      headers: { 'Authorization': 'Bearer test-token:malformed' }
    });
    assert.strictEqual(res.status, 401);
    const body = await res.json() as any;
    assert.strictEqual(body.code, 'auth/invalid-id-token');
  });

  test('rejects request with expired token with 401', async () => {
    const res = await fetch(`${baseUrl}/api/investigations`, {
      headers: { 'Authorization': 'Bearer test-token:expired' }
    });
    assert.strictEqual(res.status, 401);
    const body = await res.json() as any;
    assert.strictEqual(body.code, 'auth/id-token-expired');
  });

  test('rejects request with revoked token with 401', async () => {
    const res = await fetch(`${baseUrl}/api/investigations`, {
      headers: { 'Authorization': 'Bearer test-token:revoked' }
    });
    assert.strictEqual(res.status, 401);
    const body = await res.json() as any;
    assert.strictEqual(body.code, 'auth/id-token-revoked');
  });

  test('rejects authenticated user not in FIREBASE_ADMIN_UIDS allowlist with 403 Forbidden', async () => {
    const res = await fetch(`${baseUrl}/api/investigations`, {
      headers: { 'Authorization': `Bearer test-token:${unauthorizedUser}` }
    });
    assert.strictEqual(res.status, 403);
    const body = await res.json() as any;
    assert.strictEqual(body.code, 'auth/forbidden-operator');
  });

  test('allows authorized operator UID with 200 OK', async () => {
    const res = await fetch(`${baseUrl}/api/investigations`, {
      headers: { 'Authorization': `Bearer test-token:${userA}` }
    });
    assert.strictEqual(res.status, 200);
  });

  test('every protected endpoint rejects unauthenticated requests with 401', async () => {
    const endpoints = [
      { path: '/api/investigations', method: 'GET' },
      { path: '/api/investigations/INV-001', method: 'GET' },
      { path: '/api/investigations/INV-001/export', method: 'GET' },
      { path: '/api/investigations', method: 'POST', body: {} },
      { path: '/api/verify-endpoint', method: 'POST', body: {} },
      { path: '/api/replay-investigation', method: 'POST', body: {} },
      { path: '/api/investigations/import', method: 'POST', body: {} },
      { path: '/api/analyze-artifact', method: 'POST', body: {} }
    ];

    for (const ep of endpoints) {
      const res = await fetch(`${baseUrl}${ep.path}`, {
        method: ep.method,
        headers: { 'Content-Type': 'application/json' },
        body: ep.body ? JSON.stringify(ep.body) : undefined
      });
      assert.strictEqual(res.status, 401, `Endpoint ${ep.method} ${ep.path} must return 401 when unauthenticated`);
    }
  });

  // 2. Multi-Tenant Ownership & Scope Isolation Tests
  test('User A can list only their own investigations, not User B sessions', async () => {
    const res = await fetch(`${baseUrl}/api/investigations`, {
      headers: { 'Authorization': `Bearer test-token:${userA}` }
    });
    assert.strictEqual(res.status, 200);
    const list = await res.json() as any[];
    const ids = list.map(i => i.investigation_id);

    assert.ok(ids.includes(sessionAId), 'User A must see their own session');
    assert.ok(!ids.includes(sessionBId), 'User A must NOT see User B session in list');
  });

  test('User A cannot fetch User B investigation details (returns 404)', async () => {
    const res = await fetch(`${baseUrl}/api/investigations/${sessionBId}`, {
      headers: { 'Authorization': `Bearer test-token:${userA}` }
    });
    assert.strictEqual(res.status, 404, 'Accessing another user investigation must return 404');
  });

  test('User A cannot export User B investigation bundle (returns 404)', async () => {
    const res = await fetch(`${baseUrl}/api/investigations/${sessionBId}/export`, {
      headers: { 'Authorization': `Bearer test-token:${userA}` }
    });
    assert.strictEqual(res.status, 404, 'Exporting another user investigation must return 404');
  });

  test('User A cannot verify an endpoint on User B session (returns 404)', async () => {
    const res = await fetch(`${baseUrl}/api/verify-endpoint`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer test-token:${userA}`
      },
      body: JSON.stringify({
        investigation_id: sessionBId,
        endpoint_path: '/api/v1/health',
        method: 'GET'
      })
    });
    assert.strictEqual(res.status, 404, 'Verifying endpoint on another user session must return 404');
  });

  test('import overrides client-supplied UID with verified caller UID', async () => {
    const testImportId = 'INV-IMPORT-OVERRIDE-01';
    const bundle = {
      bundle_version: '1.0.0',
      exported_at: new Date().toISOString(),
      investigation: {
        investigation_id: testImportId,
        owner_uid: 'spoofed-attacker-uid',
        goal: 'Import Test',
        target: {
          type: 'web_url',
          identifier: 'https://import-test.example',
          identity_hash: 'abc',
          capabilities: ['http_acquisition']
        },
        toolchain: { rea_version: '6.5.0', studio_version: '1.0.0', node_version: 'v22' },
        status: 'COMPLETED',
        evidence_sources: { static_analysis: true, runtime_observation: false, network_inspection: false, version_comparison: false },
        evidence: [],
        findings: [],
        unknowns: [],
        coverage: { stages_executed: 1, stages_total: 12, endpoints_discovered: 0, endpoints_verified: 0, scripts_mapped: 0, technologies_confirmed: 0 },
        timeline: [],
        graph: { nodes: [], edges: [] },
        manifest: { created_at: new Date().toISOString(), parameters: {} }
      },
      evidence_payloads: {},
      report_markdown: '# Report'
    };

    const res = await fetch(`${baseUrl}/api/investigations/import`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer test-token:${userA}`
      },
      body: JSON.stringify({ bundle })
    });

    assert.strictEqual(res.status, 200);
    const importedSession = await res.json() as any;
    assert.strictEqual(importedSession.owner_uid, userA, 'Owner UID must be bound to verified token, ignoring client-supplied field');

    // Clean up
    await deleteInvestigation(testImportId, userA);
  });
});

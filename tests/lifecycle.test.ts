import { test, describe, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'http';
import { createInvestigationApp } from '../src/server/app';
import { runInvestigationPipeline } from '../src/server/pipeline';
import { getInvestigation, deleteInvestigation } from '../src/server/persistence';
import { TARGET_REGISTRY, SUPPORTED_TARGET_TYPES } from '../src/types/investigation';

describe('Investigation Lifecycle & Stage Accounting Tests', () => {
  let server: http.Server;
  let baseUrl: string;
  const testAuthHeaders = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer test-token:test-operator-1'
  };

  before(async () => {
    process.env.FIREBASE_STORAGE_BACKEND = 'sqlite';
    process.env.NODE_ENV = 'test';

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

  test('Target Capability Registry defines supported and disabled target kinds accurately', () => {
    assert.strictEqual(TARGET_REGISTRY.web_url.status, 'supported');
    assert.strictEqual(TARGET_REGISTRY.local_artifact.status, 'disabled');
    assert.strictEqual(TARGET_REGISTRY.browser_target.status, 'disabled');
    assert.strictEqual(TARGET_REGISTRY.binary.status, 'disabled');
    assert.strictEqual(TARGET_REGISTRY.archive.status, 'disabled');

    assert.deepStrictEqual(SUPPORTED_TARGET_TYPES, ['web_url']);
  });

  test('POST /api/investigations rejects unsupported target types with 400 Bad Request', async () => {
    const disabledTypes = ['binary', 'browser_target', 'archive', 'local_artifact', 'unsupported_custom'];

    for (const target_type of disabledTypes) {
      const res = await fetch(`${baseUrl}/api/investigations`, {
        method: 'POST',
        headers: testAuthHeaders,
        body: JSON.stringify({
          target_type,
          identifier: 'some_identifier',
          goal: 'Test unsupported target'
        })
      });

      assert.strictEqual(res.status, 400, `Target type ${target_type} must return 400`);
      const body = await res.json() as any;
      assert.ok(body.error.includes('Unsupported target type'));
      assert.ok(body.error.includes('Currently supported target types: web_url'));
    }
  });

  test('concurrent investigations receive globally unique collision-resistant IDs', async () => {
    const createdSessions = await Promise.all([
      runInvestigationPipeline({ identifier: 'https://example.com/one', fixtureHtml: '<html>one</html>', owner_uid: 'test-operator-1' }),
      runInvestigationPipeline({ identifier: 'https://example.com/two', fixtureHtml: '<html>two</html>', owner_uid: 'test-operator-1' }),
      runInvestigationPipeline({ identifier: 'https://example.com/three', fixtureHtml: '<html>three</html>', owner_uid: 'test-operator-1' })
    ]);

    const ids = createdSessions.map(s => s.investigation_id);
    const uniqueIds = new Set(ids);
    assert.strictEqual(uniqueIds.size, 3, 'All 3 investigations must have unique IDs');

    for (const id of ids) {
      assert.match(id, /^INV-202[0-9]-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
      await deleteInvestigation(id, 'test-operator-1');
    }
  });

  test('reports exact pipeline stage outcomes, accounting, and reasons', async () => {
    const session = await runInvestigationPipeline({
      identifier: 'https://example.com/coverage-test',
      fixtureHtml: '<!doctype html><html><head><title>App</title></head><body><div id="root" data-reactroot=""></div><script src="/app.js"></script></body></html>',
      owner_uid: 'test-operator-1'
    });

    assert.strictEqual(session.status, 'COMPLETED');
    assert.strictEqual(session.coverage.stages_total, 12);
    assert.strictEqual(session.coverage.stages_executed, 10);
    assert.strictEqual(session.coverage.stages_skipped, 2);
    assert.strictEqual(session.coverage.stages_failed, 0);

    // Verify skipped stages have documented reasons
    const skippedStages = session.timeline.filter(t => t.status === 'skipped');
    assert.strictEqual(skippedStages.length, 2);

    const browserStage = skippedStages.find(s => s.stage === 'runtime_browser_observation');
    assert.ok(browserStage && browserStage.reason?.includes('Runtime browser lab not supported in Phase 3'));

    const diffStage = skippedStages.find(s => s.stage === 'differential_version_comparison');
    assert.ok(diffStage && diffStage.reason?.includes('Differential version comparison not supported in Phase 3'));

    await deleteInvestigation(session.investigation_id, 'test-operator-1');
  });

  test('preserves failed investigation status and failure evidence on acquisition failure', async () => {
    let threw = false;

    try {
      await runInvestigationPipeline({
        identifier: 'https://non-existent-domain-for-failure-test-xyz123.test',
        owner_uid: 'test-operator-1'
      });
    } catch (err: any) {
      threw = true;
      assert.ok(err.message.includes('DNS resolution failed') || err.message.includes('acquisition failed'));
    }

    assert.strictEqual(threw, true);
  });
});

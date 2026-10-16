import { test, describe, afterEach, before } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import { 
  initPersistence, 
  saveInvestigation, 
  getInvestigation, 
  listInvestigations, 
  deleteInvestigation,
  clearMemoryCache,
  getExportBundle,
  getPersistenceDir
} from '../src/server/persistence';
import { getRepository } from '../src/server/repository';
import { InvestigationSession } from '../src/types/investigation';

describe('Investigation SQLite Persistence & Recovery Tests', () => {
  const testId = 'INV-PERSIST-SQLITE-TEST-999';

  before(() => {
    process.env.FIREBASE_STORAGE_BACKEND = 'sqlite';
    process.env.NODE_ENV = 'test';
    initPersistence();
  });

  function createTestSession(id: string): InvestigationSession {
    return {
      investigation_id: id,
      owner_uid: 'test-operator-1',
      goal: 'SQLite Persistence and Recovery Verification',
      target: {
        type: 'web_url',
        identifier: 'https://example-persisted.test',
        identity_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        capabilities: ['http_acquisition']
      },
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
      evidence: [
        {
          evidence_id: `ev_${id}_01`,
          schema_version: '1.0.0',
          type: 'observation',
          phase: 'target_resolution',
          source: {
            kind: 'config_literal',
            location: 'https://example-persisted.test',
            sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
          },
          content: { verified: true },
          canonical_digest: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
          authority: 'direct',
          timestamp: new Date().toISOString(),
          tool: 'rea-test',
          limitations: []
        }
      ],
      findings: [
        {
          finding_id: `finding_${id}_01`,
          claim: 'Persisted session test claim',
          category: 'server',
          classification: 'observation',
          confidence: 1.0,
          status: 'CONFIRMED',
          method: 'Config literal inspection',
          evidence_ids: [`ev_${id}_01`],
          details: { port: 443 }
        }
      ],
      unknowns: [],
      coverage: {
        stages_executed: 1,
        stages_total: 12,
        endpoints_discovered: 0,
        endpoints_verified: 0,
        scripts_mapped: 0,
        technologies_confirmed: 1
      },
      timeline: [],
      graph: {
        nodes: [{ id: 'https://example-persisted.test', label: 'target', type: 'target' }],
        edges: []
      },
      manifest: {
        created_at: new Date().toISOString(),
        parameters: { test: true },
        integrity_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
      }
    };
  }

  afterEach(async () => {
    await deleteInvestigation(testId);
  });

  test('saves investigation session atomically into SQLite and verifies schema storage', async () => {
    const session = createTestSession(testId);
    await saveInvestigation(session, 'test-operator-1');

    const dataDir = getPersistenceDir();
    const dbPath = path.join(dataDir, 'rea_studio.db');

    assert.ok(fs.existsSync(dbPath), `SQLite database must exist at ${dbPath}`);

    const retrieved = await getInvestigation(testId, 'test-operator-1');
    assert.ok(retrieved, 'Investigation must be retrieved from repository');
    assert.strictEqual(retrieved.investigation_id, testId);
    assert.strictEqual(retrieved.target.identifier, 'https://example-persisted.test');
    assert.strictEqual(retrieved.evidence.length, 1);
    assert.strictEqual(retrieved.findings.length, 1);
  });

  test('reloads investigation from SQLite after memory cache is cleared (server restart simulation)', async () => {
    const session = createTestSession(testId);
    await saveInvestigation(session, 'test-operator-1');

    // 1. Simulate server shutdown / memory loss
    await clearMemoryCache();

    // 2. Simulate server boot initialization
    initPersistence();

    // 3. Retrieve investigation from SQLite
    const reloaded = await getInvestigation(testId, 'test-operator-1');
    assert.ok(reloaded, 'Investigation must be restored from SQLite database');
    assert.strictEqual(reloaded.investigation_id, testId);
    assert.strictEqual(reloaded.target.identifier, 'https://example-persisted.test');
    assert.strictEqual(reloaded.evidence.length, 1);
    assert.strictEqual(reloaded.findings.length, 1);
    assert.strictEqual(reloaded.findings[0].claim, 'Persisted session test claim');
  });

  test('generates valid export bundle from persisted session', async () => {
    const session = createTestSession(testId);
    await saveInvestigation(session, 'test-operator-1');

    const bundle = await getExportBundle(testId, 'test-operator-1');
    assert.ok(bundle, 'Export bundle must be generated');
    assert.strictEqual(bundle.bundle_version, '1.0.0');
    assert.strictEqual(bundle.investigation.investigation_id, testId);
    assert.ok(bundle.evidence_payloads[`ev_${testId}_01`]);
  });

  test('lists all persisted investigations across restarts', async () => {
    const session = createTestSession(testId);
    await saveInvestigation(session, 'test-operator-1');

    await clearMemoryCache();
    initPersistence();

    const list = await listInvestigations('test-operator-1');
    const found = list.find(i => i.investigation_id === testId);
    assert.ok(found, 'Persisted investigation must appear in listInvestigations()');
  });

  test('deletes investigation from both memory cache and SQLite', async () => {
    const session = createTestSession(testId);
    await saveInvestigation(session, 'test-operator-1');

    const deleted = await deleteInvestigation(testId, 'test-operator-1');
    assert.strictEqual(deleted, true);
    assert.strictEqual(await getInvestigation(testId, 'test-operator-1'), null, 'Session must not be found in cache or SQLite');
  });
});

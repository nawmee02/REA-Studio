import { test, describe, afterEach } from 'node:test';
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

  function createTestSession(id: string): InvestigationSession {
    return {
      investigation_id: id,
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
          finding_id: `fd_${id}_01`,
          claim: 'Persisted session test claim',
          category: 'server',
          classification: 'observation',
          confidence: 1.0,
          status: 'VERIFIED',
          evidence_ids: [`ev_${id}_01`],
          method: 'Direct test fixture'
        }
      ],
      unknowns: ['Unknown test parameter'],
      coverage: {
        stages_executed: 10,
        stages_total: 12,
        stages_skipped: 2,
        stages_failed: 0,
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

  afterEach(() => {
    deleteInvestigation(testId);
  });

  test('saves investigation session atomically into SQLite and verifies schema storage', () => {
    const session = createTestSession(testId);
    saveInvestigation(session);

    const dataDir = getPersistenceDir();
    const dbPath = path.join(dataDir, 'rea_studio.db');

    assert.ok(fs.existsSync(dbPath), `SQLite database must exist at ${dbPath}`);

    const retrieved = getInvestigation(testId);
    assert.ok(retrieved, 'Investigation must be retrieved from repository');
    assert.strictEqual(retrieved.investigation_id, testId);
    assert.strictEqual(retrieved.target.identifier, 'https://example-persisted.test');
    assert.strictEqual(retrieved.evidence.length, 1);
    assert.strictEqual(retrieved.findings.length, 1);
  });

  test('reloads investigation from SQLite after memory cache is cleared (server restart simulation)', () => {
    const session = createTestSession(testId);
    saveInvestigation(session);

    // 1. Simulate server shutdown / memory loss
    clearMemoryCache();

    // 2. Simulate server boot initialization
    initPersistence();

    // 3. Retrieve investigation from SQLite
    const reloaded = getInvestigation(testId);
    assert.ok(reloaded, 'Investigation must be restored from SQLite database');
    assert.strictEqual(reloaded.investigation_id, testId);
    assert.strictEqual(reloaded.target.identifier, 'https://example-persisted.test');
    assert.strictEqual(reloaded.evidence.length, 1);
    assert.strictEqual(reloaded.findings.length, 1);
    assert.strictEqual(reloaded.findings[0].claim, 'Persisted session test claim');
  });

  test('generates valid export bundle from persisted session', () => {
    const session = createTestSession(testId);
    saveInvestigation(session);

    const bundle = getExportBundle(testId);
    assert.ok(bundle, 'Export bundle must be generated');
    assert.strictEqual(bundle.bundle_version, '1.0.0');
    assert.strictEqual(bundle.investigation.investigation_id, testId);
    assert.ok(bundle.evidence_payloads[`ev_${testId}_01`]);
    assert.strictEqual(bundle.integrity.verification_status, 'hash-verified');
  });

  test('lists all persisted investigations across restarts', () => {
    const session = createTestSession(testId);
    saveInvestigation(session);

    clearMemoryCache();
    initPersistence();

    const list = listInvestigations();
    const found = list.find(i => i.investigation_id === testId);
    assert.ok(found, 'Persisted investigation must appear in listInvestigations()');
  });

  test('deletes investigation from both memory cache and SQLite', () => {
    const session = createTestSession(testId);
    saveInvestigation(session);

    const deleted = deleteInvestigation(testId);
    assert.strictEqual(deleted, true);
    assert.strictEqual(getInvestigation(testId), null, 'Session must not be found in cache or SQLite');
  });
});

import { test, describe } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import { runInvestigationPipeline } from '../src/server/pipeline';
import { replayInvestigationOffline } from '../src/server/replay';
import { deleteInvestigation } from '../src/server/persistence';

describe('Golden Pipeline Regression Tests', () => {
  const fixturesPath = path.resolve(process.cwd(), 'tests/fixtures/fixtures.json');
  const fixturesData = JSON.parse(fs.readFileSync(fixturesPath, 'utf8'));

  test('runs React SPA fixture through the full investigation pipeline', async () => {
    const fixture = fixturesData.fixtures.find((f: any) => f.name === 'react_spa_golden');
    assert.ok(fixture, 'React golden fixture must exist');

    // Run the fixture through the full end-to-end investigation pipeline
    const session = await runInvestigationPipeline({
      identifier: 'https://linear.app/dashboard',
      goal: 'Golden Pipeline React Regression Test',
      fixtureHtml: fixture.html,
      fixtureHeaders: {
        'content-type': 'text/html; charset=utf-8',
        'server': 'cloudflare',
        'x-content-type-options': 'nosniff'
      }
    });

    // 1. Verify target and lifecycle
    assert.strictEqual(session.status, 'COMPLETED');
    assert.strictEqual(session.target.identifier, 'https://linear.app/dashboard');

    // 2. Verify evidence ledger generation
    assert.ok(session.evidence.length >= 6, 'Pipeline must generate all standard evidence records');
    const targetEv = session.evidence.find(e => e.phase === 'target_resolution');
    const htmlEv = session.evidence.find(e => e.phase === 'html_dom_inspection');
    const scriptEv = session.evidence.find(e => e.phase === 'script_inventory');
    const techEv = session.evidence.find(e => e.phase === 'technology_detection');
    const epEv = session.evidence.find(e => e.phase === 'endpoint_extraction');

    assert.ok(targetEv, 'Must produce target_resolution evidence');
    assert.ok(htmlEv, 'Must produce html_dom_inspection evidence');
    assert.ok(scriptEv, 'Must produce script_inventory evidence');
    assert.ok(techEv, 'Must produce technology_detection evidence');
    assert.ok(epEv, 'Must produce endpoint_extraction evidence');

    // 3. Verify technology findings
    const reactFinding = session.findings.find(f => f.category === 'technology' && f.claim.includes('React'));
    assert.ok(reactFinding, 'Pipeline findings must include React');
    assert.strictEqual(reactFinding.status, 'CONFIRMED');
    assert.strictEqual(reactFinding.classification, 'observation');
    assert.strictEqual(reactFinding.confidence, 0.95);
    assert.ok(reactFinding.evidence_ids.includes(techEv!.evidence_id));

    // 4. Verify endpoint discovery
    const epFinding = session.findings.find(f => f.category === 'endpoint' && f.claim.includes('/api/v2/issues'));
    assert.ok(epFinding, 'Pipeline findings must include /api/v2/issues');
    assert.strictEqual(epFinding.status, 'DISCOVERED');
    assert.ok(epFinding.evidence_ids.includes(epEv!.evidence_id));

    // 5. Verify graph nodes and edges
    assert.ok(session.graph.nodes.some(n => n.type === 'target'));
    assert.ok(session.graph.nodes.some(n => n.type === 'script'));
    assert.ok(session.graph.nodes.some(n => n.type === 'endpoint'));
    assert.ok(session.graph.edges.some(e => e.relation === 'loads'));
    assert.ok(session.graph.edges.some(e => e.relation === 'discovers'));

    // 6. Verify cryptographic replay passes with 0 corruptions
    const replayReport = replayInvestigationOffline(session);
    assert.strictEqual(replayReport.reproducibility, 'DETERMINISTIC_OFFLINE');
    assert.strictEqual(replayReport.evidence_integrity.corrupted, 0);
    assert.strictEqual(replayReport.evidence_integrity.verified_hashes, session.evidence.length);
    assert.strictEqual(replayReport.manifest_intact, true);

    // Cleanup disk test fixture
    deleteInvestigation(session.investigation_id);
  });

  test('runs Lit and Custom Web Components fixture through the full investigation pipeline', async () => {
    const fixture = fixturesData.fixtures.find((f: any) => f.name === 'lit_web_components_golden');
    assert.ok(fixture, 'Lit golden fixture must exist');

    const session = await runInvestigationPipeline({
      identifier: 'https://example-components.dev/app',
      goal: 'Golden Pipeline Web Components Regression Test',
      fixtureHtml: fixture.html
    });

    assert.strictEqual(session.status, 'COMPLETED');

    // Verify detection of both Lit / Shadow DOM and Web Components
    const litFinding = session.findings.find(f => f.category === 'technology' && f.claim.includes('Lit / Shadow DOM'));
    assert.ok(litFinding, 'Pipeline findings must include Lit / Shadow DOM');
    assert.strictEqual(litFinding.status, 'CONFIRMED');

    const wcFinding = session.findings.find(f => f.category === 'technology' && f.claim.includes('Web Components'));
    assert.ok(wcFinding, 'Pipeline findings must include Web Components');
    assert.strictEqual(wcFinding.status, 'CONFIRMED');

    // Verify replay passes
    const replayReport = replayInvestigationOffline(session);
    assert.strictEqual(replayReport.evidence_integrity.corrupted, 0);
    assert.strictEqual(replayReport.manifest_intact, true);

    deleteInvestigation(session.investigation_id);
  });
});

import { test, describe } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';

describe('Golden Regression Fixtures', () => {
  const fixturesPath = path.resolve(process.cwd(), 'tests/fixtures/fixtures.json');
  const fixturesData = JSON.parse(fs.readFileSync(fixturesPath, 'utf8'));

  test('validates React SPA golden fixture', () => {
    const fixture = fixturesData.fixtures.find((f: any) => f.name === 'react_spa_golden');
    assert.ok(fixture);

    const hasReact = fixture.html.includes('data-reactroot');
    assert.strictEqual(hasReact, true);

    const endpointMatch = fixture.html.match(/\/api\/v2\/issues/);
    assert.ok(endpointMatch);

    const hasRootDiv = fixture.html.includes('id="root"');
    assert.strictEqual(hasRootDiv, fixture.expected.has_root);
  });

  test('validates Lit & Web Components golden fixture', () => {
    const fixture = fixturesData.fixtures.find((f: any) => f.name === 'lit_web_components_golden');
    assert.ok(fixture);

    const customEl = fixture.html.match(/<([a-z0-9]+-[a-z0-9-]+)/i)?.[1];
    assert.strictEqual(customEl, fixture.expected.custom_elements[0]);

    const isLit = fixture.html.includes('LitElement') && fixture.html.includes('attachShadow()');
    assert.strictEqual(isLit, true);
  });
});

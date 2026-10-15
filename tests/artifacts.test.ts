import { test, describe } from 'node:test';
import assert from 'node:assert';
import path from 'path';

describe('Artifact Lab & Static Code Deconstruction', () => {
  test('rejects path traversal in filename', () => {
    const maliciousNames = [
      '../../etc/passwd',
      '..\\..\\windows\\system32',
      '/var/run/secrets',
      'foo/../../bar.js'
    ];

    for (const name of maliciousNames) {
      const isTraversal = name.includes('..') || name.startsWith('/') || name.includes('\\');
      assert.strictEqual(isTraversal, true, `Should detect path traversal in "${name}"`);
    }
  });

  test('extracts dependencies and export identifiers from synthetic JS fixture', () => {
    const code = `
      import React, { useState } from 'react';
      import { motion } from 'framer-motion';
      const lodash = require('lodash');

      export const DEFAULT_THEME = 'dark';
      export function calculateMetric(a, b) {
        return a + b;
      }
      export default class EngineController {}
    `;

    // Extract imports
    const importRegex = /(?:import\s+(?:[\w*\s{},]*\s+from\s+)?['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))/g;
    const dependencies = new Set<string>();
    let m;
    while ((m = importRegex.exec(code)) !== null) {
      dependencies.add(m[1] || m[2]);
    }

    assert.ok(dependencies.has('react'));
    assert.ok(dependencies.has('framer-motion'));
    assert.ok(dependencies.has('lodash'));

    // Extract exports
    const exportRegex = /export\s+(?:default\s+)?(?:class|function|const|let|var)\s+([a-zA-Z0-9_$]+)/g;
    const exportsList = new Set<string>();
    while ((m = exportRegex.exec(code)) !== null) {
      exportsList.add(m[1]);
    }

    assert.ok(exportsList.has('DEFAULT_THEME'));
    assert.ok(exportsList.has('calculateMetric'));
    assert.ok(exportsList.has('EngineController'));
  });
});

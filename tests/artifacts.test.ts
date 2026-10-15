import { test, describe, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'http';
import { createInvestigationApp } from '../src/server/app';

describe('Artifact Lab API & Implementation Tests', () => {
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

  test('POST /api/analyze-artifact rejects path traversal in filenames via API', async () => {
    const maliciousFilenames = [
      '../../etc/passwd',
      '..\\..\\windows\\system32',
      '/var/run/secrets.js',
      'foo/../../bar.js'
    ];

    for (const filename of maliciousFilenames) {
      const res = await fetch(`${baseUrl}/api/analyze-artifact`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code: 'console.log("safe code");',
          filename,
          type: 'javascript'
        })
      });

      assert.strictEqual(res.status, 400, `API should return HTTP 400 for traversal path "${filename}"`);
      const body = await res.json() as any;
      assert.ok(
        body.error && body.error.includes('Path traversal characters detected'),
        `Error response should state traversal was detected, got: ${JSON.stringify(body)}`
      );
    }
  });

  test('POST /api/analyze-artifact rejects oversized payloads', async () => {
    // 11MB payload
    const oversized = 'x'.repeat(11 * 1024 * 1024);
    const res = await fetch(`${baseUrl}/api/analyze-artifact`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: oversized,
        filename: 'bundle.js',
        type: 'javascript'
      })
    });

    // Express json parser limit 10MB will return 413, or analyzer returns 400
    assert.ok(res.status === 400 || res.status === 413, `Expected 400 or 413 for oversized code, got: ${res.status}`);
  });

  test('POST /api/analyze-artifact parses dependencies, exports, and endpoints via API', async () => {
    const code = `
      import React from 'react';
      import { motion } from 'framer-motion';
      const utils = require('./utils');

      export const CONFIG = { api: '/api/v2/telemetry' };
      export function initEngine() {
        return fetch('/api/v2/handshake');
      }
      export default class CoreController {}
    `;

    const res = await fetch(`${baseUrl}/api/analyze-artifact`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code,
        filename: 'app.bundle.js',
        type: 'javascript'
      })
    });

    assert.strictEqual(res.status, 200);
    const body = await res.json() as any;

    assert.strictEqual(body.artifact.filename, 'app.bundle.js');
    assert.strictEqual(body.artifact.sha256.length, 64);

    assert.ok(body.analysis.dependencies.includes('react'));
    assert.ok(body.analysis.dependencies.includes('framer-motion'));
    assert.ok(body.analysis.dependencies.includes('./utils'));

    assert.ok(body.analysis.exports.includes('CONFIG'));
    assert.ok(body.analysis.exports.includes('initEngine'));
    assert.ok(body.analysis.exports.includes('CoreController'));

    assert.ok(body.analysis.endpoints.includes('/api/v2/telemetry'));
    assert.ok(body.analysis.endpoints.includes('/api/v2/handshake'));
  });
});

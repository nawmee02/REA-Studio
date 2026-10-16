import { test, describe, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'http';
import { createInvestigationApp } from '../src/server/app';

describe('Artifact Lab API & Implementation Tests', () => {
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
        headers: testAuthHeaders,
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
      headers: testAuthHeaders,
      body: JSON.stringify({
        code: oversized,
        filename: 'huge.js'
      })
    });

    // Express json limit returns 413
    assert.strictEqual(res.status, 413, 'Oversized payload must be rejected with 413 Payload Too Large');
  });

  test('POST /api/analyze-artifact extracts dependencies, endpoints, and telemetry calls from code', async () => {
    const sampleBundle = `
      import { initializeApp } from "firebase/app";
      import axios from "axios";

      export const TELEMETRY_URL = "/api/v2/metrics";
      const GATEWAY = "wss://realtime.company.internal/socket";

      export async function sendTelemetry(metric) {
        return axios.post(TELEMETRY_URL, { metric });
      }
    `;

    const res = await fetch(`${baseUrl}/api/analyze-artifact`, {
      method: 'POST',
      headers: testAuthHeaders,
      body: JSON.stringify({
        code: sampleBundle,
        filename: 'app.bundle.js',
        type: 'javascript'
      })
    });

    assert.strictEqual(res.status, 200);
    const body = await res.json() as any;

    assert.ok(body.analysis && body.analysis.dependencies, 'Dependencies must be extracted');
    const depNames = body.analysis.dependencies;
    assert.ok(depNames.includes('firebase/app'), 'Must detect firebase/app import');
    assert.ok(depNames.includes('axios'), 'Must detect axios import');

    assert.ok(body.analysis.endpoints, 'Endpoints must be extracted');
    const epPaths = body.analysis.endpoints;
    assert.ok(epPaths.includes('/api/v2/metrics'), 'Must extract /api/v2/metrics endpoint');

    assert.ok(body.artifact, 'Artifact stats must be computed');
    assert.strictEqual(body.artifact.filename, 'app.bundle.js');
    assert.ok(body.artifact.sha256, 'Digest must be present');
  });
});

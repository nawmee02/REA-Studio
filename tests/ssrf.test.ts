import { test, describe } from 'node:test';
import assert from 'node:assert';
import { isRestrictedIp, validateUrlStructure } from '../src/server/networkGuard';

describe('SSRF & IP Boundary Enforcement', () => {
  test('blocks IPv4 loopback addresses', () => {
    assert.strictEqual(isRestrictedIp('127.0.0.1'), true);
    assert.strictEqual(isRestrictedIp('127.0.0.2'), true);
    assert.strictEqual(isRestrictedIp('127.255.255.255'), true);
    assert.strictEqual(isRestrictedIp('0.0.0.0'), true);
  });

  test('blocks RFC 1918 private subnets', () => {
    assert.strictEqual(isRestrictedIp('10.0.0.1'), true);
    assert.strictEqual(isRestrictedIp('10.254.0.1'), true);
    assert.strictEqual(isRestrictedIp('172.16.0.1'), true);
    assert.strictEqual(isRestrictedIp('172.24.1.1'), true);
    assert.strictEqual(isRestrictedIp('172.31.255.255'), true);
    assert.strictEqual(isRestrictedIp('192.168.0.1'), true);
    assert.strictEqual(isRestrictedIp('192.168.1.100'), true);
  });

  test('blocks Cloud Metadata and Link-Local subnets (169.254.0.0/16)', () => {
    assert.strictEqual(isRestrictedIp('169.254.169.254'), true);
    assert.strictEqual(isRestrictedIp('169.254.0.1'), true);
    assert.strictEqual(isRestrictedIp('169.254.255.254'), true);
  });

  test('blocks Carrier-Grade NAT (100.64.0.0/10)', () => {
    assert.strictEqual(isRestrictedIp('100.64.0.1'), true);
    assert.strictEqual(isRestrictedIp('100.100.50.1'), true);
    assert.strictEqual(isRestrictedIp('100.127.255.254'), true);
  });

  test('blocks IPv6 loopback, ULA, and Link-Local', () => {
    assert.strictEqual(isRestrictedIp('::1'), true);
    assert.strictEqual(isRestrictedIp('::'), true);
    assert.strictEqual(isRestrictedIp('fc00::1'), true);
    assert.strictEqual(isRestrictedIp('fd12:3456:789a::1'), true);
    assert.strictEqual(isRestrictedIp('fe80::1'), true);
  });

  test('blocks IPv4-mapped IPv6 private addresses (anti-bypass)', () => {
    assert.strictEqual(isRestrictedIp('::ffff:127.0.0.1'), true);
    assert.strictEqual(isRestrictedIp('::ffff:10.0.0.1'), true);
    assert.strictEqual(isRestrictedIp('::ffff:169.254.169.254'), true);
    assert.strictEqual(isRestrictedIp('::ffff:192.168.1.1'), true);
  });

  test('permits legitimate public internet IPv4 and IPv6 addresses', () => {
    assert.strictEqual(isRestrictedIp('8.8.8.8'), false);
    assert.strictEqual(isRestrictedIp('1.1.1.1'), false);
    assert.strictEqual(isRestrictedIp('93.184.216.34'), false);
    assert.strictEqual(isRestrictedIp('2606:4700:4700::1111'), false);
  });

  test('validates URL protocols strictly', () => {
    assert.throws(() => validateUrlStructure('file:///etc/passwd'), /Forbidden protocol/);
    assert.throws(() => validateUrlStructure('ftp://ftp.example.com'), /Forbidden protocol/);
    assert.throws(() => validateUrlStructure('gopher://gopher.example.com'), /Forbidden protocol/);
    assert.throws(() => validateUrlStructure('javascript:alert(1)'), /Forbidden protocol/);
    assert.throws(() => validateUrlStructure('data:text/html,hello'), /Forbidden protocol/);
  });

  test('blocks prohibited hostnames and metadata endpoints', () => {
    assert.throws(() => validateUrlStructure('http://localhost:3000'), /Prohibited target host/);
    assert.throws(() => validateUrlStructure('http://app.localhost:8080'), /Prohibited target host/);
    assert.throws(() => validateUrlStructure('http://metadata.google.internal'), /Prohibited target host/);
    assert.throws(() => validateUrlStructure('http://169.254.169.254/latest/meta-data/'), /Prohibited/);
  });

  test('accepts clean standard public URLs', () => {
    const u1 = validateUrlStructure('https://linear.app');
    assert.strictEqual(u1.hostname, 'linear.app');

    const u2 = validateUrlStructure('http://example.com/test?query=1');
    assert.strictEqual(u2.hostname, 'example.com');
  });

  test('rejects target when initial origin violates expectedOrigin', async () => {
    const { safeFetch } = await import('../src/server/networkGuard');
    await assert.rejects(
      async () => {
        await safeFetch('https://another-domain.com/path', {
          expectedOrigin: 'https://example.com:443'
        });
      },
      /Scope violation: Target origin "https:\/\/another-domain\.com:443" does not match authorized origin "https:\/\/example\.com:443"/
    );
  });
});

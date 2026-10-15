import dns from 'dns';
import net from 'net';
import http from 'http';
import https from 'https';
import { promisify } from 'util';

const dnsLookup = promisify(dns.lookup);
const dnsResolve4 = promisify(dns.resolve4);
const dnsResolve6 = promisify(dns.resolve6);

export interface SafeFetchOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string | Buffer;
  timeoutMs?: number;
  maxBytes?: number;
  maxRedirects?: number;
  expectedOrigin?: string; // If supplied, enforces strict origin matching across initial URL and all redirect hops
}

/**
 * Returns the normalized origin string: scheme://hostname:effectivePort
 */
export function getNormalizedOrigin(rawUrl: string | URL): string {
  const parsed = typeof rawUrl === 'string' ? new URL(rawUrl) : rawUrl;
  const isHttps = parsed.protocol === 'https:';
  const effectivePort = parsed.port || (isHttps ? '443' : '80');
  return `${parsed.protocol}//${parsed.hostname.toLowerCase()}:${effectivePort}`;
}

export interface SafeFetchResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  finalUrl: string;
  resolvedIp: string;
  redirectsFollowed: number;
}

/**
 * Checks if an IPv4 address is in a private, loopback, or reserved subnet.
 */
function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map(n => parseInt(n, 10));
  if (parts.length !== 4 || parts.some(isNaN)) return true;

  const [a, b, c, d] = parts;

  // 0.0.0.0/8 (Current network)
  if (a === 0) return true;

  // 10.0.0.0/8 (Private)
  if (a === 10) return true;

  // 100.64.0.0/10 (Shared address space / Carrier-grade NAT)
  if (a === 100 && b >= 64 && b <= 127) return true;

  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;

  // 169.254.0.0/16 (Link-local & Cloud Metadata)
  if (a === 169 && b === 254) return true;

  // 172.16.0.0/12 (Private)
  if (a === 172 && b >= 16 && b <= 31) return true;

  // 192.0.0.0/24 (IETF Protocol Assignments)
  if (a === 192 && b === 0 && c === 0) return true;

  // 192.0.2.0/24 (TEST-NET-1 documentation)
  if (a === 192 && b === 0 && c === 2) return true;

  // 192.168.0.0/16 (Private)
  if (a === 192 && b === 168) return true;

  // 198.18.0.0/15 (Benchmarking)
  if (a === 198 && (b === 18 || b === 19)) return true;

  // 198.51.100.0/24 (TEST-NET-2 documentation)
  if (a === 198 && b === 51 && c === 100) return true;

  // 203.0.113.0/24 (TEST-NET-3 documentation)
  if (a === 203 && b === 0 && c === 113) return true;

  // 224.0.0.0/4 (Multicast)
  if (a >= 224 && a <= 239) return true;

  // 240.0.0.0/4 (Reserved)
  if (a >= 240) return true;

  // 255.255.255.255 (Broadcast)
  if (a === 255 && b === 255 && c === 255 && d === 255) return true;

  return false;
}

/**
 * Checks if an IPv6 address is in a private, loopback, or reserved subnet.
 */
function isPrivateIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase();

  // Loopback (::1) and Unspecified (::)
  if (normalized === '::1' || normalized === '::') return true;

  // IPv4-mapped IPv6 (::ffff:x.x.x.x or ::ffff:7f00:1)
  const mappedV4Match = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mappedV4Match) {
    return isPrivateIPv4(mappedV4Match[1]);
  }

  // IPv4-compatible IPv6 (deprecated ::x.x.x.x)
  const compatV4Match = normalized.match(/^::(\d+\.\d+\.\d+\.\d+)$/i);
  if (compatV4Match) {
    return isPrivateIPv4(compatV4Match[1]);
  }

  // Unique Local Address (ULA fc00::/7 -> fc00 to fdff)
  if (/^f[cd][0-9a-f]{2}:/i.test(normalized)) return true;

  // Link-Local (fe80::/10 -> fe80 to febf)
  if (/^fe[89ab][0-9a-f]{1}:/i.test(normalized)) return true;

  // Site-Local (fec0::/10, deprecated)
  if (/^fe[c-f][0-9a-f]{1}:/i.test(normalized)) return true;

  // Documentation (2001:db8::/32)
  if (/^2001:0?db8:/i.test(normalized)) return true;

  // Multicast (ff00::/8)
  if (/^ff[0-9a-f]{2}:/i.test(normalized)) return true;

  return false;
}

/**
 * Universal IP safety validator.
 */
export function isRestrictedIp(ip: string): boolean {
  const version = net.isIP(ip);
  if (version === 4) return isPrivateIPv4(ip);
  if (version === 6) return isPrivateIPv6(ip);
  return true; // Not a valid standard IP -> treat as restricted
}

/**
 * Validates and normalizes target URL against protocol and metadata restrictions.
 */
export function validateUrlStructure(rawUrl: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error('Malformed URL format. Expected standard http:// or https://');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Forbidden protocol: "${parsed.protocol}". Only HTTP and HTTPS are permitted.`);
  }

  const hostname = parsed.hostname.toLowerCase();

  // Blacklisted hostnames & cloud metadata aliases
  const prohibitedHosts = [
    'localhost',
    'metadata.google.internal',
    'metadata',
    'instance-data',
    '169.254.169.254'
  ];

  if (prohibitedHosts.includes(hostname) || hostname.endsWith('.localhost')) {
    throw new Error(`Prohibited target host "${hostname}": resolves to local loopback or cloud metadata.`);
  }

  // Check if hostname is directly an IP literal
  if (net.isIP(hostname)) {
    if (isRestrictedIp(hostname)) {
      throw new Error(`Prohibited target IP "${hostname}": falls within a private or reserved subnet.`);
    }
  }

  return parsed;
}

/**
 * Resolves a hostname to safe IPs and throws if any IP is restricted.
 */
export async function resolveSafeIp(hostname: string): Promise<string> {
  if (net.isIP(hostname)) {
    if (isRestrictedIp(hostname)) {
      throw new Error(`Prohibited IP address: ${hostname}`);
    }
    return hostname;
  }

  let addresses: dns.LookupAddress[];
  try {
    addresses = await dnsLookup(hostname, { all: true });
  } catch (err: any) {
    throw new Error(`DNS resolution failed for host "${hostname}": ${err.message}`);
  }

  if (!addresses || addresses.length === 0) {
    throw new Error(`No DNS records found for host "${hostname}"`);
  }

  for (const addr of addresses) {
    if (isRestrictedIp(addr.address)) {
      throw new Error(`SSRF Block: Host "${hostname}" resolves to restricted address "${addr.address}".`);
    }
  }

  return addresses[0].address;
}

/**
 * Executes a network fetch with:
 * - Pre-connection DNS validation (anti-DNS rebinding)
 * - Safe manual redirect loop with per-hop IP and protocol checks
 * - Maximum byte buffer size protection (anti-decompression bomb)
 * - Timeout handling
 */
export async function safeFetch(targetUrl: string, options: SafeFetchOptions = {}): Promise<SafeFetchResponse> {
  const {
    method = 'GET',
    headers = {},
    body,
    timeoutMs = 10000,
    maxBytes = 5 * 1024 * 1024, // 5 MB
    maxRedirects = 5,
    expectedOrigin
  } = options;

  let currentUrl = targetUrl;
  let redirectsFollowed = 0;

  if (expectedOrigin) {
    const initialOrigin = getNormalizedOrigin(currentUrl);
    if (initialOrigin !== expectedOrigin) {
      throw new Error(`Scope violation: Target origin "${initialOrigin}" does not match authorized origin "${expectedOrigin}".`);
    }
  }

  while (redirectsFollowed <= maxRedirects) {
    const parsed = validateUrlStructure(currentUrl);
    if (expectedOrigin) {
      const hopOrigin = getNormalizedOrigin(parsed);
      if (hopOrigin !== expectedOrigin) {
        throw new Error(`Cross-origin redirect violation: Redirected to origin "${hopOrigin}" which differs from authorized origin "${expectedOrigin}".`);
      }
    }
    const resolvedIp = await resolveSafeIp(parsed.hostname);

    const isHttps = parsed.protocol === 'https:';
    const port = parsed.port ? parseInt(parsed.port, 10) : (isHttps ? 443 : 80);

    const response = await new Promise<SafeFetchResponse>((resolve, reject) => {
      let isTimedOut = false;
      const timer = setTimeout(() => {
        isTimedOut = true;
        req.destroy(new Error(`Connection timed out after ${timeoutMs}ms.`));
      }, timeoutMs);

      const requestOptions: http.RequestOptions = {
        method,
        host: resolvedIp, // Connect directly to verified IP to prevent DNS rebinding TOCTOU
        port,
        path: parsed.pathname + parsed.search,
        headers: {
          ...headers,
          'Host': parsed.hostname, // Preserve standard virtual host header
          'User-Agent': headers['User-Agent'] || 'Mozilla/5.0 REA-Engine/6.5.0 (Security-Hardened)',
          'Accept': headers['Accept'] || '*/*',
          'Connection': 'close'
        },
        timeout: timeoutMs
      };

      if (isHttps) {
        // Enforce Server Name Indication (SNI) for TLS
        (requestOptions as https.RequestOptions).servername = parsed.hostname;
      }

      const client = isHttps ? https : http;
      const req = client.request(requestOptions, (res) => {
        const resHeaders: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (v) resHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
        }

        // Handle Redirects manually to validate each target hop
        const statusCode = res.statusCode || 0;
        if ([301, 302, 303, 307, 308].includes(statusCode)) {
          const location = res.headers.location;
          if (!location) {
            clearTimeout(timer);
            return reject(new Error(`Redirect HTTP ${statusCode} without Location header.`));
          }

          // Resolve relative redirect against current URL
          let redirectUrl: string;
          try {
            redirectUrl = new URL(location, currentUrl).toString();
          } catch {
            clearTimeout(timer);
            return reject(new Error(`Malformed redirect Location: "${location}".`));
          }

          clearTimeout(timer);
          res.resume(); // Discard body
          return resolve({
            status: statusCode,
            statusText: res.statusMessage || 'Redirect',
            headers: resHeaders,
            body: redirectUrl, // Pass redirect URL
            finalUrl: redirectUrl,
            resolvedIp,
            redirectsFollowed
          });
        }

        // Bounded Body Reader
        const chunks: Buffer[] = [];
        let totalBytes = 0;

        res.on('data', (chunk: Buffer) => {
          totalBytes += chunk.length;
          if (totalBytes > maxBytes) {
            clearTimeout(timer);
            req.destroy(new Error(`Response exceeded maximum size limit of ${maxBytes} bytes.`));
            return;
          }
          chunks.push(chunk);
        });

        res.on('end', () => {
          clearTimeout(timer);
          const fullBody = Buffer.concat(chunks).toString('utf8');
          resolve({
            status: statusCode,
            statusText: res.statusMessage || '',
            headers: resHeaders,
            body: fullBody,
            finalUrl: currentUrl,
            resolvedIp,
            redirectsFollowed
          });
        });

        res.on('error', (err) => {
          clearTimeout(timer);
          reject(err);
        });
      });

      req.on('error', (err) => {
        clearTimeout(timer);
        if (isTimedOut) {
          reject(new Error(`Request timed out after ${timeoutMs}ms.`));
        } else {
          reject(err);
        }
      });

      if (body) {
        req.write(body);
      }
      req.end();
    });

    // Check if response was a redirect
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      redirectsFollowed += 1;
      if (redirectsFollowed > maxRedirects) {
        throw new Error(`Exceeded maximum redirect limit (${maxRedirects}).`);
      }
      currentUrl = response.body; // response.body contains the target redirectUrl
      continue;
    }

    return response;
  }

  throw new Error(`Exceeded maximum redirect limit (${maxRedirects}).`);
}

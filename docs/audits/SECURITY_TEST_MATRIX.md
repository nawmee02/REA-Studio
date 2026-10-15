# REA Studio — Security Test Matrix & Threat Validation

**Audit Date**: 2026-10-15  
**Component**: Network Guard & Scanner Transport (`src/server/networkGuard.ts`)

---

## Threat Scenarios & Test Coverage

| Test ID | Threat Scenario | Attack Vector | Expected Defense | Test Status |
| :--- | :--- | :--- | :--- | :--- |
| **SSRF-01** | Loopback probing | Target `127.0.0.1`, `127.0.0.2`, `127.255.255.255` | Blocked by `isRestrictedIp` IPv4 loopback mask (`127.0.0.0/8`) | **PASS** |
| **SSRF-02** | Local zero network | Target `0.0.0.0` | Blocked by `isRestrictedIp` (`0.0.0.0/8`) | **PASS** |
| **SSRF-03** | RFC 1918 Private LAN | Target `10.0.0.1`, `172.16.0.1`, `192.168.1.1` | Blocked by RFC 1918 subnet validation | **PASS** |
| **SSRF-04** | Cloud Metadata Theft | Target `169.254.169.254`, `metadata.google.internal` | Blocked by both IP check (`169.254.0.0/16`) and hostname blacklist | **PASS** |
| **SSRF-05** | IPv4-Mapped IPv6 Bypass | Target `::ffff:127.0.0.1`, `::ffff:169.254.169.254` | Extracted and validated as mapped IPv4 address | **PASS** |
| **SSRF-06** | Carrier-Grade NAT (CGNAT) | Target `100.64.0.1`, `100.100.50.1` | Blocked by `100.64.0.0/10` bitmask check | **PASS** |
| **SSRF-07** | IPv6 ULA & Link-Local | Target `fc00::1`, `fd12:...`, `fe80::1` | Blocked by IPv6 prefix checks (`fc00::/7`, `fe80::/10`) | **PASS** |
| **SSRF-08** | Protocol Smuggling | Target `file:///etc/passwd`, `gopher://`, `ftp://` | Throws `Forbidden protocol` immediately in `validateUrlStructure` | **PASS** |
| **SSRF-09** | Hostname Loopback Aliases | Target `localhost`, `app.localhost:8080` | Rejected by hostname inspection | **PASS** |
| **SSRF-10** | DNS Rebinding (TOCTOU) | Domain changes DNS IP between check and fetch | Prevented via direct IP connection pinning with virtual `Host` header | **PASS** |
| **SSRF-11** | Open Redirect SSRF | External 302 redirecting to `169.254.169.254` | Manual redirect follower re-validates each hop through `resolveSafeIp` | **PASS** |
| **SSRF-12** | Verification Host Escape | Probe `/api/verify-endpoint` with unrelated domain | Rejected with `403 Scope violation: host does not match target` | **PASS** |
| **TRAV-01** | Path Traversal in Artifact | Upload filename `../../etc/passwd` | Rejected by `path.basename` and traversal check | **PASS** |
| **BOMB-01** | Response Memory Bomb | Target returning > 5 MB payload stream | Connection terminated once byte threshold is exceeded | **PASS** |
| **TIME-01** | Slowloris / Hung Socket | Target hanging connection without data | Aborted strictly at 10,000ms timeout | **PASS** |

---

## Test Execution Command

Run the complete security suite locally with:

```bash
npm test
```
All 15 security and truth-model test cases execute in ~950ms under the Node.js test runner.

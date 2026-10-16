# REA Studio (Reverse Engineer Anything Studio)

REA Studio is a reproducible reverse-engineering platform built on the principles of evidence provenance, cryptographic reproducibility, strict boundary isolation, and secure multi-tenant cloud persistence.

Rather than acting as an opaque guessing tool, REA Studio records verifiable evidence records into a tamper-evident ledger, separates factual observations from derived inferences, and explicitly documents residual unknowns.

---

## Architecture Overview (Phase 4: Firebase Auth & Cloud Firestore)

```text
                         ┌──────────────────────┐
                         │      REA Studio      │
                         │   Web UI & Client    │
                         └──────────┬───────────┘
                                    │ (Firebase Auth ID Token)
                                    ▼
                         ┌──────────────────────┐
                         │ Express API Gateway  │
                         │ (requireAuth Guard)  │
                         └──────────┬───────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
               Reconnaissance  Artifact Lab   Verification Engine
                    │               │               │
                    └───────────────┼───────────────┘
                                    │
                        Evidence & Findings Ledger
                                    │
                                    ▼
                   ┌─────────────────────────────────┐
                   │  Investigation Repository Layer  │
                   └────────────────┬────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
                    ▼                               ▼
       Cloud Firestore (Production)      SQLite Adapter (Local Dev/Test)
       - investigations/{id}             - data/rea_studio.db (git-ignored)
       - evidence subcollections         - Deterministic isolated tests
       - findings subcollections
       - graph subcollections
```

---

## Authentication & Authorization Model

1. **Client Identity**: Operators sign in using Firebase Authentication (Email & Password). Public self-registration is disabled in the UI; accounts are provisioned by project administrators.
2. **Server-Side Token Verification (`src/server/authMiddleware.ts`)**:
   - Every protected API route enforces `Authorization: Bearer <Firebase ID Token>`.
   - Verified cryptographically via the `firebase-admin` Auth SDK with revocation checks (`checkRevoked: true`).
   - Rejects missing, expired, revoked, or forged tokens with HTTP 401.
3. **Allowlist Enforcement (`FIREBASE_ADMIN_UIDS`)**:
   - When `FIREBASE_ADMIN_UIDS` is configured, only UIDs listed in the server-side environment variable are authorized to operate the Studio (unlisted UIDs return HTTP 403 Forbidden).
   - Client-supplied identity fields (`uid`, `role`, `isAdmin`) are never trusted.
4. **Multi-Tenant Ownership & Isolation**:
   - Every investigation document and subcollection record is tagged with the verified `owner_uid`.
   - Queries (`list`, `getById`, `delete`, `export`, and `verify-endpoint`) strictly enforce requester UID isolation. Users cannot view, modify, or export investigations owned by other operators.
   - Bundle import overrides client metadata with the verified token UID.

---

## Storage Backends: Cloud Firestore vs. SQLite

- **Production Mode (`FIREBASE_STORAGE_BACKEND=firestore`)**:
  - Normalized document model avoiding document size limits:
    - Root: `investigations/{investigationId}` (manifest, coverage, lifecycle, target, ownerUid)
    - Subcollection: `investigations/{investigationId}/evidence/{evidenceId}`
    - Subcollection: `investigations/{investigationId}/findings/{findingId}`
    - Subcollection: `investigations/{investigationId}/graph/main`
  - Atomic batch writes via `db.batch().commit()`.
  - **Fail-Fast Safety**: The application will never silently fall back to SQLite when Firestore is configured. If Firestore initialization fails, the server fails fast with a clear error.
- **Local Dev & Test Mode (`FIREBASE_STORAGE_BACKEND=sqlite`)**:
  - Uses `node:sqlite` in-process database with migration tracking.
  - Automatically enabled for deterministic offline testing suites.
  - SQLite files (`*.db`, `*.sqlite`, `data/`) are ignored by version control.

---

## Firestore Security Rules (`firestore.rules`)

REA Studio uses a **server-authoritative security model**. All persistence, queries, mutations, and active verification probes execute exclusively through the authenticated Express API and Firebase Admin SDK.

Direct client-side SDK reads and writes are denied by default:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if false;
    }
  }
}
```

---

## Environment Configuration

Copy `.env.example` to `.env` and configure your settings:

```env
# Client-side settings (exposed to Vite)
VITE_FIREBASE_API_KEY="AIzaSy..."
VITE_FIREBASE_AUTH_DOMAIN="ai-studio-applet-webapp-8d0c9.firebaseapp.com"
VITE_FIREBASE_PROJECT_ID="ai-studio-applet-webapp-8d0c9"
VITE_FIREBASE_APP_ID="1:176038363707:web:0ccccd2358c0c9db8ed21e"

# Server-side Firebase Admin & Persistence settings
FIREBASE_PROJECT_ID="ai-studio-applet-webapp-8d0c9"
FIREBASE_DATABASE_ID="ai-studio-reastudio-63bdf93b-3367-40fd-8f0f-585fd2c4f1c6"
FIREBASE_STORAGE_BACKEND="firestore" # "firestore" for production; "sqlite" for local dev/testing
FIREBASE_ADMIN_UIDS="operator-uid-1,operator-uid-2"
```

### Initial Setup in Firebase Console

1. **Authentication**: Enable **Email/Password** provider in Firebase Console under Authentication → Sign-in method.
2. **Users**: Create your initial administrator user under Authentication → Users.
3. **Allowlist**: Copy the created User UID and add it to `FIREBASE_ADMIN_UIDS` in your server environment.
4. **Firestore**: The database `ai-studio-reastudio-63bdf93b-3367-40fd-8f0f-585fd2c4f1c6` has been provisioned in region `asia-southeast1`.

---

## Development & Testing

### Installation

```bash
bun install --frozen-lockfile
```

### Running Dev Server

```bash
npm run dev
```

The dev server starts on `http://localhost:3000`.

### Running Automated Test Suite

```bash
npm test
```

The test suite runs 58 tests across 9 test suites:
- `auth_and_ownership.test.ts` (Authentication, allowlist, multi-tenant isolation, spoofing protection)
- `persistence.test.ts` (Atomic session persistence, server restart recovery, bundle generation)
- `verification.test.ts` (Origin normalization, candidate validation, safe HTTP methods)
- `artifacts.test.ts` (Path traversal prevention, AST extraction, payload limits)
- `replay.test.ts` (Cryptographic digest recomputation, manifest verification, tamper detection)
- `lifecycle.test.ts` (Target capability registry, stage accounting, failure preservation)
- `golden.test.ts` (End-to-end regression fixtures)
- `evidence.test.ts` (Evidence canonical digests)
- `ssrf.test.ts` (IPv4/IPv6 private subnets, cloud metadata, connection pinning)

### Production Build & Lint

```bash
npm run lint
npm run build
```

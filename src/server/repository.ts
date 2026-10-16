import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { DatabaseSync } from 'node:sqlite';
import { 
  InvestigationSession, 
  EvidenceRecord, 
  FindingRecord, 
  InvestigationExportBundle 
} from '../types/investigation';
import { canonicalJsonStringify, sha256 } from './replay';
import { FirestoreInvestigationRepository } from './firestoreRepository';
import { resolveServerConfig } from './firebaseAdmin';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const DB_PATH = path.join(DATA_DIR, 'rea_studio.db');

export interface InvestigationRepository {
  save(session: InvestigationSession, ownerUid: string): Promise<void>;
  getById(id: string, requesterUid?: string): Promise<InvestigationSession | null>;
  list(requesterUid?: string): Promise<InvestigationSession[]>;
  delete(id: string, requesterUid?: string): Promise<boolean>;
  clearCache(): Promise<void>;
  getExportBundle(id: string, requesterUid?: string): Promise<InvestigationExportBundle | null>;
  importExportBundle(bundle: InvestigationExportBundle, ownerUid: string): Promise<InvestigationSession>;
  close?(): Promise<void> | void;
}

export class SqliteInvestigationRepository implements InvestigationRepository {
  private db: DatabaseSync;
  private cache: Map<string, InvestigationSession> = new Map();

  constructor(customDbPath?: string) {
    const targetPath = customDbPath || DB_PATH;
    const parentDir = path.dirname(targetPath);
    if (!fs.existsSync(parentDir)) {
      fs.mkdirSync(parentDir, { recursive: true });
    }

    this.db = new DatabaseSync(targetPath);
    this.runMigrations();
    this.preloadCache();
  }

  private runMigrations(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL,
        description TEXT NOT NULL
      );
    `);

    const rows = this.db.prepare('SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1').all() as any[];
    const currentVersion = rows.length > 0 ? (rows[0].version as number) : 0;

    if (currentVersion < 1) {
      this.db.exec('BEGIN');
      try {
        this.db.exec(`
          CREATE TABLE IF NOT EXISTS investigations (
            investigation_id TEXT PRIMARY KEY,
            owner_uid TEXT,
            target_type TEXT NOT NULL,
            target_identifier TEXT NOT NULL,
            target_identity_hash TEXT NOT NULL,
            status TEXT NOT NULL,
            goal TEXT NOT NULL,
            stages_executed INTEGER NOT NULL,
            stages_total INTEGER NOT NULL,
            stages_skipped INTEGER NOT NULL DEFAULT 0,
            stages_failed INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            manifest_json TEXT NOT NULL,
            graph_json TEXT NOT NULL,
            unknowns_json TEXT NOT NULL,
            timeline_json TEXT NOT NULL,
            toolchain_json TEXT NOT NULL,
            coverage_json TEXT NOT NULL,
            session_json TEXT NOT NULL
          );

          CREATE TABLE IF NOT EXISTS evidence_records (
            evidence_id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            type TEXT NOT NULL,
            phase TEXT NOT NULL,
            authority TEXT NOT NULL,
            source_kind TEXT NOT NULL,
            source_location TEXT NOT NULL,
            source_sha256 TEXT NOT NULL,
            canonical_digest TEXT NOT NULL,
            content_json TEXT NOT NULL,
            limitations_json TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            tool TEXT NOT NULL,
            parent_evidence_ids_json TEXT,
            FOREIGN KEY (investigation_id) REFERENCES investigations (investigation_id) ON DELETE CASCADE
          );

          CREATE TABLE IF NOT EXISTS findings (
            finding_id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            claim TEXT NOT NULL,
            category TEXT NOT NULL,
            classification TEXT NOT NULL,
            confidence REAL NOT NULL,
            status TEXT NOT NULL,
            method TEXT NOT NULL,
            evidence_ids_json TEXT NOT NULL,
            supports_json TEXT,
            details_json TEXT,
            FOREIGN KEY (investigation_id) REFERENCES investigations (investigation_id) ON DELETE CASCADE
          );

          CREATE INDEX IF NOT EXISTS idx_evidence_investigation ON evidence_records (investigation_id);
          CREATE INDEX IF NOT EXISTS idx_findings_investigation ON findings (investigation_id);
          CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations (status);
        `);

        this.db.prepare('INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?)')
          .run(1, new Date().toISOString(), 'Initial normalized schema');
        this.db.exec('COMMIT');
      } catch (err) {
        this.db.exec('ROLLBACK');
        throw err;
      }
    }

    if (currentVersion < 2) {
      try {
        this.db.exec('ALTER TABLE investigations ADD COLUMN owner_uid TEXT;');
        this.db.prepare('INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?)')
          .run(2, new Date().toISOString(), 'Add owner_uid column for multi-tenant isolation');
      } catch (err: any) {
        // column may already exist
      }
    }
  }

  private preloadCache(): void {
    try {
      const rows = this.db.prepare('SELECT session_json FROM investigations').all() as any[];
      for (const row of rows) {
        if (row.session_json) {
          const session = JSON.parse(row.session_json) as InvestigationSession;
          this.cache.set(session.investigation_id, session);
        }
      }
    } catch {
      // ignore
    }
  }

  async save(session: InvestigationSession, ownerUid: string): Promise<void> {
    session.owner_uid = ownerUid;
    this.cache.set(session.investigation_id, JSON.parse(JSON.stringify(session)));

    this.db.exec('BEGIN');
    try {
      const upsertInv = this.db.prepare(`
        INSERT INTO investigations (
          investigation_id, owner_uid, target_type, target_identifier, target_identity_hash,
          status, goal, stages_executed, stages_total, stages_skipped, stages_failed,
          created_at, completed_at, manifest_json, graph_json, unknowns_json,
          timeline_json, toolchain_json, coverage_json, session_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(investigation_id) DO UPDATE SET
          owner_uid = excluded.owner_uid,
          target_type = excluded.target_type,
          target_identifier = excluded.target_identifier,
          target_identity_hash = excluded.target_identity_hash,
          status = excluded.status,
          goal = excluded.goal,
          stages_executed = excluded.stages_executed,
          stages_total = excluded.stages_total,
          stages_skipped = excluded.stages_skipped,
          stages_failed = excluded.stages_failed,
          created_at = excluded.created_at,
          completed_at = excluded.completed_at,
          manifest_json = excluded.manifest_json,
          graph_json = excluded.graph_json,
          unknowns_json = excluded.unknowns_json,
          timeline_json = excluded.timeline_json,
          toolchain_json = excluded.toolchain_json,
          coverage_json = excluded.coverage_json,
          session_json = excluded.session_json
      `);

      upsertInv.run(
        session.investigation_id,
        ownerUid,
        session.target.type,
        session.target.identifier,
        session.target.identity_hash,
        session.status,
        session.goal,
        session.coverage.stages_executed,
        session.coverage.stages_total,
        session.coverage.stages_skipped || 0,
        session.coverage.stages_failed || 0,
        session.manifest.created_at,
        session.manifest.completed_at || null,
        JSON.stringify(session.manifest),
        JSON.stringify(session.graph),
        JSON.stringify(session.unknowns),
        JSON.stringify(session.timeline),
        JSON.stringify(session.toolchain),
        JSON.stringify(session.coverage),
        JSON.stringify(session)
      );

      // Replace child records atomically
      this.db.prepare('DELETE FROM evidence_records WHERE investigation_id = ?').run(session.investigation_id);
      this.db.prepare('DELETE FROM findings WHERE investigation_id = ?').run(session.investigation_id);

      const insertEvidence = this.db.prepare(`
        INSERT INTO evidence_records (
          evidence_id, investigation_id, schema_version, type, phase, authority,
          source_kind, source_location, source_sha256, canonical_digest,
          content_json, limitations_json, timestamp, tool, parent_evidence_ids_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      for (const ev of session.evidence || []) {
        insertEvidence.run(
          ev.evidence_id,
          session.investigation_id,
          ev.schema_version,
          ev.type,
          ev.phase,
          ev.authority,
          ev.source.kind,
          ev.source.location,
          ev.source.sha256,
          ev.canonical_digest,
          JSON.stringify(ev.content),
          JSON.stringify(ev.limitations || []),
          ev.timestamp,
          ev.tool,
          ev.parent_evidence_ids ? JSON.stringify(ev.parent_evidence_ids) : null
        );
      }

      const insertFinding = this.db.prepare(`
        INSERT INTO findings (
          finding_id, investigation_id, claim, category, classification,
          confidence, status, method, evidence_ids_json, supports_json, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      for (const f of session.findings || []) {
        insertFinding.run(
          f.finding_id,
          session.investigation_id,
          f.claim,
          f.category,
          f.classification,
          f.confidence,
          f.status,
          f.method,
          JSON.stringify(f.evidence_ids || []),
          f.supports ? JSON.stringify(f.supports) : null,
          f.details ? JSON.stringify(f.details) : null
        );
      }

      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  async getById(id: string, requesterUid?: string): Promise<InvestigationSession | null> {
    if (this.cache.has(id)) {
      const session = this.cache.get(id)!;
      if (requesterUid && session.owner_uid && session.owner_uid !== requesterUid) {
        return null;
      }
      return JSON.parse(JSON.stringify(session));
    }

    const row = this.db.prepare('SELECT session_json, owner_uid FROM investigations WHERE investigation_id = ?').get(id) as any;
    if (!row || !row.session_json) {
      return null;
    }

    if (requesterUid && row.owner_uid && row.owner_uid !== requesterUid) {
      return null;
    }

    const session = JSON.parse(row.session_json) as InvestigationSession;
    if (row.owner_uid) session.owner_uid = row.owner_uid;
    this.cache.set(session.investigation_id, session);
    return session;
  }

  async list(requesterUid?: string): Promise<InvestigationSession[]> {
    let rows: any[];
    if (requesterUid) {
      rows = this.db.prepare('SELECT session_json, owner_uid FROM investigations WHERE owner_uid = ? ORDER BY created_at DESC').all(requesterUid) as any[];
    } else {
      rows = this.db.prepare('SELECT session_json, owner_uid FROM investigations ORDER BY created_at DESC').all() as any[];
    }

    const sessions: InvestigationSession[] = [];
    for (const row of rows) {
      if (row.session_json) {
        const s = JSON.parse(row.session_json) as InvestigationSession;
        if (row.owner_uid) s.owner_uid = row.owner_uid;
        sessions.push(s);
      }
    }
    return sessions;
  }

  async delete(id: string, requesterUid?: string): Promise<boolean> {
    if (requesterUid) {
      const session = await this.getById(id, requesterUid);
      if (!session) return false;
    }

    this.cache.delete(id);
    this.db.exec('BEGIN');
    try {
      this.db.prepare('DELETE FROM evidence_records WHERE investigation_id = ?').run(id);
      this.db.prepare('DELETE FROM findings WHERE investigation_id = ?').run(id);
      this.db.prepare('DELETE FROM investigations WHERE investigation_id = ?').run(id);
      this.db.exec('COMMIT');
      return true;
    } catch (err) {
      this.db.exec('ROLLBACK');
      return false;
    }
  }

  async clearCache(): Promise<void> {
    this.cache.clear();
  }

  async getExportBundle(id: string, requesterUid?: string): Promise<InvestigationExportBundle | null> {
    const session = await this.getById(id, requesterUid);
    if (!session) return null;

    const evidencePayloads: Record<string, Record<string, any>> = {};
    for (const ev of session.evidence) {
      evidencePayloads[ev.evidence_id] = ev.content;
    }

    const reportMarkdown = `# REA Studio Investigation Report
**Investigation ID:** \`${session.investigation_id}\`  
**Target:** \`${session.target.identifier}\` (\`${session.target.type}\`)  
**Status:** \`${session.status}\`  
**Created At:** \`${session.manifest.created_at}\`  
**Completed At:** \`${session.manifest.completed_at || 'In-Progress'}\`  
**Integrity Hash:** \`${session.manifest.integrity_hash || 'Unsealed'}\`

## Summary & Coverage
- **Stages Executed:** ${session.coverage.stages_executed}/${session.coverage.stages_total}
- **Endpoints Discovered:** ${session.coverage.endpoints_discovered}
- **Endpoints Verified:** ${session.coverage.endpoints_verified}
- **Evidence Count:** ${session.evidence.length}
- **Findings Count:** ${session.findings.length}
`;

    const integrity = {
      evidence_count: session.evidence.length,
      findings_count: session.findings.length,
      manifest_hash: session.manifest.integrity_hash || '',
      bundle_hash: sha256(canonicalJsonStringify(evidencePayloads)),
      verification_status: 'hash-verified' as const
    };

    return {
      bundle_version: '1.0.0',
      exported_at: new Date().toISOString(),
      investigation: session,
      evidence_payloads: evidencePayloads,
      report_markdown: reportMarkdown,
      integrity
    };
  }

  async importExportBundle(bundle: InvestigationExportBundle, ownerUid: string): Promise<InvestigationSession> {
    if (!bundle || bundle.bundle_version !== '1.0.0') {
      throw new Error(`Unsupported bundle format or version. Expected 1.0.0.`);
    }

    const session = bundle.investigation;
    if (!session || !session.investigation_id || !session.manifest) {
      throw new Error('Invalid bundle: Missing investigation session or manifest.');
    }

    for (const ev of session.evidence || []) {
      const computedDigest = sha256(canonicalJsonStringify(ev.content));
      if (computedDigest !== ev.canonical_digest) {
        throw new Error(`Tampered bundle: Evidence "${ev.evidence_id}" payload hash mismatch.`);
      }
    }

    session.owner_uid = ownerUid;
    await this.save(session, ownerUid);
    return session;
  }

  close(): void {
    try {
      this.db.close();
    } catch {}
  }
}

let activeRepository: InvestigationRepository | null = null;

export function getRepository(): InvestigationRepository {
  if (!activeRepository) {
    const { storageBackend } = resolveServerConfig();

    if (storageBackend === 'sqlite') {
      activeRepository = new SqliteInvestigationRepository();
    } else {
      try {
        activeRepository = new FirestoreInvestigationRepository();
      } catch (err: any) {
        // Enforce Phase 5 constraint: Do not silently fall back to SQLite when Firestore is configured!
        throw new Error(
          `Cloud Firestore storage backend is configured (FIREBASE_STORAGE_BACKEND=firestore) but failed to initialize: ${err.message}. Failing fast to prevent silent fallback to SQLite.`
        );
      }
    }
  }
  return activeRepository;
}

export function setCustomRepository(repo: InvestigationRepository | null): void {
  activeRepository = repo;
}

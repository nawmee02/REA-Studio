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

const DATA_DIR = path.resolve(process.cwd(), 'data');
const DB_PATH = path.join(DATA_DIR, 'rea_studio.db');

export interface InvestigationRepository {
  save(session: InvestigationSession): void;
  getById(id: string): InvestigationSession | null;
  list(): InvestigationSession[];
  delete(id: string): boolean;
  clearCache(): void;
  getExportBundle(id: string): InvestigationExportBundle | null;
  importExportBundle(bundle: InvestigationExportBundle): InvestigationSession;
  close(): void;
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
            category TEXT NOT NULL,
            classification TEXT NOT NULL,
            status TEXT NOT NULL,
            claim TEXT NOT NULL,
            confidence REAL NOT NULL,
            method TEXT NOT NULL,
            evidence_ids_json TEXT NOT NULL,
            supports_json TEXT,
            details_json TEXT,
            FOREIGN KEY (investigation_id) REFERENCES investigations (investigation_id) ON DELETE CASCADE
          );

          CREATE INDEX IF NOT EXISTS idx_evidence_investigation ON evidence_records (investigation_id);
          CREATE INDEX IF NOT EXISTS idx_findings_investigation ON findings (investigation_id);

          INSERT INTO schema_migrations (version, applied_at, description)
          VALUES (1, datetime('now'), 'Initial schema: investigations, evidence_records, findings');
        `);
        this.db.exec('COMMIT');
      } catch (err) {
        this.db.exec('ROLLBACK');
        throw err;
      }
    }
  }

  private preloadCache(): void {
    try {
      const rows = this.db.prepare('SELECT session_json FROM investigations ORDER BY created_at DESC').all() as any[];
      this.cache.clear();
      for (const row of rows) {
        if (row.session_json) {
          try {
            const session = JSON.parse(row.session_json) as InvestigationSession;
            if (session && session.investigation_id) {
              this.cache.set(session.investigation_id, session);
            }
          } catch (e) {
            console.error('Failed to parse cached session:', e);
          }
        }
      }
    } catch (err) {
      console.error('Error preloading cache from SQLite:', err);
    }
  }

  public save(session: InvestigationSession): void {
    if (!session || !session.investigation_id) {
      throw new Error('Valid investigation session with investigation_id is required.');
    }

    this.cache.set(session.investigation_id, session);

    const serializedSession = JSON.stringify(session);
    const stagesExecuted = session.coverage?.stages_executed || 0;
    const stagesTotal = session.coverage?.stages_total || 0;
    const stagesSkipped = session.coverage?.stages_skipped || 0;
    const stagesFailed = session.coverage?.stages_failed || 0;

    this.db.exec('BEGIN');
    try {
      // Upsert investigation
      const upsertInv = this.db.prepare(`
        INSERT INTO investigations (
          investigation_id, target_type, target_identifier, target_identity_hash,
          status, goal, stages_executed, stages_total, stages_skipped, stages_failed,
          created_at, completed_at, manifest_json, graph_json, unknowns_json,
          timeline_json, toolchain_json, coverage_json, session_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(investigation_id) DO UPDATE SET
          status = excluded.status,
          stages_executed = excluded.stages_executed,
          stages_total = excluded.stages_total,
          stages_skipped = excluded.stages_skipped,
          stages_failed = excluded.stages_failed,
          completed_at = excluded.completed_at,
          manifest_json = excluded.manifest_json,
          graph_json = excluded.graph_json,
          unknowns_json = excluded.unknowns_json,
          timeline_json = excluded.timeline_json,
          coverage_json = excluded.coverage_json,
          session_json = excluded.session_json
      `);

      upsertInv.run(
        session.investigation_id,
        session.target.type,
        session.target.identifier,
        session.target.identity_hash,
        session.status,
        session.goal,
        stagesExecuted,
        stagesTotal,
        stagesSkipped,
        stagesFailed,
        session.manifest.created_at,
        session.manifest.completed_at || null,
        JSON.stringify(session.manifest),
        JSON.stringify(session.graph),
        JSON.stringify(session.unknowns),
        JSON.stringify(session.timeline),
        JSON.stringify(session.toolchain),
        JSON.stringify(session.coverage),
        serializedSession
      );

      // Refresh evidence records
      this.db.prepare('DELETE FROM evidence_records WHERE investigation_id = ?').run(session.investigation_id);
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
          ev.schema_version || '1.0.0',
          ev.type,
          ev.phase,
          ev.authority,
          ev.source.kind,
          ev.source.location,
          ev.source.sha256,
          ev.canonical_digest || ev.source.sha256,
          JSON.stringify(ev.content),
          JSON.stringify(ev.limitations || []),
          ev.timestamp,
          ev.tool,
          JSON.stringify(ev.parent_evidence_ids || [])
        );
      }

      // Refresh findings
      this.db.prepare('DELETE FROM findings WHERE investigation_id = ?').run(session.investigation_id);
      const insertFinding = this.db.prepare(`
        INSERT INTO findings (
          finding_id, investigation_id, category, classification, status,
          claim, confidence, method, evidence_ids_json, supports_json, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      for (const fd of session.findings || []) {
        insertFinding.run(
          fd.finding_id,
          session.investigation_id,
          fd.category,
          fd.classification,
          fd.status,
          fd.claim,
          fd.confidence,
          fd.method,
          JSON.stringify(fd.evidence_ids || []),
          JSON.stringify(fd.supports || []),
          JSON.stringify(fd.details || {})
        );
      }

      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  public getById(id: string): InvestigationSession | null {
    if (this.cache.has(id)) {
      return this.cache.get(id)!;
    }

    const row = this.db.prepare('SELECT session_json FROM investigations WHERE investigation_id = ?').get(id) as any;
    if (row && row.session_json) {
      try {
        const session = JSON.parse(row.session_json) as InvestigationSession;
        this.cache.set(id, session);
        return session;
      } catch {
        return null;
      }
    }

    return null;
  }

  public list(): InvestigationSession[] {
    const rows = this.db.prepare('SELECT session_json FROM investigations ORDER BY created_at DESC').all() as any[];
    const list: InvestigationSession[] = [];
    for (const row of rows) {
      if (row.session_json) {
        try {
          list.push(JSON.parse(row.session_json));
        } catch {
          // ignore corrupted row
        }
      }
    }
    return list;
  }

  public delete(id: string): boolean {
    this.cache.delete(id);
    const res = this.db.prepare('DELETE FROM investigations WHERE investigation_id = ?').run(id);
    return res.changes > 0;
  }

  public clearCache(): void {
    this.cache.clear();
  }

  public getExportBundle(id: string): InvestigationExportBundle | null {
    const session = this.getById(id);
    if (!session) return null;

    const evidencePayloads: Record<string, Record<string, any>> = {};
    for (const ev of session.evidence) {
      evidencePayloads[ev.evidence_id] = ev.content;
    }

    const reportMarkdown = generateSessionReportMarkdown(session);
    const bundlePayload = {
      investigation: session,
      evidence_payloads: evidencePayloads
    };
    const bundleHash = sha256(canonicalJsonStringify(bundlePayload));

    return {
      bundle_version: '1.0.0',
      exported_at: new Date().toISOString(),
      investigation: session,
      evidence_payloads: evidencePayloads,
      report_markdown: reportMarkdown,
      integrity: {
        evidence_count: session.evidence.length,
        findings_count: session.findings.length,
        manifest_hash: session.manifest.integrity_hash || '',
        bundle_hash: bundleHash,
        verification_status: 'hash-verified'
      }
    };
  }

  public importExportBundle(bundle: InvestigationExportBundle): InvestigationSession {
    if (!bundle || bundle.bundle_version !== '1.0.0' || !bundle.investigation) {
      throw new Error('Invalid export bundle: missing bundle_version "1.0.0" or investigation session.');
    }

    const session = bundle.investigation;
    this.save(session);
    return session;
  }

  public close(): void {
    this.db.close();
  }
}

function generateSessionReportMarkdown(session: InvestigationSession): string {
  return `# REA Investigation Report: ${session.investigation_id}

**Target**: \`${session.target.identifier}\` (\`${session.target.type}\`)  
**Target Identity SHA-256**: \`${session.target.identity_hash}\`  
**Status**: \`${session.status}\`  
**Created At**: ${session.manifest.created_at}  
**Integrity Hash**: \`${session.manifest.integrity_hash || 'unsealed'}\`  

---

## Findings Summary
${session.findings.map(f => `- **[${f.status}]** (${f.classification.toUpperCase()} ${(f.confidence * 100).toFixed(0)}%) ${f.claim} (Evidence: ${f.evidence_ids.join(', ')})`).join('\n')}

---

## Evidence Ledger (${session.evidence.length} records)
${session.evidence.map(e => `- \`${e.evidence_id}\` [${e.phase}] SHA-256: \`${e.source.sha256}\` (${e.authority})`).join('\n')}
`;
}

// Global default singleton instance
let repositoryInstance: InvestigationRepository | null = null;

export function getRepository(): InvestigationRepository {
  if (!repositoryInstance) {
    repositoryInstance = new SqliteInvestigationRepository();
  }
  return repositoryInstance;
}

export function setRepository(repo: InvestigationRepository): void {
  repositoryInstance = repo;
}

import { Firestore } from 'firebase-admin/firestore';
import { 
  InvestigationSession, 
  EvidenceRecord, 
  FindingRecord, 
  InvestigationExportBundle 
} from '../types/investigation';
import { canonicalJsonStringify, sha256 } from './replay';
import { getAdminFirestore } from './firebaseAdmin';

export class FirestoreInvestigationRepository {
  private db: Firestore;

  constructor(customDb?: Firestore) {
    this.db = customDb || getAdminFirestore();
  }

  async save(session: InvestigationSession, ownerUid: string): Promise<void> {
    const investigationId = session.investigation_id;
    const invRef = this.db.collection('investigations').doc(investigationId);

    session.owner_uid = ownerUid;

    const topLevelData = {
      investigation_id: session.investigation_id,
      owner_uid: ownerUid,
      goal: session.goal,
      target: session.target,
      status: session.status,
      toolchain: session.toolchain,
      evidence_sources: session.evidence_sources,
      unknowns: session.unknowns || [],
      coverage: session.coverage,
      timeline: session.timeline || [],
      manifest: session.manifest,
      created_at: session.manifest.created_at,
      completed_at: session.manifest.completed_at || null,
      updated_at: new Date().toISOString()
    };

    const batch = this.db.batch();

    // 1. Root Investigation Document
    batch.set(invRef, topLevelData, { merge: true });

    // 2. Subcollection: evidence
    if (session.evidence && session.evidence.length > 0) {
      for (const ev of session.evidence) {
        const evRef = invRef.collection('evidence').doc(ev.evidence_id);
        batch.set(evRef, {
          ...ev,
          investigation_id: investigationId,
          owner_uid: ownerUid
        }, { merge: true });
      }
    }

    // 3. Subcollection: findings
    if (session.findings && session.findings.length > 0) {
      for (const finding of session.findings) {
        const findingRef = invRef.collection('findings').doc(finding.finding_id);
        batch.set(findingRef, {
          ...finding,
          investigation_id: investigationId,
          owner_uid: ownerUid
        }, { merge: true });
      }
    }

    // 4. Subcollection: graph
    if (session.graph) {
      const graphRef = invRef.collection('graph').doc('main');
      batch.set(graphRef, {
        nodes: session.graph.nodes || [],
        edges: session.graph.edges || [],
        updated_at: new Date().toISOString()
      }, { merge: true });
    }

    await batch.commit();
  }

  async getById(id: string, requesterUid?: string): Promise<InvestigationSession | null> {
    const invRef = this.db.collection('investigations').doc(id);
    const docSnap = await invRef.get();

    if (!docSnap.exists) {
      return null;
    }

    const data = docSnap.data() as any;

    // Enforce ownership if requesterUid is provided
    if (requesterUid && data.owner_uid && data.owner_uid !== requesterUid) {
      return null;
    }

    // Fetch normalized subcollections in parallel
    const [evidenceSnap, findingsSnap, graphSnap] = await Promise.all([
      invRef.collection('evidence').get(),
      invRef.collection('findings').get(),
      invRef.collection('graph').doc('main').get()
    ]);

    const evidence: EvidenceRecord[] = evidenceSnap.docs.map(d => {
      const docData = d.data();
      return {
        evidence_id: docData.evidence_id,
        schema_version: docData.schema_version,
        type: docData.type,
        phase: docData.phase,
        source: docData.source,
        content: docData.content,
        canonical_digest: docData.canonical_digest,
        authority: docData.authority,
        timestamp: docData.timestamp,
        tool: docData.tool,
        limitations: docData.limitations || [],
        parent_evidence_ids: docData.parent_evidence_ids
      };
    });

    const findings: FindingRecord[] = findingsSnap.docs.map(d => {
      const docData = d.data();
      return {
        finding_id: docData.finding_id,
        claim: docData.claim,
        category: docData.category,
        classification: docData.classification,
        confidence: docData.confidence,
        status: docData.status,
        evidence_ids: docData.evidence_ids || [],
        supports: docData.supports,
        method: docData.method,
        details: docData.details
      };
    });

    const graph = graphSnap.exists 
      ? { nodes: graphSnap.data()?.nodes || [], edges: graphSnap.data()?.edges || [] }
      : { nodes: [], edges: [] };

    return {
      investigation_id: data.investigation_id,
      owner_uid: data.owner_uid,
      goal: data.goal,
      target: data.target,
      toolchain: data.toolchain,
      status: data.status,
      evidence_sources: data.evidence_sources,
      evidence,
      findings,
      unknowns: data.unknowns || [],
      coverage: data.coverage,
      timeline: data.timeline || [],
      graph,
      manifest: data.manifest
    };
  }

  async list(requesterUid?: string): Promise<InvestigationSession[]> {
    let query = this.db.collection('investigations');
    let snap;
    if (requesterUid) {
      snap = await query.where('owner_uid', '==', requesterUid).get();
    } else {
      snap = await query.get();
    }

    const sessions: InvestigationSession[] = [];
    for (const doc of snap.docs) {
      const data = doc.data() as any;
      sessions.push({
        investigation_id: data.investigation_id,
        owner_uid: data.owner_uid,
        goal: data.goal,
        target: data.target,
        toolchain: data.toolchain,
        status: data.status,
        evidence_sources: data.evidence_sources,
        evidence: [],
        findings: [],
        unknowns: data.unknowns || [],
        coverage: data.coverage,
        timeline: data.timeline || [],
        graph: { nodes: [], edges: [] },
        manifest: data.manifest
      });
    }

    return sessions;
  }

  async delete(id: string, requesterUid?: string): Promise<boolean> {
    const invRef = this.db.collection('investigations').doc(id);
    const docSnap = await invRef.get();
    if (!docSnap.exists) return false;

    if (requesterUid) {
      const data = docSnap.data();
      if (data?.owner_uid && data.owner_uid !== requesterUid) {
        return false;
      }
    }

    // Delete subcollections then root
    const [evidenceSnap, findingsSnap] = await Promise.all([
      invRef.collection('evidence').get(),
      invRef.collection('findings').get()
    ]);

    const batch = this.db.batch();
    evidenceSnap.docs.forEach(d => batch.delete(d.ref));
    findingsSnap.docs.forEach(d => batch.delete(d.ref));
    batch.delete(invRef.collection('graph').doc('main'));
    batch.delete(invRef);

    await batch.commit();
    return true;
  }

  async clearCache(): Promise<void> {
    // Firestore has no local in-memory cache to clear
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

    // Cryptographic validation of imported evidence records
    for (const ev of session.evidence || []) {
      const computedDigest = sha256(canonicalJsonStringify(ev.content));
      if (computedDigest !== ev.canonical_digest) {
        throw new Error(`Tampered bundle: Evidence "${ev.evidence_id}" payload hash mismatch.`);
      }
    }

    // Force ownerUid to the authenticated user importing the bundle
    session.owner_uid = ownerUid;
    await this.save(session, ownerUid);
    return session;
  }
}

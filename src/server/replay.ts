import crypto from 'crypto';
import { InvestigationSession, EvidenceRecord, FindingRecord } from '../types/investigation';

export function sha256(data: string | Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Deterministic JSON stringifier that sorts all object keys recursively.
 */
export function canonicalJsonStringify(val: any): string {
  if (val === null || typeof val !== 'object') {
    return JSON.stringify(val);
  }
  if (Array.isArray(val)) {
    return '[' + val.map(canonicalJsonStringify).join(',') + ']';
  }
  const sortedKeys = Object.keys(val).sort();
  const keyVals = sortedKeys.map(key => `${JSON.stringify(key)}:${canonicalJsonStringify(val[key])}`);
  return '{' + keyVals.join(',') + '}';
}

/**
 * Recomputes the canonical content digest for an evidence record.
 */
export function computeEvidenceContentDigest(content: Record<string, any>): string {
  const canonicalPayload = canonicalJsonStringify(content);
  return sha256(canonicalPayload);
}

/**
 * Computes the overall session integrity hash across target, evidence ledger, and findings.
 */
export function computeSessionIntegrityHash(session: {
  investigation_id: string;
  target: { identifier: string; identity_hash: string };
  evidence: EvidenceRecord[];
  findings: FindingRecord[];
  unknowns?: string[];
  manifest: { created_at: string; parameters: Record<string, any> };
}): string {
  const evidenceDigests = session.evidence
    .map(e => `${e.evidence_id}::${e.source?.sha256 || ''}::${computeEvidenceContentDigest(e.content)}`)
    .sort();

  const findingFingerprints = session.findings
    .map(f => `${f.finding_id}::${f.classification}::${f.status}::${(f.evidence_ids || []).slice().sort().join(',')}`)
    .sort();

  const sessionPayload = {
    investigation_id: session.investigation_id,
    target_id: session.target.identifier,
    target_hash: session.target.identity_hash,
    evidence: evidenceDigests,
    findings: findingFingerprints,
    unknowns: (session.unknowns || []).slice().sort(),
    created_at: session.manifest.created_at,
    parameters: session.manifest.parameters
  };

  return sha256(canonicalJsonStringify(sessionPayload));
}

export interface ReplayVerificationItem {
  evidence_id: string;
  type: string;
  phase: string;
  declared_digest: string;
  recomputed_content_digest: string;
  hash_verified: boolean;
  tamper_detected: boolean;
  reasons?: string[];
}

export interface ReplayReport {
  reproducibility: 'DETERMINISTIC_OFFLINE';
  investigation_id: string;
  target: InvestigationSession['target'];
  evidence_integrity: {
    total: number;
    verified_hashes: number;
    corrupted: number;
    corrupted_evidence_ids: string[];
    verification_items: ReplayVerificationItem[];
  };
  finding_integrity: {
    total: number;
    valid_citations: number;
    invalid_citations: number;
    invalid_finding_ids: string[];
  };
  normalized_findings: InvestigationSession['findings'];
  unknowns: string[];
  manifest_hash: string;
  recomputed_manifest_hash: string;
  manifest_intact: boolean;
}

/**
 * Replays an investigation strictly offline against captured evidence nodes,
 * recomputing cryptographic digests to detect any tampering or divergence.
 */
export function replayInvestigationOffline(session: InvestigationSession): ReplayReport {
  let corruptedCount = 0;
  const corruptedIds: string[] = [];

  const verifiedItems: ReplayVerificationItem[] = (session.evidence || []).map(ev => {
    const reasons: string[] = [];
    const declaredDigest = ev.source?.sha256 || '';

    // 1. Verify that source.sha256 is present and a valid 64-character lowercase hex string
    const hasValidDigestFormat = typeof declaredDigest === 'string' && /^[a-f0-9]{64}$/i.test(declaredDigest);
    if (!hasValidDigestFormat) {
      reasons.push('Declared source.sha256 is missing or not a 64-char hex string');
    }

    // 2. Recompute content digest against actual evidence payload
    const recomputedContentDigest = computeEvidenceContentDigest(ev.content || {});

    // 3. Compare declared digest against recomputed digest
    const digestMatches = hasValidDigestFormat && declaredDigest.toLowerCase() === recomputedContentDigest.toLowerCase();
    if (hasValidDigestFormat && !digestMatches) {
      reasons.push(`Payload hash mismatch: declared ${declaredDigest.slice(0, 8)}... !== recomputed ${recomputedContentDigest.slice(0, 8)}...`);
    }

    const isRecordIntact = hasValidDigestFormat && digestMatches;
    if (!isRecordIntact) {
      corruptedCount++;
      corruptedIds.push(ev.evidence_id);
    }

    return {
      evidence_id: ev.evidence_id,
      type: ev.type,
      phase: ev.phase,
      declared_digest: declaredDigest || 'missing',
      recomputed_content_digest: recomputedContentDigest,
      hash_verified: isRecordIntact,
      tamper_detected: !isRecordIntact,
      reasons: reasons.length > 0 ? reasons : undefined
    };
  });

  // Verify finding citation validity
  const validEvidenceIdSet = new Set(session.evidence.map(e => e.evidence_id));
  const invalidFindingIds: string[] = [];
  let validCitations = 0;

  for (const f of session.findings || []) {
    const citationsValid = (f.evidence_ids || []).length > 0 &&
      f.evidence_ids.every(id => validEvidenceIdSet.has(id));

    if (citationsValid) {
      validCitations++;
    } else {
      invalidFindingIds.push(f.finding_id);
    }
  }

  // Recompute session integrity hash
  const declaredManifestHash = session.manifest?.integrity_hash || '';
  const recomputedManifestHash = computeSessionIntegrityHash(session);
  const manifestIntact = declaredManifestHash.length === 64 &&
    declaredManifestHash.toLowerCase() === recomputedManifestHash.toLowerCase() &&
    corruptedCount === 0;

  return {
    reproducibility: 'DETERMINISTIC_OFFLINE',
    investigation_id: session.investigation_id,
    target: session.target,
    evidence_integrity: {
      total: session.evidence?.length || 0,
      verified_hashes: verifiedItems.filter(i => i.hash_verified).length,
      corrupted: corruptedCount,
      corrupted_evidence_ids: corruptedIds,
      verification_items: verifiedItems
    },
    finding_integrity: {
      total: session.findings?.length || 0,
      valid_citations: validCitations,
      invalid_citations: invalidFindingIds.length,
      invalid_finding_ids: invalidFindingIds
    },
    normalized_findings: session.findings || [],
    unknowns: session.unknowns || [],
    manifest_hash: declaredManifestHash,
    recomputed_manifest_hash: recomputedManifestHash,
    manifest_intact: manifestIntact
  };
}

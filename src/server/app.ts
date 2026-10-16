import express, { Express } from 'express';
import { 
  EvidenceRecord, 
  Target,
  TARGET_REGISTRY,
  SUPPORTED_TARGET_TYPES,
  TargetType,
  InvestigationExportBundle,
  InvestigationSession
} from '../types/investigation';
import { 
  safeFetch, 
  validateUrlStructure,
  getNormalizedOrigin 
} from './networkGuard';
import { 
  sha256, 
  analyzeArtifactCode 
} from './analyzer';
import { 
  initPersistence, 
  saveInvestigation, 
  getInvestigation, 
  listInvestigations,
  getExportBundle,
  importExportBundle 
} from './persistence';
import { replayInvestigationOffline, computeEvidenceContentDigest } from './replay';
import { runInvestigationPipeline } from './pipeline';
import { requireAuth } from './authMiddleware';

const SAFE_VERIFICATION_METHODS = ['GET', 'HEAD', 'OPTIONS'];

export function createInvestigationApp(): Express {
  const app = express();
  app.use(express.json({ limit: '10mb' }));

  // Initialize persistence engine
  initPersistence();

  // Health check endpoint (unauthenticated)
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      service: 'rea-studio',
      version: '6.5.0',
      timestamp: new Date().toISOString()
    });
  });

  // -------------------------------------------------------------
  // POST /api/investigations — Deterministic Reconnaissance Pipeline
  // -------------------------------------------------------------
  app.post('/api/investigations', requireAuth, async (req, res) => {
    try {
      const { 
        target_type = 'web_url', 
        identifier, 
        goal,
        evidence_sources 
      } = req.body;

      const ownerUid = req.auth!.uid;

      // 1. Target Type Validation against registry
      const targetDef = TARGET_REGISTRY[target_type as TargetType];
      if (!targetDef || targetDef.status !== 'supported') {
        return res.status(400).json({
          error: `Unsupported target type: "${target_type}". Currently supported target types: ${SUPPORTED_TARGET_TYPES.join(', ')}. Target type "${target_type}" is planned for a future phase (${targetDef?.limitations?.[0] || 'Handler not implemented'}).`
        });
      }

      if (!identifier || typeof identifier !== 'string') {
        return res.status(400).json({ error: 'Target identifier is required.' });
      }

      // Early URL syntax check
      try {
        validateUrlStructure(identifier);
      } catch (err: any) {
        return res.status(400).json({ error: err.message });
      }

      const session = await runInvestigationPipeline({
        identifier,
        target_type,
        goal,
        evidence_sources,
        owner_uid: ownerUid
      });

      return res.json(session);
    } catch (error: any) {
      const status = error.message?.includes('Security boundary') || 
                     error.message?.includes('Forbidden protocol') ||
                     error.message?.includes('Unsupported target type') ? 400 : 502;
      return res.status(status).json({ error: error.message || 'Investigation pipeline failed' });
    }
  });

  // -------------------------------------------------------------
  // POST /api/verify-endpoint — Origin-Bound Verification
  // -------------------------------------------------------------
  app.post('/api/verify-endpoint', requireAuth, async (req, res) => {
    try {
      const { investigation_id, endpoint_path, method = 'GET' } = req.body;
      const ownerUid = req.auth!.uid;

      if (!investigation_id || typeof investigation_id !== 'string') {
        return res.status(400).json({ error: 'investigation_id is required.' });
      }

      if (!endpoint_path || typeof endpoint_path !== 'string') {
        return res.status(400).json({ error: 'endpoint_path is required.' });
      }

      // 1. Method restriction: default safe methods only
      const normalizedMethod = method.toUpperCase();
      if (!SAFE_VERIFICATION_METHODS.includes(normalizedMethod)) {
        return res.status(405).json({
          error: `Prohibited method "${method}": Verification probes default to safe idempotent methods (${SAFE_VERIFICATION_METHODS.join(', ')}). State-changing HTTP methods require explicit separate authorization.`
        });
      }

      // 2. Fetch session and check requester ownership
      const session = await getInvestigation(investigation_id, ownerUid);
      if (!session) {
        return res.status(404).json({ error: `Investigation "${investigation_id}" not found or unauthorized.` });
      }

      // 3. Candidate endpoint scope: must match discovered candidate in session
      const discoveredEndpoints = new Set<string>();
      (session.findings || [])
        .filter(f => f.category === 'endpoint' && f.details?.path)
        .forEach(f => discoveredEndpoints.add(f.details!.path));

      (session.evidence || [])
        .filter(e => e.phase === 'endpoint_extraction' && e.content?.endpoints)
        .forEach(e => {
          for (const ep of e.content.endpoints) {
            if (ep && ep.path) discoveredEndpoints.add(ep.path);
          }
        });

      let epPathOnly = endpoint_path;
      if (endpoint_path.startsWith('http://') || endpoint_path.startsWith('https://')) {
        try {
          epPathOnly = new URL(endpoint_path).pathname;
        } catch {}
      }

      const isDiscoveredCandidate = discoveredEndpoints.has(endpoint_path) || discoveredEndpoints.has(epPathOnly);
      if (!isDiscoveredCandidate) {
        return res.status(403).json({
          error: `Scope violation: Endpoint candidate "${endpoint_path}" was not discovered in investigation "${investigation_id}". Verification probes are restricted to discovered session endpoints.`
        });
      }

      // 4. Normalized origin comparison (Scheme, Hostname, Effective Port)
      const targetNormalizedOrigin = getNormalizedOrigin(session.target.identifier);
      let targetUrl: string;

      if (endpoint_path.startsWith('http://') || endpoint_path.startsWith('https://')) {
        const candidateNormalizedOrigin = getNormalizedOrigin(endpoint_path);
        if (candidateNormalizedOrigin !== targetNormalizedOrigin) {
          return res.status(403).json({
            error: `Scope violation: Verification candidate origin "${candidateNormalizedOrigin}" does not match target origin "${targetNormalizedOrigin}". Cross-origin, alternate-scheme, and alternate-port probes are prohibited.`
          });
        }
        targetUrl = endpoint_path;
      } else {
        const base = new URL(session.target.identifier);
        targetUrl = `${base.origin}${endpoint_path.startsWith('/') ? '' : '/'}${endpoint_path}`;
      }

      // 5. Probe using safeFetch with expectedOrigin to enforce same-origin redirects
      let probeRes;
      try {
        probeRes = await safeFetch(targetUrl, {
          method: normalizedMethod,
          timeoutMs: 5000,
          maxBytes: 512 * 1024,
          maxRedirects: 3,
          expectedOrigin: targetNormalizedOrigin,
          headers: {
            'Accept': 'application/json, text/plain, */*'
          }
        });
      } catch (probeErr: any) {
        const failedEvId = `ev_${session.investigation_id.toLowerCase()}_verify_failed_${Date.now().toString(36)}`;
        const failContent = {
          method: normalizedMethod,
          status: 0,
          error: probeErr.message,
          reachability: 'UNREACHABLE'
        };
        const failContentDigest = computeEvidenceContentDigest(failContent);
        const failEvidence: EvidenceRecord = {
          evidence_id: failedEvId,
          schema_version: '1.0.0',
          type: 'observation',
          phase: 'active_verification',
          source: {
            kind: 'network_probe',
            location: targetUrl,
            sha256: failContentDigest
          },
          content: failContent,
          canonical_digest: failContentDigest,
          authority: 'direct',
          timestamp: new Date().toISOString(),
          tool: 'rea-verification-engine@6.5.0',
          limitations: [
            'Probe connection failed or timed out; does not disprove endpoint existence under private network or specific request headers'
          ]
        };
        session.evidence.push(failEvidence);
        await saveInvestigation(session, ownerUid);

        return res.json({
          success: false,
          status: 'UNREACHABLE',
          evidence: failEvidence,
          message: `Endpoint was unreachable: ${probeErr.message}. Status remains UNVERIFIED.`
        });
      }

      const probeText = probeRes.body;
      const verifyEvId = `ev_${session.investigation_id.toLowerCase()}_verify_${Date.now().toString(36)}`;
      const probeContent = {
        method: normalizedMethod,
        status: probeRes.status,
        statusText: probeRes.statusText,
        contentType: probeRes.headers['content-type'] || 'unknown',
        preview: probeText.slice(0, 300),
        resolvedIp: probeRes.resolvedIp,
        finalUrl: probeRes.finalUrl
      };
      const probeContentDigest = computeEvidenceContentDigest(probeContent);

      const newEvidence: EvidenceRecord = {
        evidence_id: verifyEvId,
        schema_version: '1.0.0',
        type: 'observation',
        phase: 'active_verification',
        source: {
          kind: 'network_probe',
          location: probeRes.finalUrl || targetUrl,
          sha256: probeContentDigest,
          bytes: probeText.length
        },
        content: probeContent,
        canonical_digest: probeContentDigest,
        authority: 'direct',
        timestamp: new Date().toISOString(),
        tool: 'rea-verification-engine@6.5.0',
        limitations: [
          `Active probe observed behavior at ${normalizedMethod} ${probeRes.finalUrl || targetUrl} (HTTP ${probeRes.status})`,
          'Probe establishes specific observed response under recorded parameters; does not establish complete stateful API contract'
        ]
      };

      session.evidence.push(newEvidence);

      const isBehaviorObserved = probeRes.status >= 200 && probeRes.status < 500 && probeRes.status !== 404;

      const targetFinding = session.findings.find(f => f.details?.path === endpoint_path || f.claim.includes(endpoint_path));
      if (targetFinding) {
        if (isBehaviorObserved) {
          targetFinding.status = 'VERIFIED';
          targetFinding.confidence = 0.95;
          targetFinding.evidence_ids.push(verifyEvId);
          targetFinding.details = {
            ...targetFinding.details,
            verified_status: probeRes.status,
            verified_at: new Date().toISOString()
          };
          session.coverage.endpoints_verified += 1;
        } else if (probeRes.status === 404) {
          targetFinding.status = 'UNKNOWN';
          targetFinding.details = {
            ...targetFinding.details,
            verified_status: 404,
            note: 'Returned HTTP 404 on default probe; specific query parameters or request body may be required'
          };
        }
      }

      // Persist updated session
      await saveInvestigation(session, ownerUid);

      return res.json({
        success: true,
        status: isBehaviorObserved ? 'VERIFIED' : 'UNKNOWN',
        evidence: newEvidence,
        updated_finding: targetFinding
      });
    } catch (err: any) {
      return res.status(500).json({ error: `Verification failed: ${err.message}` });
    }
  });

  // -------------------------------------------------------------
  // POST /api/replay-investigation — Cryptographic Replay Engine
  // -------------------------------------------------------------
  app.post('/api/replay-investigation', requireAuth, async (req, res) => {
    try {
      const { investigation_id, session: suppliedSession, bundle } = req.body;
      const ownerUid = req.auth!.uid;

      let session: InvestigationSession | null = null;
      if (bundle) {
        if (!bundle || bundle.bundle_version !== '1.0.0' || !bundle.investigation) {
          return res.status(400).json({ error: 'Corrupted or unsupported export bundle version.' });
        }
        session = bundle.investigation;
      } else if (suppliedSession) {
        session = suppliedSession;
      } else if (investigation_id) {
        session = await getInvestigation(investigation_id, ownerUid);
      }

      if (!session) {
        return res.status(404).json({ error: `Investigation "${investigation_id}" not found or unauthorized.` });
      }

      const report = replayInvestigationOffline(session);
      return res.json(report);
    } catch (err: any) {
      return res.status(500).json({ error: `Replay failed: ${err.message}` });
    }
  });

  // -------------------------------------------------------------
  // GET /api/investigations/:id/export — Export Versioned Bundle
  // -------------------------------------------------------------
  app.get('/api/investigations/:id/export', requireAuth, async (req, res) => {
    const ownerUid = req.auth!.uid;
    const bundle = await getExportBundle(req.params.id, ownerUid);
    if (!bundle) {
      return res.status(404).json({ error: 'Investigation not found or unauthorized.' });
    }
    res.setHeader('Content-Disposition', `attachment; filename="${req.params.id}.rea-bundle.json"`);
    return res.json(bundle);
  });

  // -------------------------------------------------------------
  // POST /api/investigations/import — Import Versioned Bundle
  // -------------------------------------------------------------
  app.post('/api/investigations/import', requireAuth, async (req, res) => {
    try {
      const { bundle } = req.body;
      const ownerUid = req.auth!.uid;
      const session = await importExportBundle(bundle, ownerUid);
      return res.json(session);
    } catch (err: any) {
      return res.status(400).json({ error: err.message });
    }
  });

  // -------------------------------------------------------------
  // POST /api/analyze-artifact — Artifact Lab AST/Code Analysis
  // -------------------------------------------------------------
  app.post('/api/analyze-artifact', requireAuth, async (req, res) => {
    try {
      const { code, filename = 'bundle.js', type = 'javascript' } = req.body;
      const result = analyzeArtifactCode(code, filename, type);
      return res.json(result);
    } catch (err: any) {
      return res.status(400).json({ error: err.message });
    }
  });

  // -------------------------------------------------------------
  // GET /api/investigations — List all investigations for current operator
  // -------------------------------------------------------------
  app.get('/api/investigations', requireAuth, async (req, res) => {
    const ownerUid = req.auth!.uid;
    const list = await listInvestigations(ownerUid);
    const summaries = list.map(inv => ({
      investigation_id: inv.investigation_id,
      owner_uid: inv.owner_uid,
      target: inv.target,
      status: inv.status,
      created_at: inv.manifest.created_at,
      findings_count: inv.findings?.length || 0,
      evidence_count: inv.evidence?.length || 0
    }));
    return res.json(summaries);
  });

  // -------------------------------------------------------------
  // GET /api/investigations/:id — Get full investigation session
  // -------------------------------------------------------------
  app.get('/api/investigations/:id', requireAuth, async (req, res) => {
    const ownerUid = req.auth!.uid;
    const session = await getInvestigation(req.params.id, ownerUid);
    if (!session) {
      return res.status(404).json({ error: 'Investigation not found or unauthorized.' });
    }
    return res.json(session);
  });

  return app;
}

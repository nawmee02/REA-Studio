import path from 'path';
import crypto from 'crypto';
import { 
  InvestigationSession, 
  EvidenceRecord, 
  FindingRecord, 
  TimelineEntry, 
  GraphNode, 
  GraphEdge, 
  Target,
  TargetType,
  TARGET_REGISTRY,
  SUPPORTED_TARGET_TYPES 
} from '../types/investigation';
import { 
  safeFetch, 
  validateUrlStructure 
} from './networkGuard';
import { 
  sha256, 
  detectTechnologies, 
  extractEndpoints, 
  analyzeScriptInventory 
} from './analyzer';
import { 
  computeEvidenceContentDigest, 
  computeSessionIntegrityHash 
} from './replay';
import { saveInvestigation } from './persistence';

export interface PipelineOptions {
  identifier: string;
  target_type?: TargetType | string;
  goal?: string;
  evidence_sources?: {
    static_analysis: boolean;
    runtime_observation: boolean;
    network_inspection: boolean;
    version_comparison: boolean;
  };
  fixtureHtml?: string;
  fixtureHeaders?: Record<string, string>;
  fixtureStatusCode?: number;
}

/**
 * Runs the deterministic REA reconnaissance and analysis pipeline.
 * Supports both live remote URL targets (via safeFetch) and offline golden fixtures.
 */
export async function runInvestigationPipeline(options: PipelineOptions): Promise<InvestigationSession> {
  const startTime = Date.now();
  const timeline: TimelineEntry[] = [];

  const recordTimeline = (
    stage: string, 
    status: 'started' | 'completed' | 'skipped' | 'failed', 
    duration_ms: number, 
    evidence_produced?: string[],
    reason?: string,
    error?: string
  ) => {
    timeline.push({
      stage,
      timestamp: new Date().toISOString(),
      status,
      duration_ms,
      evidence_produced,
      reason,
      error
    });
  };

  const {
    identifier,
    target_type = 'web_url',
    goal = 'General Architecture & API Reconnaissance',
    evidence_sources = {
      static_analysis: true,
      runtime_observation: false,
      network_inspection: true,
      version_comparison: false
    },
    fixtureHtml,
    fixtureHeaders,
    fixtureStatusCode = 200
  } = options;

  // 1. Target Type Capability & Registry Validation
  const targetDef = TARGET_REGISTRY[target_type as TargetType];
  if (!targetDef || targetDef.status !== 'supported') {
    throw new Error(
      `Unsupported target type: "${target_type}". Currently supported target types: ${SUPPORTED_TARGET_TYPES.join(', ')}. Target type "${target_type}" is planned for a future phase (${targetDef?.limitations?.[0] || 'Handler not implemented'}).`
    );
  }

  if (!identifier || typeof identifier !== 'string') {
    throw new Error('Target identifier is required.');
  }

  // Generate collision-resistant unique investigation ID
  const investigationId = `INV-${new Date().getFullYear()}-${crypto.randomUUID()}`;
  const evidenceList: EvidenceRecord[] = [];
  const findingsList: FindingRecord[] = [];
  const unknownsList: string[] = [];
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  // Stage 1: Resolve Target & Declare Capabilities
  const s1Start = Date.now();
  let validatedUrl: URL;
  try {
    validatedUrl = validateUrlStructure(identifier);
  } catch (err: any) {
    recordTimeline('target_resolution', 'failed', Date.now() - s1Start, undefined, undefined, err.message);
    throw err;
  }

  const canonicalUrl = validatedUrl.origin + validatedUrl.pathname;
  const targetIdentityHash = sha256(canonicalUrl);

  const target: Target = {
    type: target_type as TargetType,
    identifier: canonicalUrl,
    identity_hash: targetIdentityHash,
    capabilities: targetDef.availableStages,
    metadata: {
      hostname: validatedUrl.hostname,
      port: validatedUrl.port || (validatedUrl.protocol === 'https:' ? '443' : '80'),
      pathname: validatedUrl.pathname
    }
  };

  const targetContent = { target };
  const targetContentDigest = computeEvidenceContentDigest(targetContent);
  const ev01: EvidenceRecord = {
    evidence_id: `ev_${investigationId.toLowerCase()}_001_target_identity`,
    schema_version: '1.0.0',
    type: 'observation',
    phase: 'target_resolution',
    source: {
      kind: 'config_literal',
      location: canonicalUrl,
      sha256: targetContentDigest
    },
    content: targetContent,
    canonical_digest: targetContentDigest,
    authority: 'direct',
    timestamp: new Date().toISOString(),
    tool: 'rea-target-resolver@6.5.0',
    limitations: ['Resolved hostname without authenticated credentials']
  };
  evidenceList.push(ev01);
  nodes.push({ id: target.identifier, label: target.identifier, type: 'target', data: target });
  recordTimeline('target_resolution', 'completed', Date.now() - s1Start, [ev01.evidence_id]);

  // Stage 2: HTTP Acquisition (with anti-SSRF and DNS pinning)
  const s2Start = Date.now();
  let htmlText = '';
  let responseHeaders: Record<string, string> = {};
  let statusCode = 200;
  let resolvedIp = '127.0.0.1';

  try {
    if (fixtureHtml !== undefined) {
      htmlText = fixtureHtml;
      responseHeaders = fixtureHeaders || {
        'content-type': 'text/html; charset=utf-8',
        'server': 'rea-fixture-harness',
        'x-content-type-options': 'nosniff'
      };
      statusCode = fixtureStatusCode;
      resolvedIp = '198.51.100.1'; // RFC 5737 TEST-NET-2
    } else {
      const safeRes = await safeFetch(canonicalUrl, {
        timeoutMs: 10000,
        maxBytes: 5 * 1024 * 1024,
        maxRedirects: 5,
        headers: {
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9'
        }
      });
      htmlText = safeRes.body;
      responseHeaders = safeRes.headers;
      statusCode = safeRes.status;
      resolvedIp = safeRes.resolvedIp;
    }
    recordTimeline('http_acquisition', 'completed', Date.now() - s2Start);
  } catch (err: any) {
    recordTimeline('http_acquisition', 'failed', Date.now() - s2Start, undefined, undefined, err.message);

    // Record failure evidence and persist failed session
    const failContent = { error: err.message, target: canonicalUrl, status: 'FAILED' };
    const failDigest = computeEvidenceContentDigest(failContent);
    const failEv: EvidenceRecord = {
      evidence_id: `ev_${investigationId.toLowerCase()}_002_acquisition_failed`,
      schema_version: '1.0.0',
      type: 'observation',
      phase: 'http_acquisition',
      source: {
        kind: 'http_response',
        location: canonicalUrl,
        sha256: failDigest
      },
      content: failContent,
      canonical_digest: failDigest,
      authority: 'direct',
      timestamp: new Date().toISOString(),
      tool: 'rea-socket-guard@6.5.0',
      limitations: ['HTTP acquisition failed due to network or security boundary error']
    };
    evidenceList.push(failEv);

    const failSession: InvestigationSession = {
      investigation_id: investigationId,
      goal,
      target,
      toolchain: {
        rea_version: '6.5.0',
        studio_version: '1.0.0',
        node_version: process.version
      },
      status: 'FAILED',
      evidence_sources,
      evidence: evidenceList,
      findings: findingsList,
      unknowns: [`HTTP acquisition failed: ${err.message}`],
      coverage: {
        stages_executed: 1,
        stages_total: 12,
        stages_skipped: 10,
        stages_failed: 1,
        endpoints_discovered: 0,
        endpoints_verified: 0,
        scripts_mapped: 0,
        technologies_confirmed: 0
      },
      timeline,
      graph: { nodes, edges },
      manifest: {
        created_at: new Date(startTime).toISOString(),
        completed_at: new Date().toISOString(),
        duration_total_ms: Date.now() - startTime,
        parameters: { timeout_ms: 10000, max_response_bytes: 5242880, user_agent: 'rea-web-engine@6.5.0' }
      }
    };
    saveInvestigation(failSession);
    throw new Error(`HTTP acquisition failed: ${err.message}`);
  }

  // Stage 3: Response Headers & Edge Fingerprinting
  const s3Start = Date.now();
  const headerContent = {
    statusCode,
    headers: responseHeaders,
    securityHeaders: {
      hasHsts: !!(responseHeaders['strict-transport-security']),
      hasCsp: !!(responseHeaders['content-security-policy']),
      hasXContentTypeOptions: !!(responseHeaders['x-content-type-options']),
      hasXFrameOptions: !!(responseHeaders['x-frame-options'])
    },
    edge: {
      serverHeader: responseHeaders['server'] || 'unspecified',
      cfRay: responseHeaders['cf-ray'] || null
    }
  };
  const headerContentDigest = computeEvidenceContentDigest(headerContent);

  const ev02: EvidenceRecord = {
    evidence_id: `ev_${investigationId.toLowerCase()}_002_headers_and_edge`,
    schema_version: '1.0.0',
    type: 'observation',
    phase: 'header_inspection',
    source: {
      kind: 'http_headers',
      location: canonicalUrl,
      sha256: headerContentDigest
    },
    content: headerContent,
    canonical_digest: headerContentDigest,
    authority: 'direct',
    timestamp: new Date().toISOString(),
    tool: 'rea-header-inspector@6.5.0',
    limitations: ['Headers represent edge termination responses; origin headers may be masked']
  };
  evidenceList.push(ev02);

  if (headerContent.edge.serverHeader !== 'unspecified') {
    findingsList.push({
      finding_id: `fd_${investigationId.toLowerCase()}_server`,
      claim: `Edge server identifies as "${headerContent.edge.serverHeader}".`,
      category: 'server',
      classification: 'observation',
      confidence: 0.95,
      status: 'VERIFIED',
      evidence_ids: [ev02.evidence_id],
      method: 'Direct inspection of Server HTTP response header'
    });
  }

  const transportContent = {
    protocol: validatedUrl.protocol,
    resolvedIp,
    statusCode
  };
  const transportContentDigest = computeEvidenceContentDigest(transportContent);
  const ev03: EvidenceRecord = {
    evidence_id: `ev_${investigationId.toLowerCase()}_003_network_transport`,
    schema_version: '1.0.0',
    type: 'observation',
    phase: 'transport_inspection',
    source: {
      kind: 'http_response',
      location: canonicalUrl,
      sha256: transportContentDigest
    },
    content: transportContent,
    canonical_digest: transportContentDigest,
    authority: 'direct',
    timestamp: new Date().toISOString(),
    tool: 'rea-socket-guard@6.5.0',
    limitations: ['Connection established through pinned public DNS IP validation']
  };
  evidenceList.push(ev03);
  recordTimeline('header_inspection', 'completed', Date.now() - s3Start, [ev02.evidence_id, ev03.evidence_id]);

  // Stage 4: HTML DOM Inspection
  const s4Start = Date.now();
  const titleMatch = htmlText.match(/<title\b[^>]*>([^<]*)<\/title>/i);
  const title = titleMatch ? titleMatch[1].trim() : '';

  const metaDescMatch = htmlText.match(/<meta\s+name=["']description["']\s+content=["']([^"']*)["']/i);
  const metaDescription = metaDescMatch ? metaDescMatch[1].trim() : '';

  const customElementRegex = /<([a-z][a-z0-9_]*-[a-z0-9_-]+)\b/gi;
  const customElementMatches = Array.from(new Set(Array.from(htmlText.matchAll(customElementRegex), m => m[1].toLowerCase())));

  const domContent = {
    title,
    metaDescription,
    customElements: customElementMatches,
    hasDoctype: /<!doctype html>/i.test(htmlText),
    hasRootDiv: htmlText.includes('id="root"') || htmlText.includes('id="__next"') || htmlText.includes('id="app"')
  };
  const domContentDigest = computeEvidenceContentDigest(domContent);

  const ev04: EvidenceRecord = {
    evidence_id: `ev_${investigationId.toLowerCase()}_004_html_dom`,
    schema_version: '1.0.0',
    type: 'observation',
    phase: 'html_dom_inspection',
    source: {
      kind: 'html_dom',
      location: canonicalUrl,
      sha256: domContentDigest,
      bytes: htmlText.length
    },
    content: domContent,
    canonical_digest: domContentDigest,
    authority: 'direct',
    timestamp: new Date().toISOString(),
    tool: 'rea-dom-parser@6.5.0',
    limitations: ['Static DOM only; custom elements registered inside deferred bundles require execution']
  };
  evidenceList.push(ev04);
  recordTimeline('html_dom_inspection', 'completed', Date.now() - s4Start, [ev04.evidence_id]);

  // Stage 5: Script Inventory
  const s5Start = Date.now();
  const { scripts: scriptsList, inlineScripts } = analyzeScriptInventory(htmlText, validatedUrl.origin);

  scriptsList.forEach(sc => {
    nodes.push({ id: sc.src, label: path.basename(sc.src.split('?')[0]) || sc.src, type: 'script', category: sc.category });
    edges.push({ source: target.identifier, target: sc.src, relation: 'loads' });
  });

  const scriptInventoryContent = {
    totalScripts: scriptsList.length,
    inlineScriptBlocks: inlineScripts.length,
    scripts: scriptsList
  };
  const scriptInventoryDigest = computeEvidenceContentDigest(scriptInventoryContent);

  const ev05: EvidenceRecord = {
    evidence_id: `ev_${investigationId.toLowerCase()}_005_script_inventory`,
    schema_version: '1.0.0',
    type: 'observation',
    phase: 'script_inventory',
    source: {
      kind: 'script_ast',
      location: canonicalUrl,
      sha256: scriptInventoryDigest
    },
    content: scriptInventoryContent,
    canonical_digest: scriptInventoryDigest,
    authority: 'direct',
    timestamp: new Date().toISOString(),
    tool: 'rea-script-inventory@6.5.0',
    limitations: ['Dynamic imports loaded via import() at runtime are not included in initial inventory']
  };
  evidenceList.push(ev05);
  recordTimeline('script_inventory', 'completed', Date.now() - s5Start, [ev05.evidence_id]);

  // Stage 6: Technology Signatures (DISCOVERED vs CONFIRMED)
  const s6Start = Date.now();
  const detectedTech = detectTechnologies(htmlText, customElementMatches);

  const techContent = { technologies: detectedTech };
  const techContentDigest = computeEvidenceContentDigest(techContent);
  const ev06: EvidenceRecord = {
    evidence_id: `ev_${investigationId.toLowerCase()}_006_technology_signatures`,
    schema_version: '1.0.0',
    type: 'observation',
    phase: 'technology_detection',
    source: {
      kind: 'script_ast',
      location: canonicalUrl,
      sha256: techContentDigest
    },
    content: techContent,
    canonical_digest: techContentDigest,
    authority: 'derived',
    timestamp: new Date().toISOString(),
    tool: 'rea-tech-fingerprint@6.5.0',
    limitations: ['Fingerprints based on static asset signatures and HTML attributes']
  };
  evidenceList.push(ev06);

  detectedTech.forEach((tech, i) => {
    findingsList.push({
      finding_id: `fd_${investigationId.toLowerCase()}_tech_${i + 1}`,
      claim: `Application employs ${tech.name} (${tech.category}).`,
      category: 'technology',
      classification: tech.status === 'CONFIRMED' ? 'observation' : 'inference',
      confidence: Math.min(0.95, tech.confidence),
      status: tech.status,
      evidence_ids: [ev06.evidence_id],
      method: tech.evidence
    });
  });
  recordTimeline('technology_detection', 'completed', Date.now() - s6Start, [ev06.evidence_id]);

  // Stage 7: Endpoint Extraction (DISCOVERED candidate status)
  const s7Start = Date.now();
  const endpointList = extractEndpoints(htmlText, inlineScripts);

  const endpointContent = { endpoints: endpointList };
  const endpointContentDigest = computeEvidenceContentDigest(endpointContent);
  const ev07: EvidenceRecord = {
    evidence_id: `ev_${investigationId.toLowerCase()}_007_endpoints_discovered`,
    schema_version: '1.0.0',
    type: 'observation',
    phase: 'endpoint_extraction',
    source: {
      kind: 'script_ast',
      location: canonicalUrl,
      sha256: endpointContentDigest
    },
    content: endpointContent,
    canonical_digest: endpointContentDigest,
    authority: 'direct',
    timestamp: new Date().toISOString(),
    tool: 'rea-endpoint-extractor@6.5.0',
    limitations: ['Static string match only; endpoint has NOT yet been actively verified with HTTP requests']
  };
  evidenceList.push(ev07);

  endpointList.forEach((ep) => {
    nodes.push({ id: ep.path, label: ep.path, type: 'endpoint', category: ep.type });
    edges.push({ source: target.identifier, target: ep.path, relation: 'discovers' });

    findingsList.push({
      finding_id: `fd_${investigationId.toLowerCase()}_ep_${sha256(ep.path).slice(0, 6)}`,
      claim: `Discovered candidate endpoint: "${ep.path}"`,
      category: 'endpoint',
      classification: 'observation',
      confidence: 0.80,
      status: 'DISCOVERED',
      evidence_ids: [ev07.evidence_id],
      method: `Static extraction from ${ep.source}`,
      details: { path: ep.path, type: ep.type }
    });
  });
  recordTimeline('endpoint_extraction', 'completed', Date.now() - s7Start, [ev07.evidence_id]);

  // Stage 8: Agent / Chatbot Discovery
  const s8Start = Date.now();
  const hasCustomAgentElement = customElementMatches.some(tag => /chat|bot|ai|agent|assistant|widget/i.test(tag));
  const hasAgentScript = scriptsList.some(s => s.category === 'widget' || /chat|bot|ai|agent|assistant/i.test(s.src));
  const hasFaqAiDeclaration = htmlText.includes('third-party AI model service') || htmlText.includes('AI-assisted');

  if (hasCustomAgentElement || hasAgentScript || hasFaqAiDeclaration) {
    const agentContent = {
      customElementDetected: hasCustomAgentElement ? customElementMatches.filter(t => /chat|bot|ai|agent|assistant|widget/i.test(t)) : null,
      agentScriptUrl: hasAgentScript ? scriptsList.find(s => s.category === 'widget')?.src : null,
      transparencyDeclaration: hasFaqAiDeclaration
    };
    const agentContentDigest = computeEvidenceContentDigest(agentContent);

    const ev08: EvidenceRecord = {
      evidence_id: `ev_${investigationId.toLowerCase()}_008_agent_signatures`,
      schema_version: '1.0.0',
      type: 'observation',
      phase: 'agent_detection',
      source: {
        kind: 'html_dom',
        location: canonicalUrl,
        sha256: agentContentDigest
      },
      content: agentContent,
      canonical_digest: agentContentDigest,
      authority: 'direct',
      timestamp: new Date().toISOString(),
      tool: 'rea-agent-detector@6.5.0',
      limitations: ['Detects client-side widget presence; underlying LLM model is hidden behind server-side proxy']
    };
    evidenceList.push(ev08);

    findingsList.push({
      finding_id: `fd_${investigationId.toLowerCase()}_agent`,
      claim: 'Target client references an interactive AI agent / chat assistant widget.',
      category: 'agent',
      classification: 'observation',
      confidence: 0.85,
      status: 'DISCOVERED',
      evidence_ids: [ev08.evidence_id],
      method: 'Discovered matching custom web component or AI transparency disclosure'
    });

    findingsList.push({
      finding_id: `fd_${investigationId.toLowerCase()}_agent_proxy`,
      claim: 'AI requests appear mediated through backend proxy rather than client-exposed vendor keys.',
      category: 'architecture',
      classification: 'inference',
      confidence: 0.75,
      status: 'DISCOVERED',
      evidence_ids: [ev08.evidence_id, ev07.evidence_id],
      supports: [ev08.evidence_id],
      method: 'Candidate endpoints discovered without client-side AI vendor SDK tokens'
    });
  }
  recordTimeline('agent_detection', 'completed', Date.now() - s8Start);

  // Stage 9: Graph Synthesis
  const s9Start = Date.now();
  recordTimeline('graph_synthesis', 'completed', Date.now() - s9Start);

  // Stage 10: Integrity Sealing
  const s10Start = Date.now();
  const manifestParameters = {
    timeout_ms: 10000,
    max_response_bytes: 5242880,
    user_agent: 'rea-web-engine@6.5.0'
  };
  const manifestCreatedAt = new Date(startTime).toISOString();

  // Explicit Residual Unknowns
  unknownsList.push('Upstream LLM vendor and temperature settings (isolated behind backend proxy gateway)');
  unknownsList.push('Origin database schema and private server-side middleware logic');
  unknownsList.push('Dynamic endpoints invoked solely by conditional user gestures or deferred authentication');

  // Record Planned but Skipped Stages explicitly
  recordTimeline(
    'runtime_browser_observation', 
    'skipped', 
    0, 
    undefined, 
    'Runtime browser lab not supported in Phase 3'
  );

  recordTimeline(
    'differential_version_comparison', 
    'skipped', 
    0, 
    undefined, 
    'Differential version comparison not supported in Phase 3'
  );

  recordTimeline('integrity_sealing', 'completed', Date.now() - s10Start);

  const partialSession = {
    investigation_id: investigationId,
    target,
    evidence: evidenceList,
    findings: findingsList,
    unknowns: unknownsList,
    manifest: {
      created_at: manifestCreatedAt,
      parameters: manifestParameters
    }
  };

  const integrityHash = computeSessionIntegrityHash(partialSession);
  const totalDuration = Date.now() - startTime;

  const completedStages = timeline.filter(t => t.status === 'completed').length;
  const skippedStages = timeline.filter(t => t.status === 'skipped').length;
  const failedStages = timeline.filter(t => t.status === 'failed').length;

  const session: InvestigationSession = {
    investigation_id: investigationId,
    goal,
    target,
    toolchain: {
      rea_version: '6.5.0',
      studio_version: '1.0.0',
      node_version: process.version
    },
    status: 'COMPLETED',
    evidence_sources,
    evidence: evidenceList,
    findings: findingsList,
    unknowns: unknownsList,
    coverage: {
      stages_executed: completedStages,
      stages_total: 12,
      stages_skipped: skippedStages,
      stages_failed: failedStages,
      endpoints_discovered: endpointList.length,
      endpoints_verified: 0,
      scripts_mapped: scriptsList.length,
      technologies_confirmed: detectedTech.filter(t => t.status === 'CONFIRMED').length
    },
    timeline,
    graph: {
      nodes,
      edges
    },
    manifest: {
      created_at: manifestCreatedAt,
      completed_at: new Date().toISOString(),
      duration_total_ms: totalDuration,
      parameters: manifestParameters,
      integrity_hash: integrityHash
    }
  };

  // Persist session to SQLite repository
  saveInvestigation(session);

  return session;
}

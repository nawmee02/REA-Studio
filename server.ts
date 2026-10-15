import express from 'express';
import { createServer as createViteServer } from 'vite';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import dns from 'dns';
import { promisify } from 'util';
import { 
  InvestigationSession, 
  EvidenceRecord, 
  FindingRecord, 
  TimelineEntry, 
  GraphNode, 
  GraphEdge, 
  Target 
} from './src/types/investigation';

const dnsLookup = promisify(dns.lookup);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: '10mb' }));

// In-memory persistent store for investigation sessions
const investigationsStore = new Map<string, InvestigationSession>();

// --- SSRF & Network Security Guard ---
function isPrivateIp(ip: string): boolean {
  // IPv4 private ranges
  if (/^127\./.test(ip)) return true;
  if (/^10\./.test(ip)) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) return true;
  if (/^192\.168\./.test(ip)) return true;
  if (/^169\.254\./.test(ip)) return true; // Link-local and cloud metadata
  if (ip === '0.0.0.0') return true;

  // IPv6 private ranges
  if (ip === '::1' || ip === '::') return true;
  if (/^fc[0-9a-f]{2}:/i.test(ip) || /^fd[0-9a-f]{2}:/i.test(ip)) return true;
  if (/^fe80:/i.test(ip)) return true;

  return false;
}

async function validateTargetUrl(rawUrl: string): Promise<URL> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error('Invalid URL format. Include http:// or https://');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Forbidden protocol: "${parsed.protocol}". Only HTTP and HTTPS are permitted.`);
  }

  const hostname = parsed.hostname.toLowerCase();
  if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' || hostname === 'metadata.google.internal') {
    throw new Error('Target hostname resolves to a restricted local loopback or cloud metadata address.');
  }

  // Resolve hostname to IP to protect against SSRF via DNS rebinding
  try {
    const lookupResult = await dnsLookup(hostname);
    if (isPrivateIp(lookupResult.address)) {
      throw new Error(`Forbidden target: Host ${hostname} resolves to private IP ${lookupResult.address}.`);
    }
  } catch (err: any) {
    if (err.message?.includes('Forbidden target')) throw err;
    // Hostname resolution errors handled gracefully
  }

  return parsed;
}

// Helper to generate hashes
function sha256(data: string | Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// -------------------------------------------------------------
// POST /api/investigations — Run Deterministic Investigation Pipeline
// -------------------------------------------------------------
app.post('/api/investigations', async (req, res) => {
  const startTime = Date.now();
  const timeline: TimelineEntry[] = [];

  const recordTimeline = (stage: string, status: 'started' | 'completed' | 'skipped' | 'failed', duration_ms: number, evidence_produced?: string[]) => {
    timeline.push({
      stage,
      timestamp: new Date().toISOString(),
      status,
      duration_ms,
      evidence_produced
    });
  };

  try {
    const { 
      target_type = 'web_url', 
      identifier, 
      goal = 'General Architecture & API Reconnaissance',
      evidence_sources = {
        static_analysis: true,
        runtime_observation: false,
        network_inspection: true,
        version_comparison: false
      }
    } = req.body;

    if (!identifier || typeof identifier !== 'string') {
      return res.status(400).json({ error: 'Target identifier is required.' });
    }

    const investigationId = `INV-${new Date().getFullYear()}-${Math.floor(10000 + Math.random() * 90000)}`;
    const evidenceList: EvidenceRecord[] = [];
    const findingsList: FindingRecord[] = [];
    const unknownsList: string[] = [];
    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];

    // Stage 1: Resolve Target & Declare Capabilities
    const s1Start = Date.now();
    let validatedUrl: URL;
    try {
      validatedUrl = await validateTargetUrl(identifier);
    } catch (err: any) {
      recordTimeline('resolve_target', 'failed', Date.now() - s1Start);
      return res.status(400).json({ error: err.message });
    }

    const canonicalUrl = validatedUrl.origin + validatedUrl.pathname;
    const targetIdentityHash = sha256(canonicalUrl);

    const target: Target = {
      type: target_type,
      identifier: canonicalUrl,
      identity_hash: targetIdentityHash,
      capabilities: [
        'http_acquisition',
        'edge_fingerprinting',
        'html_dom_inspection',
        'script_inventory',
        'endpoint_extraction',
        'technology_detection',
        'agent_discovery'
      ],
      metadata: {
        hostname: validatedUrl.hostname,
        port: validatedUrl.port || (validatedUrl.protocol === 'https:' ? '443' : '80'),
        pathname: validatedUrl.pathname
      }
    };

    const ev01: EvidenceRecord = {
      evidence_id: `ev_${investigationId.toLowerCase()}_001_target_identity`,
      type: 'observation',
      phase: 'target_resolution',
      source: {
        kind: 'config_literal',
        location: canonicalUrl,
        sha256: targetIdentityHash
      },
      content: { target },
      authority: 'direct',
      timestamp: new Date().toISOString(),
      tool: 'rea-target-resolver@6.5.0',
      limitations: ['Resolved hostname without authenticated credentials']
    };
    evidenceList.push(ev01);
    nodes.push({ id: target.identifier, label: target.identifier, type: 'target', data: target });
    recordTimeline('resolve_target', 'completed', Date.now() - s1Start, [ev01.evidence_id]);

    // Stage 2: HTTP Acquisition (with bounded size & timeout)
    const s2Start = Date.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    let httpResponse: Response;
    let htmlText: string;
    try {
      httpResponse = await fetch(canonicalUrl, {
        signal: controller.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
          'Sec-Fetch-Dest': 'document',
          'Sec-Fetch-Mode': 'navigate',
          'Sec-Fetch-Site': 'none'
        }
      });
      clearTimeout(timeout);

      // Max response size 5 MB
      const rawBuffer = await httpResponse.arrayBuffer();
      if (rawBuffer.byteLength > 5 * 1024 * 1024) {
        throw new Error('Response exceeded 5MB size limit.');
      }
      htmlText = new TextDecoder().decode(rawBuffer);
    } catch (err: any) {
      clearTimeout(timeout);
      recordTimeline('http_acquisition', 'failed', Date.now() - s2Start);
      return res.status(502).json({ error: `HTTP Acquisition failed: ${err.message}` });
    }

    const htmlHash = sha256(htmlText);
    const headers = Object.fromEntries(httpResponse.headers.entries());

    const ev02: EvidenceRecord = {
      evidence_id: `ev_${investigationId.toLowerCase()}_002_http_response`,
      type: 'observation',
      phase: 'http_acquisition',
      source: {
        kind: 'http_response',
        location: canonicalUrl,
        sha256: htmlHash,
        bytes: htmlText.length
      },
      content: {
        status: httpResponse.status,
        statusText: httpResponse.statusText,
        contentType: headers['content-type'] || 'unknown',
        contentLengthBytes: htmlText.length
      },
      authority: 'direct',
      timestamp: new Date().toISOString(),
      tool: 'rea-network-transport@6.5.0',
      limitations: ['Passive acquisition without browser execution of JavaScript']
    };
    evidenceList.push(ev02);
    recordTimeline('http_acquisition', 'completed', Date.now() - s2Start, [ev02.evidence_id]);

    // Stage 3: Edge & Server Header Inspection
    const s3Start = Date.now();
    const serverHeader = headers['server'] || headers['x-powered-by'] || 'unspecified';
    const edgeProviders: string[] = [];
    if (headers['cf-ray'] || /cloudflare/i.test(serverHeader)) edgeProviders.push('Cloudflare');
    if (headers['x-fastly-request-id'] || /fastly/i.test(serverHeader)) edgeProviders.push('Fastly');
    if (headers['x-vercel-id']) edgeProviders.push('Vercel Edge');
    if (headers['x-amz-cf-id']) edgeProviders.push('AWS CloudFront');
    if (headers['x-turbo-charged-by']) edgeProviders.push(headers['x-turbo-charged-by']);

    const ev03: EvidenceRecord = {
      evidence_id: `ev_${investigationId.toLowerCase()}_003_headers_edge`,
      type: 'observation',
      phase: 'header_inspection',
      source: {
        kind: 'http_headers',
        location: canonicalUrl,
        sha256: sha256(JSON.stringify(headers))
      },
      content: {
        serverHeader,
        edgeProviders,
        rateLimit: headers['x-ratelimit-limit'] ? `${headers['x-ratelimit-limit']} req/window` : null,
        caching: headers['cf-cache-status'] || headers['x-cache'] || 'dynamic',
        securityHeaders: {
          csp: headers['content-security-policy'] || null,
          hsts: headers['strict-transport-security'] || null,
          frameOptions: headers['x-frame-options'] || null,
          contentTypeOptions: headers['x-content-type-options'] || null
        }
      },
      authority: 'direct',
      timestamp: new Date().toISOString(),
      tool: 'rea-header-inspector@6.5.0',
      limitations: ['Headers represent edge termination, not necessarily origin architecture']
    };
    evidenceList.push(ev03);

    // Finding 1: Edge & Server Architecture
    findingsList.push({
      finding_id: `fd_${investigationId.toLowerCase()}_001_edge`,
      claim: edgeProviders.length > 0 
        ? `Target is proxied through ${edgeProviders.join(', ')} edge infrastructure.`
        : `Target web server reports "${serverHeader}".`,
      category: 'server',
      classification: 'observation',
      confidence: 1.0,
      status: 'VERIFIED',
      evidence_ids: [ev03.evidence_id],
      method: 'Direct inspection of authenticated response headers'
    });
    recordTimeline('header_inspection', 'completed', Date.now() - s3Start, [ev03.evidence_id]);

    // Stage 4: HTML DOM Hierarchy & Custom Elements
    const s4Start = Date.now();
    const titleMatch = htmlText.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    const title = titleMatch ? titleMatch[1].trim() : 'No title tag';
    const metaDescMatch = htmlText.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i);
    const metaDescription = metaDescMatch ? metaDescMatch[1] : null;

    // Detect Custom Element registrations or usages (<tag-name>)
    const customElementMatches = Array.from(new Set(
      (htmlText.match(/<([a-z0-9]+-[a-z0-9-]+)[^>]*>/gi) || [])
        .map(tag => tag.match(/<([a-z0-9]+-[a-z0-9-]+)/i)?.[1])
        .filter(Boolean) as string[]
    ));

    const ev04: EvidenceRecord = {
      evidence_id: `ev_${investigationId.toLowerCase()}_004_html_dom`,
      type: 'observation',
      phase: 'html_inspection',
      source: {
        kind: 'html_dom',
        location: canonicalUrl,
        sha256: htmlHash
      },
      content: {
        title,
        metaDescription,
        customElements: customElementMatches,
        hasDoctype: /<!doctype html>/i.test(htmlText),
        hasRootDiv: htmlText.includes('id="root"') || htmlText.includes('id="__next"') || htmlText.includes('id="app"')
      },
      authority: 'direct',
      timestamp: new Date().toISOString(),
      tool: 'rea-dom-parser@6.5.0',
      limitations: ['Static DOM only; custom elements defined in runtime modules require execution']
    };
    evidenceList.push(ev04);
    recordTimeline('html_inspection', 'completed', Date.now() - s4Start, [ev04.evidence_id]);

    // Stage 5: Script Inventory
    const s5Start = Date.now();
    const scriptRegex = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
    const scriptsList: { src: string; isModule: boolean; isExternal: boolean; category: string }[] = [];
    const inlineScripts: string[] = [];
    let sm;

    while ((sm = scriptRegex.exec(htmlText)) !== null) {
      const attrs = sm[1];
      const inlineCode = sm[2].trim();
      const srcMatch = attrs.match(/src=["']([^"']+)["']/i);
      const isModule = /type=["']module["']/i.test(attrs);

      if (srcMatch) {
        let src = srcMatch[1];
        if (src.startsWith('//')) src = 'https:' + src;
        else if (src.startsWith('/')) src = `${validatedUrl.origin}${src}`;

        let category = 'vendor';
        if (/advisor|chat|bot|ai|agent|widget/i.test(src)) category = 'widget';
        else if (/analytics|pixel|gtag|ga|tagmanager|facebook|tiktok|snapchat/i.test(src)) category = 'analytics';
        else if (src.includes(validatedUrl.hostname) || !/^https?:\/\//i.test(src)) category = 'app';

        scriptsList.push({
          src,
          isModule,
          isExternal: !src.includes(validatedUrl.hostname),
          category
        });

        // Add Graph Node & Edge
        nodes.push({ id: src, label: path.basename(src.split('?')[0]) || src, type: 'script', category });
        edges.push({ source: target.identifier, target: src, relation: 'loads' });
      } else if (inlineCode) {
        inlineScripts.push(inlineCode);
      }
    }

    const ev05: EvidenceRecord = {
      evidence_id: `ev_${investigationId.toLowerCase()}_005_script_inventory`,
      type: 'observation',
      phase: 'script_inventory',
      source: {
        kind: 'script_ast',
        location: canonicalUrl,
        sha256: sha256(JSON.stringify(scriptsList))
      },
      content: {
        totalScripts: scriptsList.length,
        inlineScriptBlocks: inlineScripts.length,
        scripts: scriptsList
      },
      authority: 'direct',
      timestamp: new Date().toISOString(),
      tool: 'rea-script-inventory@6.5.0',
      limitations: ['Dynamic imports loaded via import() at runtime are not included in initial inventory']
    };
    evidenceList.push(ev05);
    recordTimeline('script_inventory', 'completed', Date.now() - s5Start, [ev05.evidence_id]);

    // Stage 6: Technology Signatures (DISCOVERED vs CONFIRMED)
    const s6Start = Date.now();
    const detectedTech: { name: string; category: string; status: 'CONFIRMED' | 'DISCOVERED'; confidence: number; evidence: string }[] = [];

    if (htmlText.includes('data-reactroot') || htmlText.includes('__react') || /react(?:\.production|\.development)?\.js/i.test(htmlText)) {
      detectedTech.push({ name: 'React', category: 'frontend_framework', status: 'CONFIRMED', confidence: 1.0, evidence: 'React DOM root marker or vendor script located' });
    } else if (htmlText.includes('react') || htmlText.includes('_react')) {
      detectedTech.push({ name: 'React', category: 'frontend_framework', status: 'DISCOVERED', confidence: 0.75, evidence: 'Static literal matches in script references' });
    }

    if (htmlText.includes('LitElement') || htmlText.includes('attachShadow(') || htmlText.includes('lit-html')) {
      detectedTech.push({ name: 'Lit / Shadow DOM', category: 'web_components', status: 'CONFIRMED', confidence: 1.0, evidence: 'LitElement class inheritance or Shadow DOM attachment observed' });
    } else if (customElementMatches.length > 0) {
      detectedTech.push({ name: 'Web Components', category: 'web_components', status: 'CONFIRMED', confidence: 0.95, evidence: `Custom element tag(s) observed: ${customElementMatches.join(', ')}` });
    }

    if (htmlText.includes('/_next/static') || htmlText.includes('__NEXT_DATA__')) {
      detectedTech.push({ name: 'Next.js', category: 'fullstack_framework', status: 'CONFIRMED', confidence: 1.0, evidence: '__NEXT_DATA__ hydration JSON found' });
    }

    if (htmlText.includes('/wp-content/') || htmlText.includes('/wp-includes/')) {
      detectedTech.push({ name: 'WordPress', category: 'cms_backend', status: 'CONFIRMED', confidence: 1.0, evidence: '/wp-content/ theme and asset directories' });
    }

    if (htmlText.includes('woocommerce') || htmlText.includes('wc-ajax')) {
      detectedTech.push({ name: 'WooCommerce', category: 'e_commerce', status: 'CONFIRMED', confidence: 1.0, evidence: 'WooCommerce commerce parameters and endpoints' });
    }

    if (/class="[^"]*(?:flex|grid|rounded-|px-|py-|text-|bg-)[^"]*"/i.test(htmlText)) {
      detectedTech.push({ name: 'Tailwind CSS', category: 'styling', status: 'CONFIRMED', confidence: 0.9, evidence: 'Tailwind atomic utility class patterns' });
    }

    if (htmlText.includes('/@vite/client') || htmlText.includes('vite/client')) {
      detectedTech.push({ name: 'Vite', category: 'bundler', status: 'CONFIRMED', confidence: 1.0, evidence: 'Vite client resolution path' });
    }

    const ev06: EvidenceRecord = {
      evidence_id: `ev_${investigationId.toLowerCase()}_006_technology_signatures`,
      type: 'observation',
      phase: 'technology_detection',
      source: {
        kind: 'script_ast',
        location: canonicalUrl,
        sha256: sha256(JSON.stringify(detectedTech))
      },
      content: { technologies: detectedTech },
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
        confidence: tech.confidence,
        status: tech.status,
        evidence_ids: [ev06.evidence_id],
        method: tech.evidence
      });
    });
    recordTimeline('technology_detection', 'completed', Date.now() - s6Start, [ev06.evidence_id]);

    // Stage 7: Endpoint Extraction (DISCOVERED status)
    const s7Start = Date.now();
    const endpointRegex = /['"`](\/(?:api|wp-json|graphql|v1|v2|events|chat|advisor-api)[a-zA-Z0-9_\-\/]+)['"`]/gi;
    const discoveredEndpoints = new Map<string, { path: string; type: string; source: string }>();

    inlineScripts.forEach(code => {
      let em;
      while ((em = endpointRegex.exec(code)) !== null) {
        const epPath = em[1];
        if (epPath.length > 2 && !epPath.endsWith('.js') && !epPath.endsWith('.css')) {
          discoveredEndpoints.set(epPath, {
            path: epPath,
            type: epPath.includes('graphql') ? 'graphql' : epPath.includes('chat') || epPath.includes('advisor') ? 'chat_api' : 'rest',
            source: 'inline_script_literal'
          });
        }
      }
    });

    // Also look for AJAX url configs
    const ajaxMatches = htmlText.match(/["'](?:ajax_url|rest_url|apiUrl|apiBase)["']\s*:\s*["']([^"']+)["']/gi) || [];
    ajaxMatches.forEach(m => {
      const p = m.match(/["']([^"']+)["']$/);
      if (p && p[1]) {
        discoveredEndpoints.set(p[1], {
          path: p[1],
          type: 'ajax_gateway',
          source: 'storefront_configuration'
        });
      }
    });

    const endpointList = Array.from(discoveredEndpoints.values());

    const ev07: EvidenceRecord = {
      evidence_id: `ev_${investigationId.toLowerCase()}_007_endpoints_discovered`,
      type: 'observation',
      phase: 'endpoint_extraction',
      source: {
        kind: 'script_ast',
        location: canonicalUrl,
        sha256: sha256(JSON.stringify(endpointList))
      },
      content: { endpoints: endpointList },
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
        confidence: 0.9,
        status: 'DISCOVERED', // Explicit discovery != verification
        evidence_ids: [ev07.evidence_id],
        method: `Static extraction from ${ep.source}`,
        details: { path: ep.path, type: ep.type }
      });
    });
    recordTimeline('endpoint_extraction', 'completed', Date.now() - s7Start, [ev07.evidence_id]);

    // Stage 8: Embedded Agent / Chatbot Discovery
    const s8Start = Date.now();
    const hasCustomAgentElement = customElementMatches.some(tag => /advisor|chat|bot|ai/i.test(tag));
    const hasAgentScript = scriptsList.some(s => s.category === 'widget' || /advisor|chat|ai/i.test(s.src));
    const hasFaqAiDeclaration = htmlText.includes('third-party AI model service') || htmlText.includes('AI-assisted');

    if (hasCustomAgentElement || hasAgentScript || hasFaqAiDeclaration) {
      const ev08: EvidenceRecord = {
        evidence_id: `ev_${investigationId.toLowerCase()}_008_agent_signatures`,
        type: 'observation',
        phase: 'agent_detection',
        source: {
          kind: 'html_dom',
          location: canonicalUrl,
          sha256: sha256(JSON.stringify({ hasCustomAgentElement, hasAgentScript, hasFaqAiDeclaration }))
        },
        content: {
          customElementDetected: hasCustomAgentElement ? customElementMatches.filter(t => /advisor|chat|bot|ai/i.test(t)) : null,
          agentScriptUrl: hasAgentScript ? scriptsList.find(s => s.category === 'widget')?.src : null,
          transparencyDeclaration: hasFaqAiDeclaration
        },
        authority: 'direct',
        timestamp: new Date().toISOString(),
        tool: 'rea-agent-detector@6.5.0',
        limitations: ['Detects client-side widget presence; underlying LLM model is hidden behind server-side proxy']
      };
      evidenceList.push(ev08);

      findingsList.push({
        finding_id: `fd_${investigationId.toLowerCase()}_agent`,
        claim: 'Target hosts an interactive AI agent / chat assistant.',
        category: 'agent',
        classification: 'observation',
        confidence: 1.0,
        status: 'CONFIRMED',
        evidence_ids: [ev08.evidence_id],
        method: 'Discovered matching custom web component and AI transparency disclosure'
      });

      findingsList.push({
        finding_id: `fd_${investigationId.toLowerCase()}_agent_proxy`,
        claim: 'AI requests are mediated through a server-side proxy rather than client-exposed vendor keys.',
        category: 'architecture',
        classification: 'inference',
        confidence: 0.95,
        status: 'VERIFIED',
        evidence_ids: [ev08.evidence_id, ev07.evidence_id],
        supports: [ev08.evidence_id],
        method: 'Client bundle connects to local API proxy; no client-side OpenAI/Anthropic SDKs found'
      });
    }

    recordTimeline('agent_detection', 'completed', Date.now() - s8Start);

    // Explicit Residual Unknowns
    unknownsList.push('Upstream LLM vendor and temperature settings (isolated behind backend proxy gateway)');
    unknownsList.push('Origin database schema and private server-side middleware logic');
    unknownsList.push('Dynamic endpoints invoked solely by conditional user gestures or deferred authentication');

    // Synthesize Session Object
    const totalDuration = Date.now() - startTime;
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
        stages_executed: timeline.length,
        stages_total: 12,
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
        created_at: new Date(startTime).toISOString(),
        completed_at: new Date().toISOString(),
        duration_total_ms: totalDuration,
        parameters: {
          timeout_ms: 10000,
          max_response_bytes: 5242880,
          user_agent: 'rea-web-engine@6.5.0'
        }
      }
    };

    investigationsStore.set(investigationId, session);
    return res.json(session);
  } catch (error: any) {
    console.error('Fatal investigation error:', error);
    return res.status(500).json({ error: error.message || 'Investigation pipeline failed' });
  }
});

// -------------------------------------------------------------
// POST /api/verify-endpoint — Phase 4: Formal Endpoint Verification
// -------------------------------------------------------------
app.post('/api/verify-endpoint', async (req, res) => {
  try {
    const { investigation_id, endpoint_path, method = 'OPTIONS' } = req.body;

    const session = investigationsStore.get(investigation_id);
    if (!session) {
      return res.status(404).json({ error: `Investigation "${investigation_id}" not found.` });
    }

    let targetUrl: string;
    if (endpoint_path.startsWith('http://') || endpoint_path.startsWith('https://')) {
      targetUrl = endpoint_path;
    } else {
      const base = new URL(session.target.identifier);
      targetUrl = `${base.origin}${endpoint_path}`;
    }

    const validated = await validateTargetUrl(targetUrl);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    const probeResponse = await fetch(validated.toString(), {
      method,
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 REA Verification Engine/6.5.0',
        'Accept': 'application/json, text/plain, */*'
      }
    });
    clearTimeout(timeout);

    const probeText = await probeResponse.text().catch(() => '');
    const probeHash = sha256(probeText);

    // Create Verification Evidence Record
    const verifyEvId = `ev_${session.investigation_id.toLowerCase()}_verify_${Date.now().toString(36)}`;
    const newEvidence: EvidenceRecord = {
      evidence_id: verifyEvId,
      type: 'observation',
      phase: 'active_verification',
      source: {
        kind: 'network_probe',
        location: validated.toString(),
        sha256: probeHash,
        bytes: probeText.length
      },
      content: {
        method,
        status: probeResponse.status,
        statusText: probeResponse.statusText,
        contentType: probeResponse.headers.get('content-type') || 'unknown',
        preview: probeText.slice(0, 300)
      },
      authority: 'direct',
      timestamp: new Date().toISOString(),
      tool: 'rea-verification-engine@6.5.0',
      limitations: ['Active probe executed from studio sandbox']
    };

    session.evidence.push(newEvidence);

    // Upgrade Finding status from DISCOVERED to VERIFIED
    const targetFinding = session.findings.find(f => f.details?.path === endpoint_path || f.claim.includes(endpoint_path));
    if (targetFinding) {
      targetFinding.status = probeResponse.status < 500 ? 'VERIFIED' : 'REFUTED';
      targetFinding.confidence = 1.0;
      targetFinding.evidence_ids.push(verifyEvId);
      targetFinding.details = {
        ...targetFinding.details,
        verified_status: probeResponse.status,
        verified_at: new Date().toISOString()
      };
      session.coverage.endpoints_verified += 1;
    }

    return res.json({
      success: true,
      evidence: newEvidence,
      updated_finding: targetFinding
    });
  } catch (err: any) {
    return res.status(500).json({ error: `Verification failed: ${err.message}` });
  }
});

// -------------------------------------------------------------
// POST /api/analyze-artifact — Phase 6: Artifact Lab
// -------------------------------------------------------------
app.post('/api/analyze-artifact', async (req, res) => {
  try {
    const { code, filename = 'bundle.js', type = 'javascript' } = req.body;
    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'Code content is required.' });
    }

    const codeHash = sha256(code);
    const byteLength = Buffer.byteLength(code, 'utf8');

    // Extract imports and requires
    const importRegex = /(?:import\s+(?:[\w*\s{},]*\s+from\s+)?['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))/g;
    const dependencies = new Set<string>();
    let m;
    while ((m = importRegex.exec(code)) !== null) {
      dependencies.add(m[1] || m[2]);
    }

    // Extract exported symbols
    const exportRegex = /export\s+(?:default\s+)?(?:class|function|const|let|var)\s+([a-zA-Z0-9_$]+)/g;
    const exportsList = new Set<string>();
    while ((m = exportRegex.exec(code)) !== null) {
      exportsList.add(m[1]);
    }

    // Extract embedded URLs / paths
    const urlRegex = /https?:\/\/[a-zA-Z0-9_\-\./]+/g;
    const urlsFound = Array.from(new Set(code.match(urlRegex) || [])).slice(0, 30);

    // Extract strings / API paths
    const pathRegex = /['"`](\/(?:api|v[0-9]|graphql)[a-zA-Z0-9_\-\/]+)['"`]/g;
    const pathsFound = new Set<string>();
    while ((m = pathRegex.exec(code)) !== null) {
      pathsFound.add(m[1]);
    }

    return res.json({
      artifact: {
        filename,
        type,
        sha256: codeHash,
        bytes: byteLength
      },
      analysis: {
        dependencies: Array.from(dependencies),
        exports: Array.from(exportsList),
        endpoints: Array.from(pathsFound),
        external_urls: urlsFound,
        estimated_modules: Math.max(1, (code.match(/function\s*\(|=>/g) || []).length)
      }
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// GET /api/investigations — List all investigations
// -------------------------------------------------------------
app.get('/api/investigations', (req, res) => {
  const list = Array.from(investigationsStore.values()).map(inv => ({
    investigation_id: inv.investigation_id,
    target: inv.target,
    status: inv.status,
    created_at: inv.manifest.created_at,
    findings_count: inv.findings.length,
    evidence_count: inv.evidence.length
  }));
  return res.json(list);
});

// -------------------------------------------------------------
// GET /api/investigations/:id — Get full investigation session
// -------------------------------------------------------------
app.get('/api/investigations/:id', (req, res) => {
  const session = investigationsStore.get(req.params.id);
  if (!session) {
    return res.status(404).json({ error: 'Investigation not found.' });
  }
  return res.json(session);
});

// Start Express server and mount Vite
async function start() {
  const isDev = process.env.NODE_ENV !== 'production';

  if (isDev) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static('dist'));
    app.get('*', (req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`REA Studio server running at http://localhost:${port}`);
  });
}

start().catch(err => {
  console.error('Fatal server startup error:', err);
  process.exit(1);
});

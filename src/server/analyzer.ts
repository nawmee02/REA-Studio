import crypto from 'crypto';
import path from 'path';

export function sha256(data: string | Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export interface TechnologyMatch {
  name: string;
  category: string;
  status: 'CONFIRMED' | 'DISCOVERED';
  confidence: number;
  evidence: string;
}

/**
 * Deterministic technology detection based on static markers and signatures.
 */
export function detectTechnologies(htmlText: string, customElements: string[] = []): TechnologyMatch[] {
  const matches: TechnologyMatch[] = [];

  // React
  if (htmlText.includes('data-reactroot') || htmlText.includes('__react') || /react(?:\.production|\.development)?\.js/i.test(htmlText)) {
    matches.push({ name: 'React', category: 'frontend_framework', status: 'CONFIRMED', confidence: 1.0, evidence: 'React DOM root marker or vendor script located' });
  } else if (htmlText.includes('react') || htmlText.includes('_react')) {
    matches.push({ name: 'React', category: 'frontend_framework', status: 'DISCOVERED', confidence: 0.75, evidence: 'Static literal matches in script references' });
  }

  // Lit / Web Components
  if (htmlText.includes('LitElement') || htmlText.includes('attachShadow(') || htmlText.includes('lit-html')) {
    matches.push({ name: 'Lit / Shadow DOM', category: 'web_components', status: 'CONFIRMED', confidence: 1.0, evidence: 'LitElement class inheritance or Shadow DOM attachment observed' });
  }
  if (customElements.length > 0) {
    matches.push({ name: 'Web Components', category: 'web_components', status: 'CONFIRMED', confidence: 0.95, evidence: `Custom element tag(s) observed: ${customElements.join(', ')}` });
  }

  // Next.js
  if (htmlText.includes('/_next/static') || htmlText.includes('__NEXT_DATA__')) {
    matches.push({ name: 'Next.js', category: 'fullstack_framework', status: 'CONFIRMED', confidence: 1.0, evidence: '__NEXT_DATA__ hydration JSON found' });
  }

  // WordPress
  if (htmlText.includes('/wp-content/') || htmlText.includes('/wp-includes/')) {
    matches.push({ name: 'WordPress', category: 'cms_backend', status: 'CONFIRMED', confidence: 1.0, evidence: '/wp-content/ theme and asset directories' });
  }

  // WooCommerce
  if (htmlText.includes('woocommerce') || htmlText.includes('wc-ajax')) {
    matches.push({ name: 'WooCommerce', category: 'e_commerce', status: 'CONFIRMED', confidence: 1.0, evidence: 'WooCommerce commerce parameters and endpoints' });
  }

  // Tailwind CSS
  if (/class="[^"]*(?:flex|grid|rounded-|px-|py-|text-|bg-)[^"]*"/i.test(htmlText)) {
    matches.push({ name: 'Tailwind CSS', category: 'styling', status: 'CONFIRMED', confidence: 0.9, evidence: 'Tailwind atomic utility class patterns' });
  }

  // Vite
  if (htmlText.includes('/@vite/client') || htmlText.includes('vite/client')) {
    matches.push({ name: 'Vite', category: 'bundler', status: 'CONFIRMED', confidence: 1.0, evidence: 'Vite client resolution path' });
  }

  return matches;
}

export interface EndpointMatch {
  path: string;
  type: string;
  source: string;
}

/**
 * Deterministic API and AJAX endpoint discovery from script literals.
 */
export function extractEndpoints(htmlText: string, inlineScripts: string[] = []): EndpointMatch[] {
  const discovered = new Map<string, EndpointMatch>();
  const endpointRegex = /['"`](\/(?:api|wp-json|graphql|v1|v2|events|chat)[a-zA-Z0-9_\-\/]+)['"`]/gi;

  const allCodeBlocks = [...inlineScripts, htmlText];

  for (const block of allCodeBlocks) {
    let em;
    while ((em = endpointRegex.exec(block)) !== null) {
      const epPath = em[1];
      if (epPath.length > 2 && !epPath.endsWith('.js') && !epPath.endsWith('.css') && !discovered.has(epPath)) {
        discovered.set(epPath, {
          path: epPath,
          type: epPath.includes('graphql') ? 'graphql' : epPath.includes('chat') ? 'chat_api' : 'rest',
          source: 'script_string_literal'
        });
      }
    }
  }

  // Configuration parameter search
  const ajaxMatches = htmlText.match(/["'](?:ajax_url|rest_url|apiUrl|apiBase)["']\s*:\s*["']([^"']+)["']/gi) || [];
  for (const m of ajaxMatches) {
    const p = m.match(/["']([^"']+)["']$/);
    if (p && p[1] && !discovered.has(p[1])) {
      discovered.set(p[1], {
        path: p[1],
        type: 'ajax_gateway',
        source: 'storefront_configuration'
      });
    }
  }

  return Array.from(discovered.values());
}

export interface ScriptInventoryItem {
  src: string;
  isModule: boolean;
  isExternal: boolean;
  category: string;
}

/**
 * Extracts and categorizes all external script tags and inline blocks.
 */
export function analyzeScriptInventory(htmlText: string, targetOrigin: string): {
  scripts: ScriptInventoryItem[];
  inlineScripts: string[];
} {
  const scriptRegex = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  const scripts: ScriptInventoryItem[] = [];
  const inlineScripts: string[] = [];
  let sm;

  const targetHost = new URL(targetOrigin).hostname;

  while ((sm = scriptRegex.exec(htmlText)) !== null) {
    const attrs = sm[1];
    const inlineCode = sm[2].trim();
    const srcMatch = attrs.match(/src=["']([^"']+)["']/i);
    const isModule = /type=["']module["']/i.test(attrs);

    if (srcMatch) {
      let src = srcMatch[1];
      if (src.startsWith('//')) src = 'https:' + src;
      else if (src.startsWith('/')) src = `${targetOrigin.replace(/\/$/, '')}${src}`;

      let category = 'vendor';
      if (/chat|bot|ai|agent|widget|assistant/i.test(src)) category = 'widget';
      else if (/analytics|pixel|gtag|ga|tagmanager|facebook|tiktok|snapchat/i.test(src)) category = 'analytics';
      else if (src.includes(targetHost) || !/^https?:\/\//i.test(src)) category = 'app';

      scripts.push({
        src,
        isModule,
        isExternal: !src.includes(targetHost),
        category
      });
    } else if (inlineCode) {
      inlineScripts.push(inlineCode);
    }
  }

  return { scripts, inlineScripts };
}

export interface ArtifactAnalysisResult {
  artifact: {
    filename: string;
    type: string;
    sha256: string;
    bytes: number;
  };
  analysis: {
    dependencies: string[];
    exports: string[];
    endpoints: string[];
    external_urls: string[];
    estimated_modules: number;
  };
}

/**
 * Analyzes JavaScript/TS code or bundle with strict path traversal and resource limits.
 */
export function analyzeArtifactCode(code: string, filename: string = 'bundle.js', type: string = 'javascript'): ArtifactAnalysisResult {
  if (!code || typeof code !== 'string') {
    throw new Error('Code content is required.');
  }

  const byteLength = Buffer.byteLength(code, 'utf8');
  if (byteLength > 10 * 1024 * 1024) {
    throw new Error('Artifact exceeds maximum 10MB limit.');
  }

  // Path traversal check
  if (filename.includes('..') || filename.startsWith('/') || filename.includes('\\')) {
    throw new Error('Prohibited filename: Path traversal characters detected.');
  }

  const sanitizedFilename = path.basename(filename);
  const codeHash = sha256(code);

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

  // Extract embedded URLs
  const urlRegex = /https?:\/\/[a-zA-Z0-9_\-\./]+/g;
  const urlsFound = Array.from(new Set(code.match(urlRegex) || [])).slice(0, 30);

  // Extract candidate string paths
  const pathRegex = /['"`](\/(?:api|v[0-9]|graphql)[a-zA-Z0-9_\-\/]+)['"`]/g;
  const pathsFound = new Set<string>();
  while ((m = pathRegex.exec(code)) !== null) {
    pathsFound.add(m[1]);
  }

  return {
    artifact: {
      filename: sanitizedFilename,
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
  };
}

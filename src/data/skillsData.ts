export interface ReaSkill {
  id: string;
  name: string;
  title: string;
  version?: string;
  description: string;
  category: 'core' | 'development' | 'quality' | 'release';
  badge: string;
  content: string;
  references?: {
    id: string;
    title: string;
    description: string;
    filename: string;
    content: string;
  }[];
}

export interface ReaCommand {
  name: string;
  summary: string;
  category: 'javascript' | 'web' | 'native' | 'android' | 'setup';
  description: string;
  syntax: string;
  example: string;
  options: {
    flag: string;
    description: string;
    default?: string;
  }[];
}

export const REA_SKILLS: ReaSkill[] = [
  {
    id: 'reverse-engineer-anything',
    name: 'reverse-engineer-anything',
    title: 'Reverse Engineer Anything (REA)',
    version: '42',
    category: 'core',
    badge: 'Primary Skill',
    description: 'Reverse engineer native, managed, Electron/JavaScript, packaged, firmware, and browser targets with REA. Use shipped-artifact or requested runtime evidence to explain features, compare versions, decompile code, or guide a reconstruction.',
    content: `# Reverse Engineer Anything (REA)

Use REA when a claim depends on a shipped binary or package, decompilation, passive application runtime evidence, or comparison with behavior not established by available source.

## Connect only when needed
Installing this skill supplies instructions; it does not register the REA MCP server, install analysis engines, or add tools to an already-running agent. If REA tools are available and their registration is not known to be stale, proceed directly to the target.

## Core Directives
1. **Distinguish Facts from Inferences**: Every conclusion must separate *observations* (concrete static/runtime output), *derivations* (direct logical steps), and *inferences/hypotheses*.
2. **Preserve Limitations and Incomplete Coverage**: Note bounded negative searches and unsupported features.
3. **No Execution Without Explicit Target**: Never run binaries or scripts without designated target path and permissions.
4. **Evidence Provenance**: Cite Evidence IDs for all architectural claims and functional summaries.

## Work Summary-First
- For large JavaScript applications or ELF/Mach-O layouts, call \`analyze_javascript_application\` or \`inspect_binary_layout\` with \`"detail": "summary"\`.
- Inspect the retained \`parent_evidence_id\` with \`inspect_analysis_view\`.
- Decompose complex reverse engineering tasks into targeted questions with defined evidence requirements.`,
    references: [
      {
        id: 'javascript-applications',
        title: 'JavaScript & Electron Applications',
        filename: 'javascript-applications.md',
        description: 'ASAR archives, extracted JavaScript bundles, webpack/vite runtime reconciliation, and feature tracing.',
        content: `### JavaScript & Electron Applications

REA inspects packaged JavaScript applications (Webpack bundles, ASAR packages, minified scripts) without needing original source code:

1. **ASAR & Archive Extraction**:
   - \`rea analyze-javascript-application <path-to-app-or-asar> --detail summary\`
   - Analyzes entry points, dependency trees, and embedded licenses.
2. **Source Recovery**:
   - \`rea recover-javascript-sources <path> --output-dir <recovered-dir>\`
   - Reconstructs readable modules while maintaining source provenance.
3. **Semantic Tracing**:
   - Trace function calls, event handlers, and data transformations through minified identifiers.`
      },
      {
        id: 'native-and-artifacts',
        title: 'Native Binaries & Artifacts',
        filename: 'native-and-artifacts.md',
        description: 'Mach-O, ELF, PE binaries, Hopper/Ghidra/IDA integrations, decompilation, and calling convention analysis.',
        content: `### Native Binaries & Artifacts

REA connects agents to deep analysis engines (Ghidra, Hopper, IDA, objdump, LLDB):

1. **Binary Layout**:
   - Inspect section headers, symbol tables, imported libraries, and exported interfaces.
2. **Static Decompilation**:
   - Extract C-like pseudocode and assembly without launching heavyweight interactive GUIs.
3. **Memory & Byte Pattern Searches**:
   - Search strings, cryptokeys, API tokens, and masked instruction patterns.`
      },
      {
        id: 'runtime-observation',
        title: 'Runtime Observation & CDP',
        filename: 'runtime-observation.md',
        description: 'Browser and Electron runtime observation, Chrome DevTools Protocol (CDP), and network reconciliation.',
        content: `### Runtime Observation

Observe applications dynamically via Chrome DevTools Protocol (CDP) or Node V8 Inspector:

1. **Passive Page Inspection**:
   - Attach to loopback browsers to inventory event listeners, DOM mutation trees, and active workers.
2. **Network & Protocol Replay**:
   - Inspect captured HAR, mitmproxy, or WebSocket frames.
3. **Static & Runtime Reconciliation**:
   - Correlate runtime network endpoints with static bundle call sites.`
      },
      {
        id: 'android-applications',
        title: 'Android Applications (APK/AAB)',
        filename: 'android-applications.md',
        description: 'DEX bytecode inspection, AndroidManifest.xml analysis, and exported component auditing.',
        content: `### Android Applications

Decompile and audit Android APKs:

1. **APK Graph Projection**:
   - Maps Activities, Services, Broadcast Receivers, and Content Providers.
2. **Bytecode Search**:
   - Query classes, methods, and intents.
3. **Device Inspection**:
   - Query connected ADB targets, inspect system services, and capture logcat.`
      },
      {
        id: 'evidence-workflows',
        title: 'Evidence Workflows & Bundles',
        filename: 'evidence-workflows.md',
        description: 'Evidence ledger management, pagination, parent-child relations, and reproducible reports.',
        content: `### Evidence Workflows

Every REA analysis emits cryptographic Evidence objects with stable IDs:

- **Evidence ID**: Unique SHA-based node identifier.
- **Provenance**: Records the exact analyzer version, provider engine, and target file hash.
- **Observations vs Inferences**: Guarantees facts are strictly segregated from AI assumptions.`
      },
      {
        id: 'connection-and-recovery',
        title: 'Connection & Provider Recovery',
        filename: 'connection-and-recovery.md',
        description: 'MCP server setup, provider troubleshooting (Ghidra, Hopper, IDA, JADX), and agent registration.',
        content: `### Connection & Provider Setup

Troubleshoot and register REA across your AI tooling:

- \`npx rea-agents setup --yes\`: Automatically detects and registers MCP endpoints with Claude Code, Cursor, Codex, Gemini CLI, and Antigravity.
- Environment variables: \`GHIDRA_INSTALL_DIR\`, \`REA_IDA_MCP_CONFIG\`, \`REA_JADX_MCP_JAR\`.`
      }
    ]
  },
  {
    id: 'rea-tool-design',
    name: 'rea-tool-design',
    title: 'REA Tool Design & Semantics',
    category: 'development',
    badge: 'Tooling Contract',
    description: 'Design or change REA investigation tools, CLI/MCP contracts, provider capabilities, and Evidence semantics.',
    content: `# REA Tool Design

Use this skill when designing or expanding REA capabilities, MCP schemas, or CLI commands:

## Design Principles
- **Fail-Closed Integration**: Refuse undefined behavior; missing capabilities must return clear error classifications.
- **Provider Isolation**: Analysis providers (Hopper, Ghidra, Frida) are decoupled from agent-facing protocols.
- **Additive & Idempotent**: Tool invocations should never destructively mutate target user environments.
- **Output Streaming**: Large binary dumps must support paging (\`--token-limit\`, \`--filter-output\`, \`--detail summary\`).`
  },
  {
    id: 'rea-ci-tests-audit',
    name: 'rea-ci-tests-audit',
    title: 'REA CI & Test Audit',
    category: 'quality',
    badge: 'Verification',
    description: 'Audit REA CI and test suites for correctness, fixture drift, false passes, and measured performance.',
    content: `# REA CI and Tests Audit

Audit and maintain test suites across REA:
- Static analysis test fixtures.
- Decompiler regression baselines.
- Mutation testing suites (Stryker).
- End-to-end MCP protocol validations.`
  },
  {
    id: 'rea-changelog-update',
    name: 'rea-changelog-update',
    title: 'REA Changelog & Releases',
    category: 'release',
    badge: 'Automation',
    description: 'Maintain release changelogs, categorize pull requests, and ensure verifiable release provenance.',
    content: `# REA Changelog Update

Automates semantic changelog management, separating breaking changes, provider updates, and agent protocol improvements.`
  }
];

export const REA_COMMANDS: ReaCommand[] = [
  {
    name: 'analyze-javascript-application',
    summary: 'Analyze JS/Electron apps without source code',
    category: 'javascript',
    description: 'Performs static analysis on unpacked JS apps, Electron bundles, or single bundles to identify entry points, module graphs, and key features.',
    syntax: 'rea analyze-javascript-application <path> [options]',
    example: 'npx rea-agents analyze-javascript-application ./dist --detail summary --format json',
    options: [
      { flag: '--detail', description: 'Analysis depth: summary, detailed, full', default: 'summary' },
      { flag: '--format', description: 'Output format: json, toon, yaml, md', default: 'json' },
      { flag: '--token-limit', description: 'Truncate output to token budget', default: '4000' }
    ]
  },
  {
    name: 'recover-javascript-sources',
    summary: 'De-bundle & recover readable JS modules',
    category: 'javascript',
    description: 'Extracts bundled JavaScript into separate source files with provenance tracking, source-map alignment, and formatting.',
    syntax: 'rea recover-javascript-sources <bundle.js> --output-dir <dir>',
    example: 'npx rea-agents recover-javascript-sources app.bundle.js --output-dir ./recovered',
    options: [
      { flag: '--output-dir', description: 'Directory to place recovered modules' },
      { flag: '--format-code', description: 'Run prettier/formatting on output' }
    ]
  },
  {
    name: 'inspect-web-page',
    summary: 'Passive CDP inspection of a live web page',
    category: 'web',
    description: 'Connects to a running browser via Chrome DevTools Protocol to extract loaded scripts, active listeners, and DOM structure.',
    syntax: 'rea inspect-web-page [options]',
    example: 'npx rea-agents inspect-web-page --origin http://localhost:3000 --format json',
    options: [
      { flag: '--origin', description: 'Filter inspection to target origin' },
      { flag: '--capture-scripts', description: 'Store copies of in-memory script tags' }
    ]
  },
  {
    name: 'inspect-binary-layout',
    summary: 'Inspect headers, symbols, and sections of native binaries',
    category: 'native',
    description: 'Examines ELF, Mach-O, or PE executables, reporting architectures, section boundaries, symbol tables, and imported shared libraries.',
    syntax: 'rea inspect-binary-layout <binary-path>',
    example: 'npx rea-agents inspect-binary-layout /usr/bin/target --format toon',
    options: [
      { flag: '--architecture', description: 'Select architecture for fat Mach-O' },
      { flag: '--detail', description: 'Level of symbol breakdown' }
    ]
  },
  {
    name: 'trace-application-feature',
    summary: 'Trace a feature through static call references',
    category: 'javascript',
    description: 'Traces data flow and invocation paths backwards and forwards from a seed symbol (like an API endpoint, event name, or function name).',
    syntax: 'rea trace-application-feature --seed <string> [options]',
    example: 'npx rea-agents trace-application-feature --seed "onPaymentSubmit" --depth 4',
    options: [
      { flag: '--seed', description: 'Seed function, string, or identifier' },
      { flag: '--depth', description: 'Maximum call graph traversal depth', default: '3' }
    ]
  },
  {
    name: 'setup',
    summary: 'Configure MCP server with AI coding agents',
    category: 'setup',
    description: 'Configures REA MCP tools into Claude Code, Cursor, Codex, Gemini CLI, Antigravity, and other supported AI assistant environments.',
    syntax: 'rea setup [options]',
    example: 'npx rea-agents setup --yes --all-detected',
    options: [
      { flag: '--yes, -y', description: 'Approve configuration without prompting' },
      { flag: '--client <name>', description: 'Specific agent to configure (e.g. cursor, gemini_cli)' },
      { flag: '--all-detected', description: 'Configure all detected agent environments' },
      { flag: '--dry-run', description: 'Inspect planned changes without writing files' }
    ]
  }
];

export const SAMPLE_EVIDENCE = {
  evidence_id: "ev_9c8f2a1b7e4d0382",
  type: "static_javascript_summary",
  timestamp: "2026-10-15T17:51:20Z",
  target: {
    path: "/dist/assets/index.js",
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    size_bytes: 489210
  },
  provenance: {
    engine: "rea-static-js",
    version: "6.5.0",
    confidence: "deterministic"
  },
  observations: [
    {
      role: "bundler_runtime",
      framework: "Vite + React 19",
      chunks_discovered: 8,
      entrypoint: "src/main.tsx"
    },
    {
      role: "exported_api_contract",
      endpoints: [
        { method: "POST", route: "/api/analyze", handler_offset: "0x1420" },
        { method: "GET", route: "/api/evidence/:id", handler_offset: "0x2810" }
      ]
    }
  ],
  inferences: [
    {
      statement: "Application utilizes server-authoritative authentication flow",
      supported_by_evidence: ["ev_9c8f2a1b7e4d0382", "ev_4f1b8893"],
      confidence_score: 0.94
    }
  ],
  unknowns: [
    "Native bridge capabilities if running inside Electron wrapper",
    "Dynamic eval payloads inside third-party obfuscated polyfills"
  ]
};

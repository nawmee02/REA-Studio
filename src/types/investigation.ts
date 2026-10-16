export type TargetType = 'web_url' | 'local_artifact' | 'browser_target' | 'binary' | 'archive';

export interface TargetTypeDefinition {
  type: TargetType;
  label: string;
  status: 'supported' | 'planned' | 'disabled';
  acceptedIdentifierFormat: string;
  acquisitionMethod: string;
  availableStages: string[];
  requiredPermissions: string[];
  evidenceTypesProduced: string[];
  limitations: string[];
  unsupportedOperations: string[];
}

export const TARGET_REGISTRY: Record<TargetType, TargetTypeDefinition> = {
  web_url: {
    type: 'web_url',
    label: 'Web URL',
    status: 'supported',
    acceptedIdentifierFormat: 'HTTP or HTTPS URL (e.g., https://example.com/path)',
    acquisitionMethod: 'Pinned DNS safeFetch with anti-SSRF and strict origin tracking',
    availableStages: [
      'target_resolution',
      'http_acquisition',
      'header_inspection',
      'html_dom_inspection',
      'script_inventory',
      'technology_detection',
      'endpoint_extraction',
      'agent_detection',
      'graph_synthesis',
      'integrity_sealing'
    ],
    requiredPermissions: ['public_egress'],
    evidenceTypesProduced: ['observation', 'derivation'],
    limitations: [
      'Static reconnaissance and edge observation only',
      'Authenticated endpoints and client-side single-page app state require interactive session'
    ],
    unsupportedOperations: [
      'Full headless browser rendering',
      'Dynamic memory instrumentation',
      'Native binary disassembly'
    ]
  },
  local_artifact: {
    type: 'local_artifact',
    label: 'Local Artifact',
    status: 'disabled',
    acceptedIdentifierFormat: 'File path to JavaScript/TypeScript source or bundle (e.g., ./dist/bundle.js)',
    acquisitionMethod: 'Local filesystem buffer reader with path traversal constraints',
    availableStages: ['artifact_ast_parsing', 'dependency_extraction', 'endpoint_extraction'],
    requiredPermissions: ['filesystem_read'],
    evidenceTypesProduced: ['observation'],
    limitations: [
      'Workspace pipeline integration disabled in Phase 3; use dedicated Artifact Lab tab for standalone analysis'
    ],
    unsupportedOperations: [
      'Remote network acquisition',
      'Native code decompilation'
    ]
  },
  browser_target: {
    type: 'browser_target',
    label: 'Browser Target (CDP)',
    status: 'disabled',
    acceptedIdentifierFormat: 'Chrome DevTools Protocol (CDP) WebSocket URL or tab target',
    acquisitionMethod: 'Headless browser automation via CDP session',
    availableStages: ['runtime_dom_snapshot', 'network_har_capture', 'console_telemetry'],
    requiredPermissions: ['cdp_connect', 'process_spawn'],
    evidenceTypesProduced: ['runtime_capture'],
    limitations: [
      'Browser Lab is planned for a future phase and disabled in Phase 3'
    ],
    unsupportedOperations: [
      'Kernel-level packet sniffing',
      'Hardware virtualization'
    ]
  },
  binary: {
    type: 'binary',
    label: 'Native Binary (ELF/PE/Mach-O)',
    status: 'disabled',
    acceptedIdentifierFormat: 'Path to compiled executable or shared library',
    acquisitionMethod: 'Binary header parsing and symbol table extraction',
    availableStages: ['header_analysis', 'symbol_demangling', 'strings_extraction'],
    requiredPermissions: ['filesystem_read'],
    evidenceTypesProduced: ['observation'],
    limitations: [
      'Native binary analysis is planned for a future phase and disabled in Phase 3'
    ],
    unsupportedOperations: [
      'Ghidra decompilation engine',
      'GDB / LLDB live debugging'
    ]
  },
  archive: {
    type: 'archive',
    label: 'Package / ASAR Archive',
    status: 'disabled',
    acceptedIdentifierFormat: 'Path to Electron .asar, .tar.gz, or .zip archive',
    acquisitionMethod: 'Virtual archive unpacking and file-tree indexing',
    availableStages: ['archive_unpack', 'manifest_inspection', 'entrypoint_analysis'],
    requiredPermissions: ['filesystem_read'],
    evidenceTypesProduced: ['observation'],
    limitations: [
      'Archive extraction pipeline is planned for a future phase and disabled in Phase 3'
    ],
    unsupportedOperations: [
      'Binary unpacking of packed malware',
      'Encrypted container decryption'
    ]
  }
};

export const SUPPORTED_TARGET_TYPES = Object.values(TARGET_REGISTRY)
  .filter(t => t.status === 'supported')
  .map(t => t.type);

export interface Target {
  type: TargetType;
  identifier: string;
  identity_hash: string;
  capabilities: string[];
  metadata?: Record<string, any>;
}

export type AuthorityType = 'direct' | 'derived' | 'heuristic';
export type EvidenceType = 'observation' | 'derivation' | 'runtime_capture';

export interface EvidenceRecord {
  evidence_id: string;
  schema_version: '1.0.0';
  type: EvidenceType;
  phase: string;
  source: {
    kind: 'http_response' | 'http_headers' | 'html_dom' | 'script_ast' | 'config_literal' | 'network_probe';
    location: string;
    sha256: string;
    bytes?: number;
  };
  content: Record<string, any>;
  canonical_digest: string;
  authority: AuthorityType;
  timestamp: string;
  tool: string;
  limitations: string[];
  parent_evidence_ids?: string[];
}

export type FindingClassification = 'observation' | 'inference';
export type FindingStatus = 'DISCOVERED' | 'VERIFIED' | 'CONFIRMED' | 'REFUTED' | 'UNKNOWN';

export interface FindingRecord {
  finding_id: string;
  claim: string;
  category: 'server' | 'technology' | 'endpoint' | 'security' | 'agent' | 'architecture';
  classification: FindingClassification;
  confidence: number;
  status: FindingStatus;
  evidence_ids: string[];
  supports?: string[];
  method: string;
  details?: Record<string, any>;
}

export type InvestigationLifecycleStatus = 
  | 'CREATED'
  | 'TARGET_BOUND'
  | 'COLLECTING'
  | 'ANALYZING'
  | 'VERIFYING'
  | 'COMPLETED'
  | 'PARTIAL_FAILURE'
  | 'FAILED';

export interface TimelineEntry {
  stage: string;
  timestamp: string;
  status: 'started' | 'completed' | 'skipped' | 'failed';
  duration_ms: number;
  evidence_produced?: string[];
  reason?: string;
  error?: string;
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'target' | 'script' | 'module' | 'endpoint' | 'evidence' | 'finding' | 'unknown';
  category?: string;
  data?: Record<string, any>;
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: 'contains' | 'imports' | 'calls' | 'supports' | 'discovers' | 'derived_from' | 'verifies' | 'loads';
}

export interface InvestigationSession {
  investigation_id: string;
  owner_uid?: string;
  goal: string;
  target: Target;
  toolchain: {
    rea_version: string;
    studio_version: string;
    node_version: string;
  };
  status: InvestigationLifecycleStatus;
  evidence_sources: {
    static_analysis: boolean;
    runtime_observation: boolean;
    network_inspection: boolean;
    version_comparison: boolean;
  };
  evidence: EvidenceRecord[];
  findings: FindingRecord[];
  unknowns: string[];
  coverage: {
    stages_executed: number;
    stages_total: number;
    stages_skipped?: number;
    stages_failed?: number;
    endpoints_discovered: number;
    endpoints_verified: number;
    scripts_mapped: number;
    technologies_confirmed: number;
  };
  timeline: TimelineEntry[];
  graph: {
    nodes: GraphNode[];
    edges: GraphEdge[];
  };
  manifest: {
    created_at: string;
    completed_at?: string;
    duration_total_ms?: number;
    parameters: Record<string, any>;
    integrity_hash?: string;
  };
}

export interface InvestigationExportBundle {
  bundle_version: '1.0.0';
  exported_at: string;
  investigation: InvestigationSession;
  evidence_payloads: Record<string, Record<string, any>>;
  report_markdown: string;
  integrity: {
    evidence_count: number;
    findings_count: number;
    manifest_hash: string;
    bundle_hash: string;
    verification_status: 'hash-verified';
  };
}

export interface DiffReport {
  previous_id: string;
  current_id: string;
  timestamp: string;
  target_url: string;
  evidence_diff: {
    added: EvidenceRecord[];
    removed: EvidenceRecord[];
    unchanged_count: number;
  };
  findings_diff: {
    added: FindingRecord[];
    removed: FindingRecord[];
    status_changed: { finding_id: string; claim: string; previous_status: FindingStatus; new_status: FindingStatus }[];
    unchanged_count: number;
  };
}

export type TargetType = 'web_url' | 'local_artifact' | 'browser_target' | 'binary' | 'archive';

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
  type: EvidenceType;
  phase: string;
  source: {
    kind: 'http_response' | 'http_headers' | 'html_dom' | 'script_ast' | 'config_literal' | 'network_probe';
    location: string;
    sha256: string;
    bytes?: number;
  };
  content: Record<string, any>;
  authority: AuthorityType;
  timestamp: string;
  tool: string;
  limitations: string[];
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
  | 'FAILED';

export interface TimelineEntry {
  stage: string;
  timestamp: string;
  status: 'started' | 'completed' | 'skipped' | 'failed';
  duration_ms: number;
  evidence_produced?: string[];
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

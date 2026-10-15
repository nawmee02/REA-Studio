import React, { useState } from 'react';
import { 
  TargetType, 
  InvestigationSession, 
  FindingStatus, 
  FindingRecord,
  EvidenceRecord 
} from '../types/investigation';
import { 
  Terminal, 
  Search, 
  ShieldCheck, 
  Network, 
  Layers, 
  FileCode, 
  CheckCircle2, 
  AlertCircle, 
  RefreshCw, 
  Play, 
  Copy, 
  Check, 
  ExternalLink, 
  Download, 
  ArrowRight,
  GitCompare,
  Hash,
  Activity,
  HelpCircle,
  Eye,
  Sliders,
  Send
} from 'lucide-react';

export const InvestigationWorkspace: React.FC = () => {
  // Target setup form state
  const [targetType, setTargetType] = useState<TargetType>('web_url');
  const [identifier, setIdentifier] = useState<string>('https://linear.app');
  const [goal, setGoal] = useState<string>('Map frontend architecture, edge CDN routing, and internal API routes');
  const [evidenceSources, setEvidenceSources] = useState({
    static_analysis: true,
    runtime_observation: false,
    network_inspection: true,
    version_comparison: false
  });

  // Investigation run state
  const [running, setRunning] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [activeSession, setActiveSession] = useState<InvestigationSession | null>(null);
  const [activeSubTab, setActiveSubTab] = useState<'findings' | 'evidence' | 'verification' | 'graph' | 'manifest'>('findings');
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [verifyingEp, setVerifyingEp] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleStartInvestigation = async () => {
    if (!identifier.trim()) return;
    setRunning(true);
    setError(null);

    try {
      const res = await fetch('/api/investigations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_type: targetType,
          identifier: identifier.trim(),
          goal: goal.trim(),
          evidence_sources: evidenceSources
        })
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `HTTP ${res.status}: Investigation pipeline failed.`);
      }

      const session: InvestigationSession = await res.json();
      setActiveSession(session);
      setActiveSubTab('findings');
    } catch (err: any) {
      setError(err?.message || 'Error executing investigation.');
    } finally {
      setRunning(false);
    }
  };

  // Phase 4: Actively verify a discovered endpoint
  const handleVerifyEndpoint = async (endpointPath: string) => {
    if (!activeSession) return;
    setVerifyingEp(endpointPath);

    try {
      const res = await fetch('/api/verify-endpoint', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          investigation_id: activeSession.investigation_id,
          endpoint_path: endpointPath,
          method: 'GET'
        })
      });

      if (!res.ok) {
        throw new Error('Verification probe failed.');
      }

      const data = await res.json();
      if (data.success && data.updated_finding) {
        // Update local session findings and evidence
        setActiveSession({
          ...activeSession,
          evidence: [...activeSession.evidence, data.evidence],
          findings: activeSession.findings.map(f => 
            f.finding_id === data.updated_finding.finding_id ? data.updated_finding : f
          ),
          coverage: {
            ...activeSession.coverage,
            endpoints_verified: activeSession.coverage.endpoints_verified + 1
          }
        });
      }
    } catch (err: any) {
      console.error('Verification error:', err);
    } finally {
      setVerifyingEp(null);
    }
  };

  // Generate markdown report
  const generateMarkdownReport = (session: InvestigationSession) => {
    return `# REA Investigation Report: ${session.investigation_id}

**Target**: \`${session.target.identifier}\` (\`${session.target.type}\`)  
**Target Identity SHA-256**: \`${session.target.identity_hash}\`  
**Investigation Goal**: ${session.goal}  
**Status**: ${session.status}  
**Timestamp**: ${session.manifest.created_at}  
**Toolchain**: REA \`${session.toolchain.rea_version}\` | Studio \`${session.toolchain.studio_version}\` | Node \`${session.toolchain.node_version}\`

---

## 1. Executive Summary & Coverage
- **Stages Executed**: ${session.coverage.stages_executed} / ${session.coverage.stages_total}
- **Technologies Confirmed**: ${session.coverage.technologies_confirmed}
- **Endpoints Discovered**: ${session.coverage.endpoints_discovered} (Verified: ${session.coverage.endpoints_verified})
- **Total Evidence Records**: ${session.evidence.length}
- **Total Findings**: ${session.findings.length}

---

## 2. Findings (Truth Model)

${session.findings.map((f, i) => `### Finding ${i + 1}: ${f.claim}
- **Classification**: ${f.classification.toUpperCase()} (Confidence: ${(f.confidence * 100).toFixed(0)}%)
- **Status**: \`${f.status}\`
- **Method**: ${f.method}
- **Cited Evidence**: ${f.evidence_ids.map(id => `\`${id}\``).join(', ')}
${f.supports ? `- **Supports Observation(s)**: ${f.supports.map(s => `\`${s}\``).join(', ')}` : ''}
`).join('\n')}

---

## 3. Explicit Residual Unknowns
${session.unknowns.map(u => `- **UNKNOWN**: ${u}`).join('\n')}

---

## 4. Evidence Ledger
${session.evidence.map(e => `- **${e.evidence_id}** [${e.type} / ${e.authority}] from \`${e.source.kind}\` (\`${e.source.location}\`)\n  Digest: \`${e.source.sha256}\`\n  Limitations: ${e.limitations.join('; ')}`).join('\n\n')}

---
*Report generated deterministically by REA Studio under MIT License.*
`;
  };

  const filteredFindings = activeSession?.findings.filter(f => {
    if (filterCategory === 'all') return true;
    if (filterCategory === 'verified') return f.status === 'VERIFIED';
    if (filterCategory === 'discovered') return f.status === 'DISCOVERED';
    if (filterCategory === 'inference') return f.classification === 'inference';
    return f.category === filterCategory;
  }) || [];

  return (
    <div className="space-y-6">
      {/* 1. Investigation Creation Workspace Form */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 font-semibold">
                REA Investigation Pipeline
              </span>
              <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium">
                Deterministic Reconnaissance
              </span>
            </div>
            <h1 className="text-xl font-bold text-white mt-2">
              New Investigation
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Bind a target and define requirements. The studio records verifiable observations, establishes inferences, and isolates residual unknowns.
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <span>rea-agents@6.5.0</span>
          </div>
        </div>

        {/* Target Form */}
        <div className="mt-5 space-y-4">
          {/* Target Type Selector */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 block">
                Target Kind
              </label>
              <span className="text-[11px] text-slate-500">
                Phase 3: Web URL supported &bull; Standalone JS/TS code supported via Artifact Lab
              </span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
              {[
                { type: 'web_url', label: 'Web URL', status: 'supported' },
                { type: 'local_artifact', label: 'Local Artifact (Artifact Lab)', status: 'disabled' },
                { type: 'browser_target', label: 'Browser (Planned)', status: 'disabled' },
                { type: 'binary', label: 'Binary (Planned)', status: 'disabled' },
                { type: 'archive', label: 'ASAR / Archive (Planned)', status: 'disabled' }
              ].map(opt => (
                <button
                  key={opt.type}
                  type="button"
                  disabled={opt.status !== 'supported'}
                  onClick={() => opt.status === 'supported' && setTargetType(opt.type as TargetType)}
                  className={`px-3 py-2 rounded-lg text-xs font-medium border text-center transition-all ${
                    targetType === opt.type
                      ? 'bg-indigo-600 border-indigo-500 text-white shadow-sm'
                      : opt.status !== 'supported'
                        ? 'bg-slate-950/30 border-slate-900 text-slate-600 cursor-not-allowed opacity-60'
                        : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                  }`}
                  title={opt.status !== 'supported' ? 'This target type is not yet enabled for the full workspace pipeline in Phase 3.' : undefined}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {/* Identifier Input */}
          <div>
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 block mb-1">
              Target Identifier
            </label>
            <input
              type="text"
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              placeholder="https://example.com"
              className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-500 font-mono focus:outline-none focus:border-indigo-500 transition-colors shadow-inner"
            />
          </div>

          {/* Investigation Goal */}
          <div>
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 block mb-1">
              Investigation Goal
            </label>
            <input
              type="text"
              value={goal}
              onChange={(e) => setGoal(e.target.value)}
              placeholder="What are you trying to understand? (e.g. Map API routes, identify state store, detect AI agents)"
              className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-700 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-colors"
            />
          </div>

          {/* Evidence Sources Toggles */}
          <div>
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 block mb-2">
              Evidence Sources
            </label>
            <div className="flex flex-wrap items-center gap-4 text-xs text-slate-300">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={evidenceSources.static_analysis}
                  onChange={(e) => setEvidenceSources({ ...evidenceSources, static_analysis: e.target.checked })}
                  className="rounded border-slate-700 text-indigo-600 focus:ring-indigo-500"
                />
                <span>Static Analysis (AST &amp; DOM)</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={evidenceSources.network_inspection}
                  onChange={(e) => setEvidenceSources({ ...evidenceSources, network_inspection: e.target.checked })}
                  className="rounded border-slate-700 text-indigo-600 focus:ring-indigo-500"
                />
                <span>Network &amp; Edge Inspection</span>
              </label>

              <label className="flex items-center gap-2 text-slate-600 cursor-not-allowed" title="Runtime Observation is planned for a future phase and disabled in Phase 3">
                <input
                  type="checkbox"
                  disabled
                  checked={false}
                  className="rounded border-slate-800 text-slate-600 cursor-not-allowed opacity-40"
                />
                <span className="line-through decoration-slate-700">Runtime Observation</span>
                <span className="text-[10px] px-1 py-0.2 rounded bg-slate-800 text-slate-400">Planned</span>
              </label>

              <label className="flex items-center gap-2 text-slate-600 cursor-not-allowed" title="Version Comparison is planned for a future phase and disabled in Phase 3">
                <input
                  type="checkbox"
                  disabled
                  checked={false}
                  className="rounded border-slate-800 text-slate-600 cursor-not-allowed opacity-40"
                />
                <span className="line-through decoration-slate-700">Version Comparison / Diff</span>
                <span className="text-[10px] px-1 py-0.2 rounded bg-slate-800 text-slate-400">Planned</span>
              </label>
            </div>
          </div>

          {/* Action Button & Neutral Presets */}
          <div className="pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span className="text-slate-500">Neutral Presets:</span>
              <button
                type="button"
                onClick={() => setIdentifier('https://linear.app')}
                className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-800 text-slate-300 border border-slate-700/60 font-mono"
              >
                linear.app
              </button>
              <button
                type="button"
                onClick={() => setIdentifier('https://supabase.com')}
                className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-800 text-slate-300 border border-slate-700/60 font-mono"
              >
                supabase.com
              </button>
              <button
                type="button"
                onClick={() => setIdentifier('https://github.com')}
                className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-800 text-slate-300 border border-slate-700/60 font-mono"
              >
                github.com
              </button>
            </div>

            <button
              onClick={handleStartInvestigation}
              disabled={running || !identifier.trim()}
              className="px-6 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-800 disabled:text-slate-500 text-white font-medium text-xs sm:text-sm flex items-center justify-center gap-2 transition-all shadow-md cursor-pointer disabled:cursor-not-allowed"
            >
              {running ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Executing 12-Stage Pipeline...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-white" />
                  <span>Start Investigation</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Error Notice */}
      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/30 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div className="text-xs">
            <h3 className="font-semibold text-red-300">Investigation Pipeline Blocked</h3>
            <p className="text-red-200/80 mt-0.5">{error}</p>
          </div>
        </div>
      )}

      {/* 2. Active Investigation Dashboard */}
      {activeSession && (
        <div className="space-y-6">
          {/* Investigation Header */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 font-bold">
                  {activeSession.investigation_id}
                </span>
                <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                  {activeSession.status}
                </span>
                <span className="text-[11px] font-mono text-slate-400">
                  SHA-256: {activeSession.target.identity_hash.slice(0, 16)}...
                </span>
              </div>
              <h2 className="text-lg font-bold text-white mt-1 flex items-center gap-2">
                <span>{activeSession.target.identifier}</span>
                <a href={activeSession.target.identifier} target="_blank" rel="noreferrer" className="text-slate-400 hover:text-white">
                  <ExternalLink className="w-4 h-4" />
                </a>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Goal: <strong className="text-slate-300">{activeSession.goal}</strong> &bull; Total Pipeline Duration: {activeSession.manifest.duration_total_ms}ms
              </p>
            </div>

            {/* Quick Actions */}
            <div className="flex items-center gap-2">
              <button
                onClick={() => copyToClipboard(JSON.stringify(activeSession, null, 2), 'bundle_json')}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 border border-slate-700 transition-colors"
              >
                {copiedId === 'bundle_json' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedId === 'bundle_json' ? 'Copied' : 'Export Bundle JSON'}</span>
              </button>

              <button
                onClick={() => copyToClipboard(generateMarkdownReport(activeSession), 'report_md')}
                className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium flex items-center gap-1.5 transition-colors shadow-sm"
              >
                {copiedId === 'report_md' ? <Check className="w-3.5 h-3.5" /> : <FileCode className="w-3.5 h-3.5" />}
                <span>{copiedId === 'report_md' ? 'Copied MD' : 'Copy Report (.md)'}</span>
              </button>
            </div>
          </div>

          {/* Coverage Summary Metric Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs">
            <div className="bg-slate-900 border border-slate-800 p-3 rounded-lg">
              <span className="text-slate-400 text-[10px] uppercase tracking-wider block font-semibold">Evidence Nodes</span>
              <span className="text-white text-lg font-bold mt-0.5 block font-mono">{activeSession.evidence.length}</span>
              <span className="text-[10px] text-emerald-400">Hash-Verified Ledger</span>
            </div>

            <div className="bg-slate-900 border border-slate-800 p-3 rounded-lg">
              <span className="text-slate-400 text-[10px] uppercase tracking-wider block font-semibold">Findings &amp; Claims</span>
              <span className="text-white text-lg font-bold mt-0.5 block font-mono">{activeSession.findings.length}</span>
              <span className="text-[10px] text-indigo-400">Observations + Inferences</span>
            </div>

            <div className="bg-slate-900 border border-slate-800 p-3 rounded-lg">
              <span className="text-slate-400 text-[10px] uppercase tracking-wider block font-semibold">Discovered APIs</span>
              <span className="text-white text-lg font-bold mt-0.5 block font-mono">{activeSession.coverage.endpoints_discovered}</span>
              <span className="text-[10px] text-amber-400">Verified: {activeSession.coverage.endpoints_verified}</span>
            </div>

            <div className="bg-slate-900 border border-slate-800 p-3 rounded-lg">
              <span className="text-slate-400 text-[10px] uppercase tracking-wider block font-semibold">Confirmed Tech</span>
              <span className="text-white text-lg font-bold mt-0.5 block font-mono">{activeSession.coverage.technologies_confirmed}</span>
              <span className="text-[10px] text-purple-400">Static Fingerprints</span>
            </div>

            <div className="bg-slate-900 border border-slate-800 p-3 rounded-lg">
              <span className="text-slate-400 text-[10px] uppercase tracking-wider block font-semibold">Residual Unknowns</span>
              <span className="text-white text-lg font-bold mt-0.5 block font-mono">{activeSession.unknowns.length}</span>
              <span className="text-[10px] text-slate-400">Bounded Masked Logic</span>
            </div>
          </div>

          {/* Investigation Sub-navigation */}
          <div className="flex space-x-2 border-b border-slate-800 overflow-x-auto pb-1 text-xs">
            <button
              onClick={() => setActiveSubTab('findings')}
              className={`px-3.5 py-2 rounded-lg font-medium transition-colors flex items-center gap-1.5 whitespace-nowrap ${
                activeSubTab === 'findings'
                  ? 'bg-indigo-600 text-white'
                  : 'text-slate-400 hover:text-white hover:bg-slate-900'
              }`}
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Findings &amp; Claims ({activeSession.findings.length})</span>
            </button>

            <button
              onClick={() => setActiveSubTab('evidence')}
              className={`px-3.5 py-2 rounded-lg font-medium transition-colors flex items-center gap-1.5 whitespace-nowrap ${
                activeSubTab === 'evidence'
                  ? 'bg-indigo-600 text-white'
                  : 'text-slate-400 hover:text-white hover:bg-slate-900'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Evidence Ledger ({activeSession.evidence.length})</span>
            </button>

            <button
              onClick={() => setActiveSubTab('verification')}
              className={`px-3.5 py-2 rounded-lg font-medium transition-colors flex items-center gap-1.5 whitespace-nowrap ${
                activeSubTab === 'verification'
                  ? 'bg-indigo-600 text-white'
                  : 'text-slate-400 hover:text-white hover:bg-slate-900'
              }`}
            >
              <Activity className="w-3.5 h-3.5 text-amber-400" />
              <span>Verification Engine ({activeSession.coverage.endpoints_discovered})</span>
            </button>

            <button
              onClick={() => setActiveSubTab('graph')}
              className={`px-3.5 py-2 rounded-lg font-medium transition-colors flex items-center gap-1.5 whitespace-nowrap ${
                activeSubTab === 'graph'
                  ? 'bg-indigo-600 text-white'
                  : 'text-slate-400 hover:text-white hover:bg-slate-900'
              }`}
            >
              <Network className="w-3.5 h-3.5" />
              <span>Investigation Graph</span>
            </button>

            <button
              onClick={() => setActiveSubTab('manifest')}
              className={`px-3.5 py-2 rounded-lg font-medium transition-colors flex items-center gap-1.5 whitespace-nowrap ${
                activeSubTab === 'manifest'
                  ? 'bg-indigo-600 text-white'
                  : 'text-slate-400 hover:text-white hover:bg-slate-900'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>Manifest &amp; Replay</span>
            </button>
          </div>

          {/* TAB 1: Findings & Claims */}
          {activeSubTab === 'findings' && (
            <div className="space-y-4">
              {/* Category Filter Pills */}
              <div className="flex flex-wrap items-center gap-1.5 text-xs">
                {['all', 'verified', 'discovered', 'inference', 'technology', 'endpoint', 'server', 'agent'].map(cat => (
                  <button
                    key={cat}
                    onClick={() => setFilterCategory(cat)}
                    className={`px-2.5 py-1 rounded-md capitalize font-medium transition-colors ${
                      filterCategory === cat
                        ? 'bg-slate-800 text-white border border-slate-700'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>

              {/* Findings Cards List */}
              <div className="space-y-3">
                {filteredFindings.map((finding) => (
                  <div
                    key={finding.finding_id}
                    className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-2 text-xs"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-indigo-400 font-bold">
                          {finding.finding_id}
                        </span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                          finding.status === 'VERIFIED' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' :
                          finding.status === 'CONFIRMED' ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/30' :
                          'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                        }`}>
                          {finding.status}
                        </span>
                        <span className="text-[10px] uppercase font-bold text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">
                          {finding.classification}
                        </span>
                      </div>

                      <div className="text-[11px] text-slate-400">
                        Confidence: <strong className="text-white font-mono">{(finding.confidence * 100).toFixed(0)}%</strong>
                      </div>
                    </div>

                    <h3 className="text-sm font-semibold text-white">
                      {finding.claim}
                    </h3>

                    <p className="text-slate-400 text-[11px]">
                      Method: {finding.method}
                    </p>

                    <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-400 font-mono">
                      <div className="flex items-center gap-1.5">
                        <Hash className="w-3 h-3 text-indigo-400" />
                        <span>Evidence:</span>
                        {finding.evidence_ids.map(id => (
                          <span key={id} className="text-indigo-300 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">
                            {id}
                          </span>
                        ))}
                      </div>

                      {finding.supports && (
                        <div className="text-slate-400">
                          Supports: {finding.supports.join(', ')}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              {/* Residual Unknowns Box */}
              <div className="p-4 bg-slate-950/80 border border-amber-500/30 rounded-xl space-y-2 text-xs">
                <div className="flex items-center gap-2 text-amber-400 font-bold uppercase tracking-wider text-[11px]">
                  <HelpCircle className="w-4 h-4" />
                  <span>Residual Unknowns (Explicit Boundaries)</span>
                </div>
                <div className="space-y-1.5 text-amber-200/90 pl-1">
                  {activeSession.unknowns.map((unk, i) => (
                    <div key={i} className="flex items-start gap-2">
                      <span className="text-amber-400 font-bold">•</span>
                      <span>{unk}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: Evidence Ledger */}
          {activeSubTab === 'evidence' && (
            <div className="space-y-3">
              {activeSession.evidence.map((ev) => (
                <div
                  key={ev.evidence_id}
                  className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-3 text-xs"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-emerald-400 font-bold">
                        {ev.evidence_id}
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-slate-800 text-slate-300">
                        {ev.type} &bull; {ev.authority}
                      </span>
                      <span className="text-[10px] text-slate-400 font-mono">
                        Phase: {ev.phase}
                      </span>
                    </div>

                    <span className="text-[11px] text-slate-400 font-mono">
                      Tool: {ev.tool}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 p-2.5 bg-slate-950 rounded-lg border border-slate-800/80 font-mono text-[11px] text-slate-300">
                    <div>
                      <span className="text-slate-400">Source:</span> {ev.source.kind} ({ev.source.location})
                    </div>
                    <div className="truncate">
                      <span className="text-slate-400">Digest:</span> {ev.source.sha256}
                    </div>
                  </div>

                  {/* Content Preview */}
                  <div className="p-3 bg-slate-950/70 rounded-lg border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto max-h-48">
                    <pre className="text-indigo-300">{JSON.stringify(ev.content, null, 2)}</pre>
                  </div>

                  <div className="text-[11px] text-slate-400 flex items-start gap-2">
                    <span className="font-semibold text-slate-400">Limitations:</span>
                    <span>{ev.limitations.join('; ')}</span>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* TAB 3: Verification Engine */}
          {activeSubTab === 'verification' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 text-xs">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Activity className="w-4 h-4 text-amber-400" />
                  Active Verification Engine (Separate Discovery from Verification)
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  In REA, a static string match is only <strong className="text-amber-300">DISCOVERED</strong>. Trigger an active HTTP probe to promote it to <strong className="text-emerald-400">VERIFIED</strong> and record a verified evidence node.
                </p>
              </div>

              <div className="space-y-2">
                {activeSession.findings
                  .filter(f => f.category === 'endpoint')
                  .map((f) => {
                    const epPath = f.details?.path || f.claim;
                    const isVerifying = verifyingEp === epPath;

                    return (
                      <div
                        key={f.finding_id}
                        className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex flex-wrap items-center justify-between gap-3"
                      >
                        <div className="flex items-center gap-2.5 truncate">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            f.status === 'VERIFIED' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' :
                            'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                          }`}>
                            {f.status}
                          </span>
                          <span className="font-mono text-indigo-300 font-bold truncate">
                            {epPath}
                          </span>
                        </div>

                        <div className="flex items-center gap-2">
                          {f.details?.verified_status && (
                            <span className="text-[10px] font-mono text-emerald-400">
                              HTTP {f.details.verified_status} OK
                            </span>
                          )}

                          <button
                            onClick={() => handleVerifyEndpoint(epPath)}
                            disabled={isVerifying}
                            className="px-3 py-1.5 rounded bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-800 text-white font-medium text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
                          >
                            {isVerifying ? (
                              <>
                                <RefreshCw className="w-3 h-3 animate-spin" />
                                <span>Probing...</span>
                              </>
                            ) : (
                              <>
                                <Send className="w-3 h-3" />
                                <span>{f.status === 'VERIFIED' ? 'Re-Verify Probe' : 'Run Verification Probe'}</span>
                              </>
                            )}
                          </button>
                        </div>
                      </div>
                    );
                  })}
              </div>
            </div>
          )}

          {/* TAB 4: Investigation Graph */}
          {activeSubTab === 'graph' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 text-xs">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Network className="w-4 h-4 text-indigo-400" />
                  Investigation Dependency Graph (Nodes: {activeSession.graph.nodes.length}, Edges: {activeSession.graph.edges.length})
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Visual relationship tracking connecting Targets &rarr; Scripts &rarr; Endpoints &rarr; Findings.
                </p>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-3 max-h-96 overflow-y-auto">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  Graph Edges (Verified Relationships)
                </div>

                <div className="space-y-1.5 font-mono text-[11px]">
                  {activeSession.graph.edges.map((edge, i) => (
                    <div key={i} className="p-2 bg-slate-900/90 rounded border border-slate-800 flex items-center gap-2 truncate">
                      <span className="text-indigo-300 truncate max-w-xs">{edge.source}</span>
                      <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400 uppercase font-bold shrink-0">
                        --[{edge.relation}]--&gt;
                      </span>
                      <span className="text-emerald-300 truncate max-w-xs">{edge.target}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: Manifest & Replay */}
          {activeSubTab === 'manifest' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-indigo-400" />
                    Investigation Manifest &amp; Replay (Phase 10)
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Guarantees identical reproducibility. Re-running with this manifest compares findings across versions.
                  </p>
                </div>

                <button
                  onClick={handleStartInvestigation}
                  className="px-3.5 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-xs flex items-center gap-1.5 transition-colors shadow-sm"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Run Investigation Replay</span>
                </button>
              </div>

              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto max-h-96">
                <pre className="text-emerald-400">
{JSON.stringify({
  manifest_version: "1.0.0",
  investigation_id: activeSession.investigation_id,
  target: activeSession.target,
  toolchain: activeSession.toolchain,
  parameters: activeSession.manifest.parameters,
  timeline: activeSession.timeline
}, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

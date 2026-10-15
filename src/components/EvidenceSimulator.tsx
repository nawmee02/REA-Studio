import React, { useState } from 'react';
import { SAMPLE_EVIDENCE } from '../data/skillsData';
import { ShieldCheck, Eye, HelpCircle, Lightbulb, Hash, Copy, Check, Terminal } from 'lucide-react';

export const EvidenceSimulator: React.FC = () => {
  const [evidenceData, setEvidenceData] = useState(SAMPLE_EVIDENCE);
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'visual' | 'json'>('visual');

  const copyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(evidenceData, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6 pb-4 border-b border-slate-800">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-indigo-400" />
            REA Evidence Ledger & Provenance Model
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            REA strictly partitions factual observations, supported inferences, and residual unknowns with cryptographic Evidence IDs.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex bg-slate-800 p-0.5 rounded-lg border border-slate-700 text-xs">
            <button
              onClick={() => setActiveTab('visual')}
              className={`px-3 py-1 rounded-md font-medium transition-colors ${
                activeTab === 'visual' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              Visual Ledger
            </button>
            <button
              onClick={() => setActiveTab('json')}
              className={`px-3 py-1 rounded-md font-medium transition-colors ${
                activeTab === 'json' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              Raw Evidence JSON
            </button>
          </div>

          <button
            onClick={copyJson}
            className="px-3 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 border border-slate-700 transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
      </div>

      {activeTab === 'visual' ? (
        <div className="space-y-6">
          {/* Metadata Card */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-slate-950/60 border border-slate-800 p-3.5 rounded-lg">
              <div className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold mb-1 flex items-center gap-1.5">
                <Hash className="w-3 h-3 text-indigo-400" />
                Evidence ID
              </div>
              <div className="font-mono text-sm text-indigo-300 font-bold truncate">
                {evidenceData.evidence_id}
              </div>
              <div className="text-[10px] text-slate-400 mt-1">SHA-256 bound ledger node</div>
            </div>

            <div className="bg-slate-950/60 border border-slate-800 p-3.5 rounded-lg">
              <div className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold mb-1 flex items-center gap-1.5">
                <Terminal className="w-3 h-3 text-emerald-400" />
                Analyzer Engine
              </div>
              <div className="font-mono text-sm text-emerald-300 font-medium">
                {evidenceData.provenance.engine} v{evidenceData.provenance.version}
              </div>
              <div className="text-[10px] text-slate-400 mt-1">Deterministic static extraction</div>
            </div>

            <div className="bg-slate-950/60 border border-slate-800 p-3.5 rounded-lg">
              <div className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold mb-1">
                Target Artifact
              </div>
              <div className="font-mono text-xs text-slate-300 truncate">
                {evidenceData.target.path}
              </div>
              <div className="text-[10px] text-slate-400 mt-1 font-mono truncate">
                SHA: {evidenceData.target.sha256.slice(0, 18)}...
              </div>
            </div>
          </div>

          {/* Tripartite Breakdown: Observations vs Inferences vs Unknowns */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {/* 1. Observations */}
            <div className="bg-slate-950/80 border border-emerald-500/30 rounded-xl p-4 flex flex-col">
              <div className="flex items-center gap-2 mb-3 pb-2 border-b border-emerald-500/20 text-emerald-400">
                <Eye className="w-4 h-4" />
                <h3 className="text-xs font-bold uppercase tracking-wider">
                  Observations ({evidenceData.observations.length})
                </h3>
                <span className="text-[10px] ml-auto px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300">
                  Direct Facts
                </span>
              </div>
              <div className="space-y-3 flex-1">
                {evidenceData.observations.map((obs, idx) => (
                  <div key={idx} className="bg-slate-900/90 p-3 rounded-lg border border-slate-800 text-xs">
                    <div className="text-emerald-300 font-mono font-medium mb-1 flex items-center gap-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block" />
                      {obs.role}
                    </div>
                    {obs.framework && (
                      <div className="text-slate-300 mt-1">
                        Framework: <span className="font-semibold">{obs.framework}</span>
                      </div>
                    )}
                    {obs.entrypoint && (
                      <div className="text-slate-400 font-mono text-[11px] mt-0.5">
                        Entry: {obs.entrypoint} ({obs.chunks_discovered} chunks)
                      </div>
                    )}
                    {obs.endpoints && (
                      <div className="mt-2 space-y-1">
                        <div className="text-[11px] text-slate-400">Discovered Routes:</div>
                        {obs.endpoints.map((ep, i) => (
                          <div key={i} className="font-mono text-[11px] bg-slate-950 px-2 py-1 rounded text-slate-300 flex justify-between">
                            <span>{ep.method} {ep.route}</span>
                            <span className="text-slate-400">{ep.handler_offset}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
              <p className="text-[10px] text-slate-400 mt-3 pt-2 border-t border-slate-800/80">
                Proven by static AST nodes without speculation.
              </p>
            </div>

            {/* 2. Inferences */}
            <div className="bg-slate-950/80 border border-indigo-500/30 rounded-xl p-4 flex flex-col">
              <div className="flex items-center gap-2 mb-3 pb-2 border-b border-indigo-500/20 text-indigo-400">
                <Lightbulb className="w-4 h-4" />
                <h3 className="text-xs font-bold uppercase tracking-wider">
                  Inferences ({evidenceData.inferences.length})
                </h3>
                <span className="text-[10px] ml-auto px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300">
                  Hypotheses
                </span>
              </div>
              <div className="space-y-3 flex-1">
                {evidenceData.inferences.map((inf, idx) => (
                  <div key={idx} className="bg-slate-900/90 p-3 rounded-lg border border-slate-800 text-xs">
                    <p className="text-slate-200 font-medium leading-relaxed">
                      "{inf.statement}"
                    </p>
                    <div className="mt-2 pt-2 border-t border-slate-800 flex items-center justify-between text-[11px]">
                      <span className="text-slate-400">Confidence:</span>
                      <span className="font-mono font-bold text-indigo-400">{(inf.confidence_score * 100).toFixed(0)}%</span>
                    </div>
                    <div className="text-[10px] text-slate-400 mt-1 font-mono">
                      Cites: {inf.supported_by_evidence.join(', ')}
                    </div>
                  </div>
                ))}
              </div>
              <p className="text-[10px] text-slate-400 mt-3 pt-2 border-t border-slate-800/80">
                AI conclusions citing specific evidence node IDs.
              </p>
            </div>

            {/* 3. Unknowns */}
            <div className="bg-slate-950/80 border border-amber-500/30 rounded-xl p-4 flex flex-col">
              <div className="flex items-center gap-2 mb-3 pb-2 border-b border-amber-500/20 text-amber-400">
                <HelpCircle className="w-4 h-4" />
                <h3 className="text-xs font-bold uppercase tracking-wider">
                  Unknowns ({evidenceData.unknowns.length})
                </h3>
                <span className="text-[10px] ml-auto px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300">
                  Bounded Gaps
                </span>
              </div>
              <div className="space-y-2.5 flex-1">
                {evidenceData.unknowns.map((gap, idx) => (
                  <div key={idx} className="bg-slate-900/90 p-3 rounded-lg border border-slate-800 text-xs text-amber-200/90 flex items-start gap-2">
                    <span className="text-amber-400 font-bold">•</span>
                    <span>{gap}</span>
                  </div>
                ))}
              </div>
              <p className="text-[10px] text-slate-400 mt-3 pt-2 border-t border-slate-800/80">
                Explicit boundaries and negative searches marked as unresolved.
              </p>
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
          <pre className="font-mono text-xs text-emerald-400 overflow-x-auto max-h-[500px]">
            {JSON.stringify(evidenceData, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};

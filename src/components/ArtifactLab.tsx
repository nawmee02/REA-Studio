import React, { useState } from 'react';
import { apiFetch } from '../firebase/apiClient';
import { FileCode, Play, Copy, Check, Terminal, Layers, Hash, Code2, Sparkles, Folder } from 'lucide-react';

export const ArtifactLab: React.FC = () => {
  const [codeContent, setCodeContent] = useState<string>(`// Sample JavaScript/Electron Bundle Artifact
import { initializeApp } from "firebase/app";
import { getAuth, signInWithCustomToken } from "firebase/auth";
import axios from "axios";

export const API_BASE = "/api/v2/telemetry";
const WS_ENDPOINT = "wss://gateway.example.internal/live";

export async function dispatchTelemetry(payload) {
  const token = window.sessionStorage.getItem("auth_token_v2");
  return axios.post(API_BASE, { payload, token });
}

export default function renderDashboard() {
  console.log("Initializing secure client surface...");
}
`);
  const [filename, setFilename] = useState<string>('app.bundle.js');
  const [loading, setLoading] = useState<boolean>(false);
  const [analysisResult, setAnalysisResult] = useState<any | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  const handleAnalyze = async () => {
    if (!codeContent.trim()) return;
    setLoading(true);

    try {
      const data = await apiFetch('/api/analyze-artifact', {
        method: 'POST',
        body: JSON.stringify({
          code: codeContent,
          filename
        })
      });

      setAnalysisResult(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 font-semibold">
                Phase 6: Artifact Lab
              </span>
              <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium">
                Static Code Reconstructor
              </span>
            </div>
            <h1 className="text-xl font-bold text-white mt-2">
              Artifact Analysis &amp; Module Deconstruction
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Paste or input JavaScript bundles, ASAR module extracts, or code artifacts to reconstruct dependency trees, exported symbols, and embedded API paths.
            </p>
          </div>

          <button
            onClick={handleAnalyze}
            disabled={loading}
            className="px-5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-xs flex items-center gap-1.5 transition-colors cursor-pointer disabled:bg-slate-800"
          >
            <Play className="w-4 h-4 fill-white" />
            <span>{loading ? 'Deconstructing...' : 'Analyze Artifact'}</span>
          </button>
        </div>

        {/* Input Form */}
        <div className="mt-4 space-y-3">
          <div className="flex items-center gap-3 text-xs">
            <span className="text-slate-400">Artifact Name:</span>
            <input
              type="text"
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              className="px-2.5 py-1 bg-slate-950 border border-slate-700 rounded font-mono text-slate-200"
            />
          </div>

          <textarea
            value={codeContent}
            onChange={(e) => setCodeContent(e.target.value)}
            rows={10}
            className="w-full p-4 bg-slate-950 border border-slate-700 rounded-lg font-mono text-xs text-slate-300 focus:outline-none focus:border-indigo-500 leading-relaxed"
            placeholder="Paste bundle code or extracted script..."
          />
        </div>
      </div>

      {/* Results */}
      {analysisResult && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-5 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-white">
                {analysisResult.artifact.filename}
              </span>
              <span className="text-[10px] font-mono text-slate-400">
                SHA-256: {analysisResult.artifact.sha256} ({analysisResult.artifact.bytes} bytes)
              </span>
            </div>

            <button
              onClick={() => {
                navigator.clipboard.writeText(JSON.stringify(analysisResult, null, 2));
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
              }}
              className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs flex items-center gap-1"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy JSON'}</span>
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Dependencies */}
            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
              <span className="text-[11px] font-semibold uppercase text-slate-400 block">
                Imports &amp; Dependencies ({analysisResult.analysis.dependencies.length})
              </span>
              <div className="space-y-1 font-mono text-[11px]">
                {analysisResult.analysis.dependencies.map((dep: string, i: number) => (
                  <div key={i} className="text-indigo-300 bg-slate-900 px-2 py-1 rounded">
                    {dep}
                  </div>
                ))}
              </div>
            </div>

            {/* Exports */}
            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
              <span className="text-[11px] font-semibold uppercase text-slate-400 block">
                Exported Identifiers ({analysisResult.analysis.exports.length})
              </span>
              <div className="space-y-1 font-mono text-[11px]">
                {analysisResult.analysis.exports.map((exp: string, i: number) => (
                  <div key={i} className="text-emerald-300 bg-slate-900 px-2 py-1 rounded">
                    {exp}
                  </div>
                ))}
              </div>
            </div>

            {/* Embedded Endpoints */}
            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
              <span className="text-[11px] font-semibold uppercase text-slate-400 block">
                Embedded Paths &amp; Endpoints ({analysisResult.analysis.endpoints.length})
              </span>
              <div className="space-y-1 font-mono text-[11px]">
                {analysisResult.analysis.endpoints.map((ep: string, i: number) => (
                  <div key={i} className="text-amber-300 bg-slate-900 px-2 py-1 rounded">
                    {ep}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

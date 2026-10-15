/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { InvestigationWorkspace } from './components/InvestigationWorkspace';
import { ArtifactLab } from './components/ArtifactLab';
import { SkillViewer } from './components/SkillViewer';
import { CommandBuilder } from './components/CommandBuilder';
import { EvidenceSimulator } from './components/EvidenceSimulator';
import { IntegrationStatus } from './components/IntegrationStatus';
import { 
  Terminal, 
  BookOpen, 
  ShieldCheck, 
  Layers, 
  ExternalLink, 
  CheckCircle2, 
  Search,
  Sparkles,
  GitBranch,
  Activity,
  FileCode,
  Compass
} from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<'workspace' | 'artifact' | 'evidence' | 'commands' | 'skills' | 'status'>('workspace');

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-indigo-500 selection:text-white">
      {/* Top Navigation Bar */}
      <header className="sticky top-0 z-50 bg-slate-950/90 backdrop-blur-md border-b border-slate-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo & Title */}
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-indigo-600 to-violet-500 flex items-center justify-center shadow-lg shadow-indigo-500/20">
                <Terminal className="w-5 h-5 text-white" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-bold text-base tracking-tight text-white">REA Studio</span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                    v6.5.0
                  </span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                    Investigation Engine Ready
                  </span>
                </div>
                <p className="text-xs text-slate-400 hidden sm:block">
                  Reproducible Reverse-Engineering Platform &bull; Evidence Provenance &amp; Truth Model
                </p>
              </div>
            </div>

            {/* Quick Actions / External Links */}
            <div className="flex items-center gap-3">
              <a
                href="https://github.com/morluto/rea"
                target="_blank"
                rel="noreferrer"
                className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs font-medium text-slate-300 hover:text-white flex items-center gap-1.5 transition-colors"
              >
                <GitBranch className="w-3.5 h-3.5 text-indigo-400" />
                <span className="hidden sm:inline">GitHub:</span>
                <span>morluto/rea</span>
                <ExternalLink className="w-3 h-3 opacity-60" />
              </a>

              <a
                href="https://skills.sh/morluto/rea/reverse-engineer-anything"
                target="_blank"
                rel="noreferrer"
                className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium flex items-center gap-1.5 transition-colors shadow-sm"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">skills.sh</span>
                <span>Registry</span>
              </a>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div className="flex space-x-1 sm:space-x-4 border-t border-slate-800/60 overflow-x-auto py-1">
            <button
              onClick={() => setActiveTab('workspace')}
              className={`px-3.5 py-2 text-xs font-medium rounded-lg flex items-center gap-2 transition-colors whitespace-nowrap ${
                activeTab === 'workspace'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Compass className="w-3.5 h-3.5" />
              <span>Investigation Workspace</span>
            </button>

            <button
              onClick={() => setActiveTab('artifact')}
              className={`px-3.5 py-2 text-xs font-medium rounded-lg flex items-center gap-2 transition-colors whitespace-nowrap ${
                activeTab === 'artifact'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>Artifact Lab</span>
            </button>

            <button
              onClick={() => setActiveTab('evidence')}
              className={`px-3.5 py-2 text-xs font-medium rounded-lg flex items-center gap-2 transition-colors whitespace-nowrap ${
                activeTab === 'evidence'
                  ? 'bg-indigo-600/15 text-indigo-400 border border-indigo-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Evidence Model</span>
            </button>

            <button
              onClick={() => setActiveTab('commands')}
              className={`px-3.5 py-2 text-xs font-medium rounded-lg flex items-center gap-2 transition-colors whitespace-nowrap ${
                activeTab === 'commands'
                  ? 'bg-indigo-600/15 text-indigo-400 border border-indigo-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>CLI &amp; Command Builder</span>
            </button>

            <button
              onClick={() => setActiveTab('skills')}
              className={`px-3.5 py-2 text-xs font-medium rounded-lg flex items-center gap-2 transition-colors whitespace-nowrap ${
                activeTab === 'skills'
                  ? 'bg-indigo-600/15 text-indigo-400 border border-indigo-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <BookOpen className="w-3.5 h-3.5" />
              <span>REA Skills &amp; Docs</span>
            </button>

            <button
              onClick={() => setActiveTab('status')}
              className={`px-3.5 py-2 text-xs font-medium rounded-lg flex items-center gap-2 transition-colors whitespace-nowrap ${
                activeTab === 'status'
                  ? 'bg-indigo-600/15 text-indigo-400 border border-indigo-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span>Toolchain Health</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Core Philosophy Banner */}
        <div className="mb-6 p-4 rounded-xl bg-gradient-to-r from-slate-900 via-indigo-950/30 to-slate-900 border border-indigo-500/20 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-white">
                REA Studio — Evidence-Backed Investigation Architecture
              </h2>
              <p className="text-xs text-slate-400">
                &ldquo;The studio records what was observed, shows what can reasonably be inferred, isolates what remains unknown, and makes the investigation reproducible.&rdquo;
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
            <span>CLI rea-agents@6.5.0</span>
          </div>
        </div>

        {/* Tab Views */}
        {activeTab === 'workspace' && <InvestigationWorkspace />}
        {activeTab === 'artifact' && <ArtifactLab />}
        {activeTab === 'evidence' && <EvidenceSimulator />}
        {activeTab === 'commands' && <CommandBuilder />}
        {activeTab === 'skills' && <SkillViewer />}
        {activeTab === 'status' && <IntegrationStatus />}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 py-6 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-wrap items-center justify-between gap-4 text-xs text-slate-500">
          <div>
            Built with <strong>morluto/rea</strong> (Reverse Engineer Anything) &bull; Open-source under MIT License.
          </div>
          <div className="flex items-center gap-4">
            <a
              href="https://github.com/morluto/rea"
              target="_blank"
              rel="noreferrer"
              className="hover:text-slate-300 transition-colors"
            >
              GitHub Repository
            </a>
            <a
              href="https://skills.sh/morluto/rea/reverse-engineer-anything"
              target="_blank"
              rel="noreferrer"
              className="hover:text-slate-300 transition-colors"
            >
              skills.sh Directory
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}

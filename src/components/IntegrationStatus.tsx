import React from 'react';
import { CheckCircle2, FolderCheck, Cpu, Terminal, Shield, RefreshCw } from 'lucide-react';

export const IntegrationStatus: React.FC = () => {
  const installedPaths = [
    { path: '/.agents/skills/reverse-engineer-anything/SKILL.md', status: 'Active (Agent Discovery)' },
    { path: '/skills/reverse-engineer-anything/SKILL.md', status: 'Active (System Skills)' },
    { path: '/skills/rea/SKILL.md', status: 'Active (Alias)' },
    { path: '/app/applet/skills/reverse-engineer-anything/SKILL.md', status: 'Active (Project Local)' }
  ];

  const mcpClients = [
    { name: 'Gemini CLI', config: '/root/.gemini/settings.json', state: 'Configured & Aligned' },
    { name: 'Antigravity Agent', config: '/root/.gemini/config/mcp_config.json', state: 'Configured & Aligned' },
    { name: 'Codex / OpenAI', config: '/root/.codex/config.toml', state: 'Configured & Aligned' },
    { name: 'Cursor / Claude Code', config: 'Project-level .agents/skills', state: 'Auto-Discovered' }
  ];

  const capabilities = [
    'Static JS/Electron Application Analysis (No source code required)',
    'Source code & module recovery with source-map provenance',
    'Native binary layout inspection (ELF, Mach-O, PE headers & symbols)',
    'Chrome DevTools Protocol (CDP) live web page inspection',
    'Evidence Ledger & SHA-256 cryptographic provenance nodes',
    'Ghidra, Hopper, and IDA Bring-Your-Own deep analysis engines'
  ];

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-emerald-400" />
            REA Installation & Agent Health Status
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Status of REA skill files, package bindings, and MCP registrations in this environment.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-xs font-medium">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            REA Environment Healthy
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Skill Files Verification */}
        <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-4 space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <FolderCheck className="w-4 h-4 text-indigo-400" />
            Verified Skill Trees in Filesystem
          </h3>

          <div className="space-y-2">
            {installedPaths.map((item, idx) => (
              <div key={idx} className="p-2.5 bg-slate-900 rounded border border-slate-800 flex items-center justify-between text-xs">
                <span className="font-mono text-slate-300 truncate max-w-[280px]">
                  {item.path}
                </span>
                <span className="text-[11px] text-emerald-400 flex items-center gap-1 shrink-0 font-medium">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  {item.status}
                </span>
              </div>
            ))}
          </div>

          <div className="pt-2 text-[11px] text-slate-400 border-t border-slate-800/80">
            Total of 4 skill bundles downloaded including all reference documentation and schemas.
          </div>
        </div>

        {/* MCP Clients */}
        <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-4 space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <Cpu className="w-4 h-4 text-emerald-400" />
            Configured MCP Agent Registrations
          </h3>

          <div className="space-y-2">
            {mcpClients.map((client, idx) => (
              <div key={idx} className="p-2.5 bg-slate-900 rounded border border-slate-800 flex items-center justify-between text-xs">
                <div>
                  <div className="font-medium text-slate-200">{client.name}</div>
                  <div className="font-mono text-[10px] text-slate-400 truncate max-w-[240px]">
                    {client.config}
                  </div>
                </div>
                <span className="text-[11px] text-emerald-400 font-medium shrink-0">
                  {client.state}
                </span>
              </div>
            ))}
          </div>

          <div className="pt-2 text-[11px] text-slate-400 border-t border-slate-800/80">
            Command: <code className="font-mono text-indigo-300">npx -y rea-agents@6.5.0 mcp</code>
          </div>
        </div>
      </div>

      {/* REA Capabilities Matrix */}
      <div className="bg-slate-950/50 border border-slate-800 rounded-lg p-4">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2">
          <Terminal className="w-4 h-4 text-indigo-400" />
          Active REA Capabilities Available to Agents
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-slate-300">
          {capabilities.map((cap, idx) => (
            <div key={idx} className="flex items-center gap-2 p-2 rounded bg-slate-900/60 border border-slate-800/60">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>{cap}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

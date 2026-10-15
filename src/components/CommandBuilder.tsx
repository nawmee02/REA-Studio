import React, { useState } from 'react';
import { REA_COMMANDS, ReaCommand } from '../data/skillsData';
import { Terminal, Copy, Check, Play, Settings2, Info } from 'lucide-react';

export const CommandBuilder: React.FC = () => {
  const [selectedCmdName, setSelectedCmdName] = useState<string>(REA_COMMANDS[0].name);
  const [targetPath, setTargetPath] = useState<string>('./dist');
  const [selectedFormat, setSelectedFormat] = useState<string>('json');
  const [selectedDetail, setSelectedDetail] = useState<string>('summary');
  const [customArgs, setCustomArgs] = useState<string>('');
  const [copied, setCopied] = useState<boolean>(false);

  const selectedCommand = REA_COMMANDS.find(c => c.name === selectedCmdName) || REA_COMMANDS[0];

  // Construct dynamic command
  const buildCommandLine = () => {
    let cmd = `npx rea-agents ${selectedCommand.name}`;
    if (selectedCommand.category !== 'setup') {
      cmd += ` ${targetPath || '.'}`;
    }
    if (selectedCommand.options.some(o => o.flag.includes('--detail'))) {
      cmd += ` --detail ${selectedDetail}`;
    }
    if (selectedCommand.options.some(o => o.flag.includes('--format'))) {
      cmd += ` --format ${selectedFormat}`;
    }
    if (selectedCommand.category === 'setup') {
      cmd += ` --yes --all-detected`;
    }
    if (customArgs.trim()) {
      cmd += ` ${customArgs.trim()}`;
    }
    return cmd;
  };

  const commandLine = buildCommandLine();

  const handleCopy = () => {
    navigator.clipboard.writeText(commandLine);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6 pb-4 border-b border-slate-800">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Terminal className="w-5 h-5 text-indigo-400" />
            REA Command Builder & CLI Playground
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Construct and preview REA commands matching the installed REA CLI (v6.5.0) and skill rules.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs px-2.5 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700 font-mono">
            rea-agents@6.5.0
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Command Selector */}
        <div className="space-y-2">
          <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 block">
            Select Operation
          </label>
          <div className="space-y-1.5">
            {REA_COMMANDS.map(cmd => {
              const active = cmd.name === selectedCmdName;
              return (
                <button
                  key={cmd.name}
                  onClick={() => setSelectedCmdName(cmd.name)}
                  className={`w-full text-left p-2.5 rounded-lg text-xs font-medium border transition-colors ${
                    active
                      ? 'bg-indigo-600/20 border-indigo-500 text-white'
                      : 'bg-slate-800/40 border-slate-800 hover:bg-slate-800 text-slate-300'
                  }`}
                >
                  <div className="font-mono text-indigo-300 font-semibold">{cmd.name}</div>
                  <div className="text-[11px] text-slate-400 line-clamp-1 mt-0.5">{cmd.summary}</div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Options & Target Configuration */}
        <div className="md:col-span-2 space-y-4">
          <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-4 space-y-4">
            <div>
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Settings2 className="w-4 h-4 text-indigo-400" />
                Parameters for: <span className="font-mono text-indigo-300">{selectedCommand.name}</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">{selectedCommand.description}</p>
            </div>

            {selectedCommand.category !== 'setup' && (
              <div>
                <label className="text-xs text-slate-400 block mb-1">
                  Target Path (file, directory, or package)
                </label>
                <input
                  type="text"
                  value={targetPath}
                  onChange={e => setTargetPath(e.target.value)}
                  placeholder="./path/to/app.asar or ./dist"
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-md text-xs text-slate-200 font-mono focus:outline-none focus:border-indigo-500"
                />
              </div>
            )}

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-slate-400 block mb-1">Output Format (--format)</label>
                <select
                  value={selectedFormat}
                  onChange={e => setSelectedFormat(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-md text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                >
                  <option value="json">json (Default structured)</option>
                  <option value="toon">toon (Token-optimized notation)</option>
                  <option value="yaml">yaml</option>
                  <option value="md">markdown</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-slate-400 block mb-1">Analysis Detail (--detail)</label>
                <select
                  value={selectedDetail}
                  onChange={e => setSelectedDetail(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-md text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                >
                  <option value="summary">summary (Recommended initial pass)</option>
                  <option value="detailed">detailed</option>
                  <option value="full">full (Complete syntax & symbols)</option>
                </select>
              </div>
            </div>

            <div>
              <label className="text-xs text-slate-400 block mb-1">
                Additional Flags / Filters (Optional)
              </label>
              <input
                type="text"
                value={customArgs}
                onChange={e => setCustomArgs(e.target.value)}
                placeholder='--token-limit 3000 --filter-output "modules,entrypoint"'
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-md text-xs text-slate-200 font-mono focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>

          {/* Generated Command Box */}
          <div className="bg-slate-950 border border-slate-800 rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-slate-400 flex items-center gap-1.5">
                <Play className="w-3.5 h-3.5 text-emerald-400" />
                Generated CLI Command:
              </span>
              <button
                onClick={handleCopy}
                className="px-2.5 py-1 rounded bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium flex items-center gap-1 transition-colors"
              >
                {copied ? (
                  <>
                    <Check className="w-3 h-3" />
                    <span>Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copy Command</span>
                  </>
                )}
              </button>
            </div>

            <div className="p-3 bg-slate-900/90 rounded border border-slate-800 font-mono text-xs text-emerald-400 break-all select-all">
              {commandLine}
            </div>

            <div className="mt-3 flex items-start gap-2 text-[11px] text-slate-400">
              <Info className="w-3.5 h-3.5 text-slate-500 shrink-0 mt-0.5" />
              <span>
                Tip: REA respects <strong>summary-first</strong> investigation. Start with <code className="text-slate-300">--detail summary</code> to retrieve an Evidence ID before requesting a full decompiled walk.
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

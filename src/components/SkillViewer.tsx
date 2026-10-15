import React, { useState } from 'react';
import { REA_SKILLS, ReaSkill } from '../data/skillsData';
import { BookOpen, Check, Copy, FileText, ChevronRight, Sparkles, Shield, Cpu, Tag } from 'lucide-react';

export const SkillViewer: React.FC = () => {
  const [selectedSkillId, setSelectedSkillId] = useState<string>(REA_SKILLS[0].id);
  const [selectedRefId, setSelectedRefId] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  const selectedSkill = REA_SKILLS.find(s => s.id === selectedSkillId) || REA_SKILLS[0];
  const activeReference = selectedSkill.references?.find(r => r.id === selectedRefId);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      {/* Skill List Sidebar */}
      <div className="lg:col-span-4 space-y-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
              Installed REA Skills (4)
            </h2>
            <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              Active in Codebase
            </span>
          </div>

          <div className="space-y-2">
            {REA_SKILLS.map(skill => {
              const isSelected = skill.id === selectedSkillId;
              return (
                <button
                  key={skill.id}
                  onClick={() => {
                    setSelectedSkillId(skill.id);
                    setSelectedRefId(null);
                  }}
                  className={`w-full text-left p-3.5 rounded-lg border transition-all ${
                    isSelected
                      ? 'bg-indigo-600/10 border-indigo-500/40 text-white shadow-sm'
                      : 'bg-slate-800/40 border-slate-800 hover:bg-slate-800/80 text-slate-300 hover:text-white'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="font-medium text-sm flex items-center gap-2">
                        {skill.title}
                        {skill.version && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                            v{skill.version}
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-slate-400 mt-1 line-clamp-2">
                        {skill.description}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 mt-3 pt-2 border-t border-slate-800/60 text-[11px] text-slate-400">
                    <span className="flex items-center gap-1 text-indigo-400">
                      <Tag className="w-3 h-3" />
                      {skill.badge}
                    </span>
                    {skill.references && (
                      <span className="ml-auto text-slate-400">
                        {skill.references.length} reference guides
                      </span>
                    )}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* References Sub-Navigation */}
        {selectedSkill.references && selectedSkill.references.length > 0 && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-1.5">
              <FileText className="w-3.5 h-3.5 text-indigo-400" />
              Technical Guides ({selectedSkill.references.length})
            </h3>

            <div className="space-y-1.5">
              <button
                onClick={() => setSelectedRefId(null)}
                className={`w-full text-left px-3 py-2 rounded-md text-xs font-medium transition-colors flex items-center justify-between ${
                  selectedRefId === null
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                }`}
              >
                <span>Main SKILL.md Overview</span>
                <ChevronRight className="w-3.5 h-3.5 opacity-60" />
              </button>

              {selectedSkill.references.map(ref => {
                const isSelected = selectedRefId === ref.id;
                return (
                  <button
                    key={ref.id}
                    onClick={() => setSelectedRefId(ref.id)}
                    className={`w-full text-left px-3 py-2 rounded-md text-xs font-medium transition-colors flex items-center justify-between ${
                      isSelected
                        ? 'bg-indigo-600 text-white'
                        : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                    }`}
                  >
                    <span className="truncate">{ref.title}</span>
                    <span className="text-[10px] opacity-70 ml-2 font-mono">.md</span>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Main Document Content Panel */}
      <div className="lg:col-span-8">
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
          {/* Document Header */}
          <div className="p-5 border-b border-slate-800 bg-slate-900/80 flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-indigo-300 border border-slate-700">
                  {activeReference
                    ? `skills/${selectedSkill.name}/references/${activeReference.filename}`
                    : `skills/${selectedSkill.name}/SKILL.md`}
                </span>
                <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium">
                  Verified Local
                </span>
              </div>
              <h1 className="text-xl font-bold text-white mt-1.5 flex items-center gap-2">
                {activeReference ? activeReference.title : selectedSkill.title}
              </h1>
              <p className="text-sm text-slate-400 mt-0.5">
                {activeReference ? activeReference.description : selectedSkill.description}
              </p>
            </div>

            <button
              onClick={() =>
                copyToClipboard(
                  activeReference ? activeReference.content : selectedSkill.content,
                  'doc'
                )
              }
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 border border-slate-700 transition-colors"
            >
              {copied === 'doc' ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Copied Content</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy Markdown</span>
                </>
              )}
            </button>
          </div>

          {/* Document Body */}
          <div className="p-6 text-slate-300 space-y-4 max-h-[640px] overflow-y-auto font-sans leading-relaxed">
            <div className="prose prose-invert max-w-none">
              <pre className="p-4 bg-slate-950/80 rounded-lg border border-slate-800/80 font-mono text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap leading-5">
                {activeReference ? activeReference.content : selectedSkill.content}
              </pre>
            </div>

            {/* Path and Discovery metadata */}
            <div className="mt-6 pt-4 border-t border-slate-800/80 flex flex-wrap items-center justify-between text-xs text-slate-400">
              <div className="flex items-center gap-2">
                <span className="text-slate-400">Installed at:</span>
                <code className="text-indigo-400 bg-slate-800/60 px-1.5 py-0.5 rounded font-mono">
                  /.agents/skills/{selectedSkill.name}/
                </code>
                <code className="text-indigo-400 bg-slate-800/60 px-1.5 py-0.5 rounded font-mono">
                  /skills/{selectedSkill.name}/
                </code>
              </div>
              <span className="text-slate-400">Provider: morluto/rea</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

import React, { useState } from 'react';
import { Eye, Play, Pause, RotateCcw, Activity, ShieldOff, Zap, Sliders, ChevronDown, ChevronUp } from 'lucide-react';
import type { EveParams } from '../types';

interface EveControlPanelProps {
  sessionId: string;
  onEveParamsChange: (params: EveParams) => void;
}

const EveControlPanel: React.FC<EveControlPanelProps> = ({
  sessionId,
  onEveParamsChange
}) => {
  const [attackType, setAttackType] = useState<EveParams['attack_type']>('none');
  const [fraction, setFraction] = useState(0.5);
  const [noiseProbability, setNoiseProbability] = useState(0.1);
  const [lossProbability, setLossProbability] = useState(0.1);
  const [isAttacking, setIsAttacking] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [collapsed, setCollapsed] = useState(false);

  const logAction = (entry: string) => {
    setLogs(prev => [`${new Date().toLocaleTimeString()} · ${entry}`, ...prev].slice(0, 12));
  };

  const handleStartAttack = () => {
    const params: EveParams = {
      attack_type: attackType,
      params: {
        fraction: ['intercept_resend', 'partial_intercept'].includes(attackType) ? fraction : undefined,
        noise_probability: attackType === 'depolarizing' ? noiseProbability : undefined,
        loss_probability: attackType === 'qubit_loss' ? lossProbability : undefined,
      }
    };

    onEveParamsChange(params);
    setIsAttacking(attackType !== 'none');
    logAction(`Attack ${attackType} initiated`);
  };

  const handleStopAttack = () => {
    const params: EveParams = { attack_type: 'none', params: {} };
    onEveParamsChange(params);
    setIsAttacking(false);
    setAttackType('none');
    logAction('Attack halted — returning to passive');
  };

  const getAttackInfo = (type: EveParams['attack_type']) => {
    switch (type) {
      case 'intercept_resend': return { desc: 'Intercept, measure, resend. High impact.', qber: `~${(fraction * 25).toFixed(1)}%` };
      case 'partial_intercept': return { desc: 'Stealthy intercept of subset.', qber: `~${(fraction * 25).toFixed(1)}%` };
      case 'depolarizing': return { desc: 'Inject random noise.', qber: `~${(noiseProbability * 50).toFixed(1)}%` };
      case 'qubit_loss': return { desc: 'Drop particles (DoS).', qber: 'Variable' };
      default: return { desc: 'Passive monitoring.', qber: '0%' };
    }
  };

  const info = getAttackInfo(attackType);

  return (
    <div className={`glass-card transition-all duration-300 border-l-4 ${isAttacking ? 'border-l-red-500' : 'border-l-[var(--card-border)]'} ${collapsed ? 'py-4' : ''}`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-xl flex items-center justify-center ${isAttacking ? 'bg-red-500/20 text-red-500 animate-pulse' : 'bg-[var(--bg-secondary)] text-[var(--text-secondary)]'}`}>
            <Eye className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-[var(--text-primary)]">Eve Control</h3>
            {!collapsed && <p className="text-xs text-[var(--text-secondary)]">Adversarial Simulation</p>}
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className={`px-2 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider ${isAttacking ? 'bg-red-500 text-white shadow-lg shadow-red-500/20' : 'bg-[var(--bg-secondary)] text-[var(--text-muted)]'}`}>
            {isAttacking ? 'Active' : 'Passive'}
          </div>
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="p-1.5 rounded-lg hover:bg-[var(--bg-secondary)] text-[var(--text-secondary)]"
          >
            {collapsed ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {!collapsed && (
        <div className="space-y-6 animate-in fade-in slide-in-from-top-2">
          {/* Controls */}
          <div className="space-y-4">
            <div className="flex gap-4">
              <div className="flex-1 space-y-2">
                <label className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">Attack Vector</label>
                <div className="relative">
                  <select
                    value={attackType}
                    onChange={(e) => {
                      const next = e.target.value as EveParams['attack_type'];
                      setAttackType(next);
                      if (next !== 'none') logAction(`Targeting: ${next}`);
                    }}
                    className="w-full appearance-none bg-[var(--bg-secondary)] border border-[var(--card-border)] rounded-xl px-4 py-3 pr-10 text-sm font-medium focus:outline-none focus:ring-2 focus:ring-red-500/50 transition-shadow"
                  >
                    <option value="none">None (Passive Monitor)</option>
                    <option value="intercept_resend">Intercept & Resend</option>
                    <option value="partial_intercept">Partial Intercept</option>
                    <option value="depolarizing">Depolarizing Noise</option>
                    <option value="qubit_loss">Qubit Loss (DoS)</option>
                  </select>
                  <Sliders className="absolute right-3 top-3.5 w-4 h-4 text-[var(--text-muted)] pointer-events-none" />
                </div>
              </div>
            </div>

            {/* Dynamic Sliders */}
            {attackType !== 'none' && (
              <div className="p-4 rounded-xl bg-[var(--bg-secondary)] border border-[var(--card-border)] space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-[var(--text-primary)] flex items-center gap-2">
                    <Zap className="w-3 h-3 text-amber-500" />
                    Intensity
                  </span>
                  <span className="text-xs font-mono text-[var(--text-secondary)]">
                    {['intercept_resend', 'partial_intercept'].includes(attackType) ? `${(fraction * 100).toFixed(0)}%` :
                      attackType === 'depolarizing' ? `${(noiseProbability * 100).toFixed(0)}%` :
                        `${(lossProbability * 100).toFixed(0)}%`}
                  </span>
                </div>

                {['intercept_resend', 'partial_intercept'].includes(attackType) && (
                  <input type="range" min="0" max="1" step="0.05" value={fraction} onChange={(e) => setFraction(parseFloat(e.target.value))} className="w-full accent-red-500" />
                )}
                {attackType === 'depolarizing' && (
                  <input type="range" min="0" max="0.5" step="0.01" value={noiseProbability} onChange={(e) => setNoiseProbability(parseFloat(e.target.value))} className="w-full accent-red-500" />
                )}
                {attackType === 'qubit_loss' && (
                  <input type="range" min="0" max="0.5" step="0.01" value={lossProbability} onChange={(e) => setLossProbability(parseFloat(e.target.value))} className="w-full accent-red-500" />
                )}

                <div className="pt-2 border-t border-[var(--card-border)] flex justify-between text-[10px] text-[var(--text-muted)]">
                  <span>Estimated QBER: <strong className="text-red-500">{info.qber}</strong></span>
                  <span>{info.desc}</span>
                </div>
              </div>
            )}
          </div>

          {/* Action Buttons */}
          <div className="flex gap-3">
            {!isAttacking ? (
              <button
                onClick={handleStartAttack}
                disabled={attackType === 'none'}
                className="flex-1 py-3 rounded-xl bg-gradient-to-r from-red-500 to-orange-500 text-white font-bold text-sm shadow-lg shadow-red-500/20 hover:brightness-110 active:scale-95 transition-all disabled:opacity-50 disabled:shadow-none flex items-center justify-center gap-2"
              >
                <Play className="w-4 h-4 fill-current" />
                Execute Attack
              </button>
            ) : (
              <button
                onClick={handleStopAttack}
                className="flex-1 py-3 rounded-xl bg-[var(--bg-secondary)] text-[var(--text-primary)] font-bold text-sm border border-[var(--card-border)] hover:bg-[var(--bg-primary)] active:scale-95 transition-all flex items-center justify-center gap-2"
              >
                <Pause className="w-4 h-4 fill-current" />
                Halt Operation
              </button>
            )}

            <button
              onClick={() => {
                setAttackType('none');
                setFraction(0.5);
                setNoiseProbability(0.1);
                setLossProbability(0.1);
                handleStopAttack();
                logAction('Reset to defaults');
              }}
              className="p-3 rounded-xl bg-[var(--bg-secondary)] text-[var(--text-secondary)] border border-[var(--card-border)] hover:text-[var(--text-primary)] transition-colors"
              title="Reset Parameters"
            >
              <RotateCcw className="w-5 h-5" />
            </button>
          </div>

          {/* Logs */}
          <div className="rounded-xl border border-[var(--card-border)] bg-[var(--bg-primary)] overflow-hidden">
            <div className="bg-[var(--bg-secondary)] px-3 py-2 border-b border-[var(--card-border)] flex items-center justify-between">
              <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--text-secondary)]">Operation Log</span>
              <Activity className="w-3 h-3 text-[var(--text-muted)]" />
            </div>
            <div className="h-32 overflow-y-auto p-3 font-mono text-xs space-y-1.5 custom-scrollbar">
              {logs.length === 0 ? (
                <div className="h-full flex items-center justify-center text-[var(--text-muted)] italic opacity-50">
                  System Idle
                </div>
              ) : (
                logs.map((log, i) => (
                  <div key={i} className="flex gap-2 text-[var(--text-secondary)]">
                    <span className="opacity-50 select-none">›</span>
                    <span>{log}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default EveControlPanel;

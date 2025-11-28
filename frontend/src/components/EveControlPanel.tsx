import React, { useState } from 'react';
import { Eye, Play, Pause, RotateCcw, Activity, ShieldOff } from 'lucide-react';
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
    const params: EveParams = {
      attack_type: 'none',
      params: {}
    };
    
    onEveParamsChange(params);
    setIsAttacking(false);
    setAttackType('none');
    logAction('Attack halted — returning to passive');
  };

  const getAttackDescription = (type: EveParams['attack_type']) => {
    switch (type) {
      case 'intercept_resend':
        return 'Intercept qubits, measure them, and resend new qubits. Classic BB84 attack causing ~25% QBER.';
      case 'partial_intercept':
        return 'Intercept only a fraction of qubits to remain stealthy while still gaining information.';
      case 'depolarizing':
        return 'Introduce random bit/phase flips to simulate noisy channel or sophisticated attack.';
      case 'qubit_loss':
        return 'Drop qubits entirely, simulating lossy channel or denial-of-service attack.';
      default:
        return 'No attack selected. Alice and Bob will communicate securely.';
    }
  };

  const getTheoreticalQBER = () => {
    switch (attackType) {
      case 'intercept_resend':
        return `~${(fraction * 25).toFixed(1)}%`;
      case 'partial_intercept':
        return `~${(fraction * 25).toFixed(1)}%`;
      case 'depolarizing':
        return `~${(noiseProbability * 50).toFixed(1)}%`;
      case 'qubit_loss':
        return 'Variable';
      default:
        return '0%';
    }
  };

  const getDetectionProbability = () => {
    const threshold = 0.11; // 11% QBER threshold
    
    switch (attackType) {
      case 'intercept_resend':
        return fraction * 0.25 > threshold ? 'High' : 'Low';
      case 'partial_intercept':
        return fraction * 0.25 > threshold ? 'High' : 'Low';
      case 'depolarizing':
        return noiseProbability * 0.5 > threshold ? 'High' : 'Low';
      default:
        return 'None';
    }
  };

  return (
    <div className="glass-card glow-border eve text-white bg-black/40 border border-rose-500/20 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Eye className="w-5 h-5 text-rose-300" />
            <h3 className="text-lg font-semibold">Eve Control Panel</h3>
          </div>
          <p className="text-xs text-rose-200 mt-1">Simulate attacks on the BB84 channel</p>
        </div>
        <div className="flex items-center gap-2">
          <div className={`session-chip ${isAttacking ? 'eve' : ''}`}>
            {isAttacking ? 'ATTACKING' : 'PASSIVE'}
          </div>
          <button
            type="button"
            className="copy-button text-white"
            onClick={() => setCollapsed(prev => !prev)}
          >
            {collapsed ? 'Expand' : 'Collapse'}
          </button>
        </div>
      </div>

      {collapsed ? (
        <div className="session-chip eve text-sm justify-between w-full">
          <span>Eve Status</span>
          <span>{isAttacking ? 'Active attack' : 'Passive'}</span>
        </div>
      ) : (
        <>
          <div className="space-y-4">
            <label className="metric-label">Attack Type</label>
            <div className="flex items-center gap-3">
              <select
                value={attackType}
                onChange={(e) => {
                  const next = e.target.value as EveParams['attack_type'];
                  setAttackType(next);
                  logAction(`Mode switched to ${next}`);
                }}
                className="flex-1 bg-black/40 border border-rose-400/30 rounded-2xl px-4 py-2 text-sm text-white focus:outline-none"
              >
                <option value="none">No attack (passive)</option>
                <option value="intercept_resend">Intercept & Resend</option>
                <option value="partial_intercept">Partial Intercept</option>
                <option value="depolarizing">Depolarizing Noise</option>
                <option value="qubit_loss">Qubit Loss</option>
              </select>
              <span className="session-chip eve text-xs">
                <ShieldOff className="w-4 h-4" />
                QBER 11%
              </span>
            </div>
          </div>

          {attackType !== 'none' && (
            <div className="space-y-4">
              <h4 className="text-xs uppercase tracking-widest text-rose-200">Attack Parameters</h4>
              {['intercept_resend', 'partial_intercept'].includes(attackType) && (
                <div>
                  <div className="flex justify-between text-xs text-slate-300 mb-1">
                    <span>Intercept Fraction</span>
                    <span>{Math.round(fraction * 100)}%</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="1"
                    step="0.05"
                    value={fraction}
                    onChange={(e) => setFraction(parseFloat(e.target.value))}
                    className="w-full accent-rose-400"
                  />
                </div>
              )}
              {attackType === 'depolarizing' && (
                <div>
                  <div className="flex justify-between text-xs text-slate-300 mb-1">
                    <span>Noise Probability</span>
                    <span>{Math.round(noiseProbability * 100)}%</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="0.5"
                    step="0.01"
                    value={noiseProbability}
                    onChange={(e) => setNoiseProbability(parseFloat(e.target.value))}
                    className="w-full accent-rose-400"
                  />
                </div>
              )}
              {attackType === 'qubit_loss' && (
                <div>
                  <div className="flex justify-between text-xs text-slate-300 mb-1">
                    <span>Loss Probability</span>
                    <span>{Math.round(lossProbability * 100)}%</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="0.5"
                    step="0.01"
                    value={lossProbability}
                    onChange={(e) => setLossProbability(parseFloat(e.target.value))}
                    className="w-full accent-rose-400"
                  />
                </div>
              )}
            </div>
          )}

          <div className="rounded-2xl bg-black/40 border border-white/10 p-4 space-y-2 text-sm text-slate-100">
            <p className="text-xs uppercase tracking-widest text-rose-200">Expected Impact</p>
            <p>{getAttackDescription(attackType)}</p>
            {attackType !== 'none' && (
              <div className="text-xs text-amber-200 space-y-1">
                <div>Theoretical QBER: {getTheoreticalQBER()}</div>
                <div>Detection Probability: {getDetectionProbability()}</div>
              </div>
            )}
          </div>

          <div className="flex gap-3">
            {!isAttacking ? (
              <button
                onClick={handleStartAttack}
                disabled={attackType === 'none'}
                className="quantum-button bg-gradient-to-r from-rose-500 to-orange-500 text-white flex-1 flex items-center justify-center gap-2 disabled:opacity-40"
              >
                <Play className="w-4 h-4" />
                Start Attack
              </button>
            ) : (
              <button
                onClick={handleStopAttack}
                className="quantum-button bg-white/10 border border-white/30 text-white flex-1 flex items-center justify-center gap-2"
              >
                <Pause className="w-4 h-4" />
                Stop Attack
              </button>
            )}
            <button
              onClick={() => {
                setAttackType('none');
                setFraction(0.5);
                setNoiseProbability(0.1);
                setLossProbability(0.1);
                handleStopAttack();
                logAction('Parameters reset');
              }}
              className="quantum-button bg-black/30 border border-white/10 text-white flex items-center gap-2"
            >
              <RotateCcw className="w-4 h-4" />
              Reset
            </button>
          </div>

          <div className="grid grid-cols-2 gap-4 text-xs text-slate-200">
            <div className="rounded-xl bg-black/40 border border-white/5 p-3">
              <p className="metric-label">Session</p>
              <code className="font-mono text-white break-all">{sessionId}</code>
            </div>
            <div className="rounded-xl bg-black/40 border border-white/5 p-3">
              <p className="metric-label">Status</p>
              <span>{isAttacking ? '🔴 Injecting noise' : '🟢 Monitoring only'}</span>
            </div>
          </div>

          <div>
            <p className="metric-label mb-2">Live Attack Log</p>
            <div className="h-32 overflow-y-auto rounded-xl bg-black/50 border border-rose-400/30 p-3 font-mono text-xs text-rose-100 space-y-1">
              {logs.length === 0 ? (
                <p className="text-rose-200/70">Awaiting commands…</p>
              ) : (
                logs.map((entry, idx) => (
                  <div key={idx} className="flex items-center gap-2">
                    <Activity className="w-3 h-3 text-rose-400" />
                    <span>{entry}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default EveControlPanel;

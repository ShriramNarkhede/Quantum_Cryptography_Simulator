import React from 'react';
import type { BB84Progress, CryptoInfo } from '../types';

interface KeyStatusPanelProps {
  sessionKey: Uint8Array | null;
  progress: BB84Progress | null;
  eveDetected: boolean;
  cryptoInfo?: CryptoInfo | null;
}

const KeyStatusPanel: React.FC<KeyStatusPanelProps> = ({
  sessionKey,
  progress,
  eveDetected,
  cryptoInfo
}) => {
  const [revealKey, setRevealKey] = React.useState(false);

  const progressPct = Math.round((progress?.progress ?? 0) * 100);
  const qber = cryptoInfo?.qber ? (cryptoInfo.qber * 100).toFixed(2) : '--';

  const keyPreview = sessionKey
    ? Array.from(sessionKey.slice(0, 12)).map((byte) => byte.toString(16).padStart(2, '0')).join(' ')
    : 'No key material';

  const status = eveDetected
    ? { text: 'COMPROMISED', tone: 'bg-gradient-to-r from-amber-500 to-rose-600', icon: '⚠︎' }
    : sessionKey
      ? { text: 'SECURE', tone: 'bg-emerald-500/20 text-emerald-300', icon: '✓' }
      : { text: 'IN PROGRESS', tone: 'bg-slate-600/30 text-slate-200', icon: '…' };

  return (
    <section className="glass-card glow-border flex flex-col gap-5">
      <header className="flex items-center justify-between">
        <div>
          <p className="metric-label">Key Status</p>
          <h3 className="text-2xl font-semibold text-[var(--text-primary)]">Quantum Key Material</h3>
        </div>
        <span className={`session-chip ${eveDetected ? 'eve' : 'alice'}`}>
          <span className="font-bold tracking-widest text-xs">{status.icon}</span>
          <span className="text-xs font-semibold">{status.text}</span>
        </span>
      </header>

      <div>
        <div className="flex items-center justify-between mb-3">
          <span className="text-sm text-[var(--text-secondary)]">Key Generation</span>
          <span className="text-sm font-semibold text-[var(--text-primary)]">{progressPct}%</span>
        </div>
        <div className="h-3 rounded-full overflow-hidden relative" style={{ background: 'var(--track-bg)' }}>
          <div
            className="h-full rounded-full bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-500 transition-all duration-500"
            style={{ width: `${progressPct}%` }}
          />
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,_rgba(255,255,255,0.25),_transparent_55%)] animate-pulse opacity-50" />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="rounded-2xl border border-[var(--surface-border)] bg-[var(--panel-surface)] p-4">
          <p className="metric-label">Final Key Length</p>
          <p className="metric-value metric-value--compact">
            <span>{progress?.final_key_length ?? '--'}</span>
            <span className="metric-suffix">bytes</span>
          </p>
        </div>
        <div className="rounded-2xl border border-[var(--surface-border)] bg-[var(--panel-surface)] p-4">
          <p className="metric-label">Live QBER</p>
          <p className={`metric-value metric-value--compact ${eveDetected ? 'text-rose-300' : 'text-emerald-300'}`}>
            <span>{qber}</span>
            <span className="metric-suffix">%</span>
          </p>
        </div>
      </div>

      <div className="rounded-2xl bg-[var(--panel-surface)] border border-[var(--surface-border)] p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm text-[var(--text-secondary)]">Key Preview (demo only)</span>
          <button
            onClick={() => setRevealKey((prev) => !prev)}
            className="text-xs uppercase tracking-wider text-[var(--info)] hover:text-[var(--text-primary)]"
          >
            {revealKey ? 'Hide' : 'Reveal'}
          </button>
        </div>
        <div className={`font-mono text-sm tracking-widest text-[var(--text-primary)] ${revealKey ? '' : 'blur-sm'}`}>
          {keyPreview}
        </div>
      </div>
    </section>
  );
};

export default KeyStatusPanel;




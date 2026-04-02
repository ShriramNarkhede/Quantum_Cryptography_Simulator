import React, { useState } from 'react';
import { Key, Shield, ShieldAlert, Eye, EyeOff } from 'lucide-react';
import type { BB84Progress, CryptoInfo } from '../types';

interface KeyStatusPanelProps {
  sessionKey: Uint8Array | null;
  progress: BB84Progress | null;
  eveDetected: boolean;
  cryptoInfo?: CryptoInfo | null;
  userRole?: string;
}

const KeyStatusPanel: React.FC<KeyStatusPanelProps> = ({
  sessionKey,
  progress,
  eveDetected,
  cryptoInfo,
  userRole
}) => {
  const [revealKey, setRevealKey] = useState(false);

  const progressPct = Math.round((progress?.progress ?? 0) * 100);
  const qber = cryptoInfo?.qber ? (cryptoInfo.qber * 100).toFixed(2) : '--';

  const isEve = userRole === 'eve';

  const keyPreview = isEve
    ? 'ENCRYPTED - NO ACCESS'
    : sessionKey
      ? Array.from(sessionKey.slice(0, 12)).map((byte) => byte.toString(16).padStart(2, '0')).join(' ')
      : 'No key material generated';

  return (
    <div className="glass-card space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-xl flex items-center justify-center ${eveDetected ? 'bg-red-500/20 text-[var(--system-red)]' : 'bg-[var(--system-green)]/20 text-[var(--system-green)]'}`}>
            <Key className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-[var(--text-primary)]">Quantum Key</h3>
            <p className="text-xs text-[var(--text-secondary)] uppercase tracking-wider">
              {eveDetected ? 'Compromised' : sessionKey ? (isEve ? 'Established' : 'Secure') : 'Generating...'}
            </p>
          </div>
        </div>

        <div className={`px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider border ${eveDetected
          ? 'bg-red-500/10 border-red-500/30 text-[var(--system-red)] animate-pulse'
          : sessionKey
            ? 'bg-[var(--system-green)]/10 border-[var(--system-green)]/30 text-[var(--system-green)]'
            : 'bg-[var(--bg-secondary)] border-[var(--card-border)] text-[var(--text-muted)]'
          }`}>
          {eveDetected ? 'Unsafe' : sessionKey ? 'Active' : 'Pending'}
        </div>
      </div>

      {/* Progress Bar (if active) */}
      {!sessionKey && !eveDetected && (
        <div className="space-y-2">
          <div className="flex justify-between text-xs font-semibold text-[var(--text-secondary)]">
            <span>Distilling Key Material</span>
            <span>{progressPct}%</span>
          </div>
          <div className="h-2 w-full bg-[var(--bg-secondary)] rounded-full overflow-hidden border border-[var(--card-border)]">
            <div
              className="h-full bg-gradient-to-r from-[var(--system-cyan)] to-[var(--system-blue)] rounded-full transition-all duration-300 relative"
              style={{ width: `${progressPct}%` }}
            >
              <div className="absolute inset-0 bg-white/30 animate-[shimmer_2s_infinite]" />
            </div>
          </div>
        </div>
      )}

      {/* Metrics Grid */}
      <div className="grid grid-cols-2 gap-3">
        <div className="p-3 rounded-xl bg-[var(--bg-secondary)] border border-[var(--card-border)]">
          <div className="flex items-center gap-2 mb-1">
            <Shield className="w-3 h-3 text-[var(--system-indigo)]" />
            <span className="text-[10px] font-bold text-[var(--text-secondary)] uppercase tracking-wider">Key Length</span>
          </div>
          <p className="text-xl font-mono font-bold text-[var(--text-primary)]">
            {isEve ? '---' : progress?.final_key_length ?? 0}<span className="text-xs text-[var(--text-muted)] ml-1">bytes</span>
          </p>
        </div>

        <div className={`p-3 rounded-xl border ${eveDetected ? 'bg-red-500/5 border-red-500/20' : 'bg-[var(--bg-secondary)] border-[var(--card-border)]'}`}>
          <div className="flex items-center gap-2 mb-1">
            <ShieldAlert className={`w-3 h-3 ${eveDetected ? 'text-[var(--system-red)]' : 'text-[var(--text-muted)]'}`} />
            <span className={`text-[10px] font-bold uppercase tracking-wider ${eveDetected ? 'text-[var(--system-red)]' : 'text-[var(--text-secondary)]'}`}>Live QBER</span>
          </div>
          <p className={`text-xl font-mono font-bold ${eveDetected ? 'text-[var(--system-red)]' : 'text-[var(--system-green)]'}`}>
            {qber}<span className="text-xs opacity-50 ml-1">%</span>
          </p>
        </div>
      </div>

      {/* Key Preview */}
      <div className="p-4 rounded-xl bg-[var(--bg-primary)] border border-[var(--card-border)] space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">Key Stream Preview</span>
          {!isEve && (
            <button
              onClick={() => setRevealKey(!revealKey)}
              className="p-1.5 rounded-lg hover:bg-[var(--bg-secondary)] text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
              disabled={!sessionKey}
            >
              {revealKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          )}
        </div>

        <div className={`font-mono text-xs break-all leading-relaxed transition-all duration-300 ${revealKey && !isEve ? 'text-[var(--text-primary)] blur-none' : 'text-[var(--text-muted)] blur-sm select-none'}`}>
          {keyPreview}
        </div>

        {sessionKey && !isEve && (
          <div className="text-[10px] text-center text-[var(--text-muted)] pt-2 border-t border-[var(--card-border)]/50">
            SHA-256 Verified • AES-GCM Ready
          </div>
        )}

        {isEve && (
          <div className="text-[10px] text-center text-[var(--system-red)] pt-2 border-t border-[var(--card-border)]/50">
            Insufficient Privileges • Payload Encrypted
          </div>
        )}
      </div>
    </div>
  );
};

export default KeyStatusPanel;

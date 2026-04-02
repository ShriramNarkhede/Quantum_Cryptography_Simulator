import React, { useState } from 'react';
import { Copy, CheckCircle2, AlertTriangle, Wifi, WifiOff, Zap, Users, Shield } from 'lucide-react';
import type { Session, User } from '../types';

interface SessionControlPanelProps {
  session: Session | null;
  user: User | null;
  isConnected: boolean;
  serverOnline: boolean;
  eveDetected: boolean;
  sessionKeyReady: boolean;
  highContrast: boolean;
  onToggleHighContrast: () => void;
}

const roleMeta: Record<string, { label: string; bg: string; text: string; border: string }> = {
  alice: { label: 'Alice (Sender)', bg: 'bg-cyan-500/10', text: 'text-cyan-600', border: 'border-cyan-200' },
  bob: { label: 'Bob (Receiver)', bg: 'bg-indigo-500/10', text: 'text-indigo-600', border: 'border-indigo-200' },
  eve: { label: 'Eve (Attacker)', bg: 'bg-red-500/10', text: 'text-red-600', border: 'border-red-200' }
};

const SessionControlPanel: React.FC<SessionControlPanelProps> = ({
  session,
  user,
  isConnected,
  serverOnline,
  eveDetected,
  sessionKeyReady,
  highContrast,
  onToggleHighContrast
}) => {
  const [copied, setCopied] = useState(false);
  const sessionId = session?.session_id ?? 'No session active';

  const participants = React.useMemo(() => {
    if (!session) return [];
    const unique = new Map<string, Session['participants'][0]>();
    session.participants?.forEach((p) => unique.set(p.role, p));
    if (user && !unique.has(user.role)) {
      unique.set(user.role, {
        user_id: user.user_id,
        role: user.role,
        connected: true,
        joined_at: user.joined_at,
        last_activity: user.last_activity
      });
    }
    return Array.from(unique.values());
  }, [session, user]);

  const copySessionId = async () => {
    if (!session?.session_id) return;
    try {
      await navigator.clipboard.writeText(session.session_id);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  };

  const getStatusConfig = () => {
    if (!serverOnline) return { icon: WifiOff, text: 'Server Offline', color: 'text-[var(--system-red)]', bg: 'bg-red-500/10' };
    if (!isConnected) return { icon: AlertTriangle, text: 'Disconnected', color: 'text-[var(--system-orange)]', bg: 'bg-orange-500/10' };
    return { icon: Wifi, text: 'Connected', color: 'text-[var(--system-green)]', bg: 'bg-green-500/10' };
  };

  const status = getStatusConfig();

  return (
    <div className="glass-card space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
        {/* Session ID Section */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-[var(--text-secondary)]">
            <Shield className="w-4 h-4" />
            <span className="text-xs font-bold uppercase tracking-wider">Session Identifier</span>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <div className="px-4 py-2 rounded-xl bg-[var(--bg-secondary)] border border-[var(--card-border)] font-mono text-sm tracking-widest text-[var(--text-primary)] shadow-inner">
              {sessionId}
            </div>
            {session?.session_id && (
              <button
                onClick={copySessionId}
                className="p-2 rounded-lg hover:bg-[var(--bg-secondary)] text-[var(--text-secondary)] transition-colors active:scale-95"
                title="Copy Session ID"
              >
                {copied ? <CheckCircle2 className="w-5 h-5 text-[var(--system-green)]" /> : <Copy className="w-5 h-5" />}
              </button>
            )}
          </div>
        </div>

        {/* Status Pills */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Connection Status */}
          <div className={`px-3 py-1.5 rounded-full border border-current flex items-center gap-2 ${status.color} ${status.bg} bg-opacity-20`}>
            <status.icon className="w-4 h-4" />
            <span className="text-xs font-bold">{status.text}</span>
          </div>

          {/* Security Status */}
          <div className={`px-3 py-1.5 rounded-full border border-current flex items-center gap-2 ${eveDetected ? 'text-[var(--system-red)] bg-red-500/10' : 'text-[var(--system-green)] bg-green-500/10'} bg-opacity-20`}>
            {eveDetected ? <AlertTriangle className="w-4 h-4" /> : <Zap className="w-4 h-4" />}
            <span className="text-xs font-bold">{eveDetected ? 'Compromised' : 'Secure'}</span>
          </div>

          <button
            onClick={onToggleHighContrast}
            className={`px-3 py-1.5 rounded-full border text-xs font-bold transition-all ${highContrast ? 'bg-black text-white border-black' : 'bg-transparent text-[var(--text-secondary)] border-[var(--card-border)] hover:bg-[var(--bg-secondary)]'}`}
          >
            High Contrast
          </button>
        </div>
      </div>

      {/* Participants */}
      <div className="pt-4 border-t border-[var(--card-border)]">
        <div className="flex items-center gap-2 mb-3 text-[var(--text-secondary)]">
          <Users className="w-4 h-4" />
          <span className="text-xs font-bold uppercase tracking-wider">Active Participants</span>
        </div>
        <div className="flex flex-wrap gap-3">
          {participants.length === 0 ? (
            <span className="text-sm text-[var(--text-muted)] italic">Waiting for connection...</span>
          ) : (
            participants.map((p) => {
              const meta = roleMeta[p.role] || { label: p.role, bg: 'bg-gray-100', text: 'text-gray-600', border: 'border-gray-200' };
              return (
                <div key={p.role} className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border ${meta.bg} ${meta.border}`}>
                  <div className={`w-2 h-2 rounded-full ${p.connected ? 'bg-[var(--system-green)]' : 'bg-gray-300'}`} />
                  <span className={`text-xs font-bold ${meta.text}`}>{meta.label}</span>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};

export default SessionControlPanel;

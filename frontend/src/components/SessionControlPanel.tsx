import React from 'react';
import { Copy, CheckCircle2, AlertTriangle, Wifi, WifiOff, Zap } from 'lucide-react';
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

const roleMeta: Record<string, { label: string; accent: string }> = {
  alice: { label: 'Alice · Sender', accent: 'alice' },
  bob: { label: 'Bob · Receiver', accent: 'bob' },
  eve: { label: 'Eve · Attacker', accent: 'eve' }
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
  const [copied, setCopied] = React.useState(false);

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

  const status = {
    icon: !serverOnline ? <WifiOff className="text-rose-400" /> :
      !isConnected ? <AlertTriangle className="text-amber-300" /> :
        <Wifi className="text-emerald-300" />,
    text: !serverOnline ? 'Server offline' :
      !isConnected ? 'Link disrupted' :
        'Quantum link stable',
    tone: !serverOnline ? 'text-rose-300' :
      !isConnected ? 'text-amber-200' : 'text-emerald-300'
  };

  const security = eveDetected
    ? { text: 'Session compromised', tone: 'text-rose-300', icon: <AlertTriangle className="text-rose-400" /> }
    : sessionKeyReady
      ? { text: 'Secure channel active', tone: 'text-emerald-300', icon: <CheckCircle2 className="text-emerald-300" /> }
      : { text: 'Awaiting key generation', tone: 'text-slate-200', icon: <Zap className="text-slate-200" /> };

  return (
    <section className="glass-card glow-border relative overflow-hidden">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
        <div className="space-y-3">
          <p className="metric-label">Session ID</p>
          <div className="flex flex-wrap items-center gap-3">
            <code className="font-mono text-lg tracking-widest px-3 py-2 rounded-xl bg-black/40 border border-white/10">
              {sessionId}
            </code>
            {session?.session_id && (
              <button
                onClick={copySessionId}
                className="copy-button flex items-center gap-2"
                aria-label="Copy session id"
              >
                <Copy className="w-4 h-4" />
                {copied ? 'Copied' : 'Copy'}
              </button>
            )}
            <button
              onClick={onToggleHighContrast}
              className={`copy-button ${highContrast ? 'bg-emerald-500/10 text-emerald-200 border-emerald-300/50' : ''}`}
            >
              {highContrast ? 'High Contrast: ON' : 'High Contrast'}
            </button>
          </div>
        </div>

        <div className="flex-1 flex flex-wrap gap-4 justify-start lg:justify-end">
          {[security, status].map((item, idx) => (
            <div key={idx} className="session-chip">
              {item.icon}
              <span className={`${item.tone} text-sm font-medium`}>{item.text}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-6 flex flex-wrap gap-3">
        {participants.length === 0 && (
          <span className="session-chip text-slate-200">Waiting for participants…</span>
        )}
        {participants.map((participant) => {
          const meta = roleMeta[participant.role] ?? { label: participant.role, accent: 'slate' };
          return (
            <span
              key={participant.role}
              className={`session-chip ${meta.accent}`}
            >
              <span className="text-sm font-medium">{meta.label}</span>
              <span className="text-xs text-slate-400">
                {participant.connected ? '● linked' : '○ offline'}
              </span>
            </span>
          );
        })}
      </div>
    </section>
  );
};

export default SessionControlPanel;




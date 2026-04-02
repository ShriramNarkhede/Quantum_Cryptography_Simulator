import React from 'react';
import { User, Users, Key, AlertTriangle, CheckCircle, Clock } from 'lucide-react';
import type { User as UserType, Session, BB84Progress } from '../types';

interface StatusBarProps {
  currentUser: UserType | null;
  currentSession: Session | null;
  bb84Progress: BB84Progress | null;
  eveDetected: boolean;
  hasSessionKey: boolean;
}

const StatusBar: React.FC<StatusBarProps> = ({
  currentUser,
  currentSession,
  bb84Progress,
  eveDetected,
  hasSessionKey
}) => {
  if (!currentUser || !currentSession) {
    return null;
  }

  const getRoleColor = (role: string) => {
    switch (role) {
      case 'alice': return 'text-[var(--system-cyan)] bg-cyan-500/10 border-cyan-200/50';
      case 'bob': return 'text-[var(--system-indigo)] bg-indigo-500/10 border-indigo-200/50';
      case 'eve': return 'text-[var(--system-red)] bg-red-500/10 border-red-200/50';
      default: return 'text-[var(--text-secondary)] bg-[var(--bg-secondary)] border-[var(--card-border)]';
    }
  };

  const getStatusIcon = () => {
    if (eveDetected) {
      return <AlertTriangle className="w-5 h-5 text-[var(--system-red)]" />;
    }
    if (hasSessionKey) {
      return <CheckCircle className="w-5 h-5 text-[var(--system-green)]" />;
    }
    if (bb84Progress) {
      return <Clock className="w-5 h-5 text-[var(--system-blue)]" />;
    }
    return <Users className="w-5 h-5 text-[var(--text-secondary)]" />;
  };

  const getStatusText = () => {
    if (eveDetected) {
      return 'Session Compromised';
    }
    if (hasSessionKey) {
      return 'Secure Channel';
    }
    if (bb84Progress) {
      return bb84Progress.message || 'BB84 Running...';
    }
    return 'Ready to Start';
  };

  return (
    <div className={`p-5 rounded-2xl material-regular backdrop-blur-md shadow-sm border border-[var(--card-border)] ${eveDetected ? 'ring-2 ring-red-500/30' : ''}`}>
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
        {/* Left Side - User & Session Info */}
        <div className="flex flex-wrap items-center gap-4">
          {/* Current User */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[var(--bg-primary)] border border-[var(--card-border)]">
            <User className="w-3.5 h-3.5 text-[var(--text-muted)]" />
            <span className="text-xs text-[var(--text-secondary)] font-medium">You:</span>
            <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide border ${getRoleColor(currentUser.role)}`}>
              {currentUser.role}
            </span>
          </div>

          {/* Session ID */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[var(--bg-primary)] border border-[var(--card-border)]">
            <Users className="w-3.5 h-3.5 text-[var(--text-muted)]" />
            <span className="text-xs text-[var(--text-secondary)] font-medium">Session:</span>
            <code className="text-xs font-mono text-[var(--text-primary)]">
              {currentSession.session_id}
            </code>
          </div>

          {/* Participants Count */}
          <div className="text-xs text-[var(--text-muted)] font-medium px-2">
            {currentSession.participants?.length || 1} online
          </div>
        </div>

        {/* Right Side - Status */}
        <div className="flex items-center gap-4 w-full lg:w-auto justify-between lg:justify-end">
          {/* BB84 Progress */}
          {bb84Progress && (
            <div className="flex items-center gap-3 bg-[var(--bg-primary)] px-3 py-1.5 rounded-full border border-[var(--card-border)]">
              <div className="w-24 bg-gray-200 rounded-full h-1.5 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-300 ${eveDetected ? 'bg-red-500' : hasSessionKey ? 'bg-green-500' : 'bg-blue-500'
                    }`}
                  style={{ width: `${(bb84Progress.progress || 0) * 100}%` }}
                />
              </div>
              <span className="text-[10px] font-bold text-[var(--text-muted)] w-8 text-right">
                {Math.round((bb84Progress.progress || 0) * 100)}%
              </span>
            </div>
          )}

          {/* Main Status */}
          <div className="flex items-center gap-2">
            {getStatusIcon()}
            <span className={`text-sm font-bold tracking-tight ${eveDetected ? 'text-[var(--system-red)]' :
                hasSessionKey ? 'text-[var(--system-green)]' :
                  bb84Progress ? 'text-[var(--system-blue)]' : 'text-[var(--text-secondary)]'
              }`}>
              {getStatusText()}
            </span>
          </div>
        </div>
      </div>

      {/* BB84 Detailed Progress */}
      {bb84Progress && (
        <div className="mt-4 pt-3 border-t border-[var(--card-border)] animate-in slide-in-from-top-1">
          <div className="flex flex-wrap items-center justify-between text-xs font-medium text-[var(--text-secondary)] gap-y-2">
            <span className="bg-[var(--bg-primary)] px-2 py-1 rounded-md border border-[var(--card-border)]">Stage: {bb84Progress.stage?.replace('_', ' ').toUpperCase()}</span>
            {bb84Progress.qber !== undefined && (
              <span className="flex items-center gap-2">
                QBER: <span className={bb84Progress.qber > (bb84Progress.threshold || 0.11) ? 'text-red-500' : 'text-green-500'}>{(bb84Progress.qber * 100).toFixed(2)}%</span>
                {bb84Progress.threshold && (
                  <span className="text-[var(--text-muted)]">
                    (Max: {(bb84Progress.threshold * 100).toFixed(1)}%)
                  </span>
                )}
              </span>
            )}
            {bb84Progress.sifted_length !== undefined && bb84Progress.original_length !== undefined && (
              <span>
                Bits: {bb84Progress.sifted_length} / {bb84Progress.original_length}
              </span>
            )}
            {bb84Progress.final_key_length && (
              <span className="text-[var(--system-green)]">Final Key: {bb84Progress.final_key_length} bytes</span>
            )}
          </div>
        </div>
      )}

      {/* Eve Detection Warning */}
      {eveDetected && (
        <div className="mt-3 p-3 rounded-xl bg-red-500/10 border border-red-500/20 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0" />
          <div>
            <p className="text-sm font-bold text-red-700">Security Alert: Eavesdropper Detected</p>
            <p className="text-xs text-red-600/80 mt-0.5">
              Quantum error rates indicate active interception. The protocol has been aborted to protect information.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

export default StatusBar;

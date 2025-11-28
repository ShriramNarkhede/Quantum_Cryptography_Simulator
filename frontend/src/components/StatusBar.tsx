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
      case 'alice': return 'text-alice bg-green-100';
      case 'bob': return 'text-bob bg-blue-100';
      case 'eve': return 'text-eve bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusIcon = () => {
    if (eveDetected) {
      return <AlertTriangle className="w-5 h-5 text-red-500" />;
    }
    if (hasSessionKey) {
      return <CheckCircle className="w-5 h-5 text-green-500" />;
    }
    if (bb84Progress) {
      return <Clock className="w-5 h-5 text-blue-500" />;
    }
    return <Users className="w-5 h-5 text-gray-500" />;
  };

  const getStatusText = () => {
    if (eveDetected) {
      return 'Eve Detected - Session Compromised';
    }
    if (hasSessionKey) {
      return 'Secure Channel Established';
    }
    if (bb84Progress) {
      return bb84Progress.message || 'BB84 in progress...';
    }
    return 'Ready for Key Generation';
  };

  const getStatusColor = () => {
    if (eveDetected) {
      return 'bg-red-50 border-red-200';
    }
    if (hasSessionKey) {
      return 'bg-green-50 border-green-200';
    }
    if (bb84Progress) {
      return 'bg-blue-50 border-blue-200';
    }
    return 'bg-gray-50 border-gray-200';
  };

  return (
    <div className={`p-4 rounded-lg border ${getStatusColor()}`}>
      <div className="flex items-center justify-between">
        {/* Left Side - User & Session Info */}
        <div className="flex items-center space-x-4">
          {/* Current User */}
          <div className="flex items-center space-x-2">
            <User className="w-4 h-4 text-gray-500" />
            <span className="text-sm font-medium text-gray-700">You are:</span>
            <span className={`px-2 py-1 rounded-full text-xs font-medium ${getRoleColor(currentUser.role)}`}>
              {currentUser.role.charAt(0).toUpperCase() + currentUser.role.slice(1)}
            </span>
          </div>

          {/* Session ID */}
          <div className="flex items-center space-x-2">
            <Users className="w-4 h-4 text-gray-500" />
            <span className="text-sm font-medium text-gray-700">Session:</span>
            <code className="px-2 py-1 bg-gray-100 rounded text-xs font-mono">
              {currentSession.session_id}
            </code>
          </div>

          {/* Participants Count */}
          <div className="text-sm text-gray-600">
            {currentSession.participants?.length || 1} participant(s)
          </div>
        </div>

        {/* Right Side - Status */}
        <div className="flex items-center space-x-3">
          {/* BB84 Progress */}
          {bb84Progress && (
            <div className="flex items-center space-x-2">
              <div className="w-32 bg-gray-200 rounded-full h-2">
                <div
                  className={`h-2 rounded-full transition-all duration-300 ${
                    eveDetected ? 'bg-red-500' : hasSessionKey ? 'bg-green-500' : 'bg-blue-500'
                  }`}
                  style={{ width: `${(bb84Progress.progress || 0) * 100}%` }}
                />
              </div>
              <span className="text-xs text-gray-600">
                {Math.round((bb84Progress.progress || 0) * 100)}%
              </span>
            </div>
          )}

          {/* Key Status */}
          {hasSessionKey && (
            <div className="flex items-center space-x-1">
              <Key className="w-4 h-4 text-green-600" />
              <span className="text-xs text-green-600 font-medium">Key Ready</span>
            </div>
          )}

          {/* Main Status */}
          <div className="flex items-center space-x-2">
            {getStatusIcon()}
            <span className={`text-sm font-medium ${
              eveDetected ? 'text-red-700' : 
              hasSessionKey ? 'text-green-700' : 
              bb84Progress ? 'text-blue-700' : 'text-gray-700'
            }`}>
              {getStatusText()}
            </span>
          </div>
        </div>
      </div>

      {/* BB84 Detailed Progress */}
      {bb84Progress && (
        <div className="mt-3 pt-3 border-t border-gray-200">
          <div className="flex items-center justify-between text-xs text-gray-600">
            <span>Stage: {bb84Progress.stage}</span>
            {bb84Progress.qber !== undefined && (
              <span>
                QBER: {(bb84Progress.qber * 100).toFixed(2)}%
                {bb84Progress.threshold && (
                  <span className="ml-1">
                    (Threshold: {(bb84Progress.threshold * 100).toFixed(1)}%)
                  </span>
                )}
              </span>
            )}
            {bb84Progress.sifted_length !== undefined && bb84Progress.original_length !== undefined && (
              <span>
                Sifted: {bb84Progress.sifted_length}/{bb84Progress.original_length} bits
              </span>
            )}
            {bb84Progress.final_key_length && (
              <span>Final Key: {bb84Progress.final_key_length} bytes</span>
            )}
          </div>
        </div>
      )}

      {/* Eve Detection Warning */}
      {eveDetected && (
        <div className="mt-3 pt-3 border-t border-red-200">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-red-500" />
            <span className="text-sm text-red-700">
              Quantum bit error rate exceeded threshold. Communication channel may be compromised.
            </span>
          </div>
        </div>
      )}
    </div>
  );
};

export default StatusBar;


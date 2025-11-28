// src/components/CryptoMonitor.tsx
import React from 'react';
import { Shield, AlertTriangle, CheckCircle, Clock } from 'lucide-react';
import type { CryptoInfo, EncryptionStatus } from '../types';

interface CryptoMonitorProps {
  cryptoInfo: CryptoInfo | null;
  encryptionStatus: EncryptionStatus;
  securityRecommendations: string[];
}

const CryptoMonitor: React.FC<CryptoMonitorProps> = ({
  cryptoInfo,
  encryptionStatus,
  securityRecommendations
}) => {
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatTime = (seconds: number): string => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    
    if (hours > 0) return `${hours}h ${minutes}m`;
    if (minutes > 0) return `${minutes}m ${secs}s`;
    return `${secs}s`;
  };

  return (
    <div className="glass-card glow-border space-y-4">
      <div className="flex items-center space-x-2">
        <Shield className="w-5 h-5 text-[var(--info)]" />
        <h3 className="text-lg font-medium text-[var(--text-primary)]">Crypto Monitor</h3>
      </div>

      <div className="space-y-4">
        <div className="flex items-center justify-between p-3 rounded-xl bg-[var(--bg-tertiary)] border border-[var(--surface-border)]">
          <div className="flex items-center space-x-3">
            <span className="text-2xl">{encryptionStatus.icon}</span>
            <div>
              <div className={`font-medium ${encryptionStatus.color}`}>
                {encryptionStatus.description}
              </div>
              <div className="text-sm text-[var(--text-secondary)]">
                {encryptionStatus.status === 'none' ? 'No encryption active' : 
                 encryptionStatus.status === 'hybrid' ? 'Maximum security mode' :
                 'Quantum security active'}
              </div>
            </div>
          </div>
        </div>

        {cryptoInfo && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-3">
              <div className="flex items-center justify-between text-sm text-[var(--text-secondary)]">
                <span>Messages</span>
                <span className="font-medium text-[var(--text-primary)]">{cryptoInfo.crypto_stats.message_count}</span>
              </div>
              <div className="flex items-center justify-between text-sm text-[var(--text-secondary)]">
                <span>Files</span>
                <span className="font-medium text-[var(--text-primary)]">{cryptoInfo.crypto_stats.file_count}</span>
              </div>
              <div className="flex items-center justify-between text-sm text-[var(--text-secondary)]">
                <span>Key Usage</span>
                <span className="font-medium text-[var(--text-primary)]">
                  {formatBytes(cryptoInfo.crypto_stats.total_key_stream_bytes)}
                </span>
              </div>
            </div>
            
            <div className="space-y-3">
              <div className="flex items-center justify-between text-sm text-[var(--text-secondary)]">
                <span>QBER</span>
                <span className={`font-medium ${
                  cryptoInfo.qber && cryptoInfo.qber > cryptoInfo.qber_threshold 
                    ? 'text-[var(--eve)]' : 'text-[var(--success)]'
                }`}>
                  {cryptoInfo.qber ? `${(cryptoInfo.qber * 100).toFixed(2)}%` : 'N/A'}
                </span>
              </div>
              <div className="flex items-center justify-between text-sm text-[var(--text-secondary)]">
                <span>Key Age</span>
                <span className="font-medium text-[var(--text-primary)]">
                  {formatTime(cryptoInfo.key_age_seconds)}
                </span>
              </div>
              <div className="flex items-center justify-between text-sm text-[var(--text-secondary)]">
                <span>Violations</span>
                <span className={`font-medium ${
                  cryptoInfo.security_violations > 0 ? 'text-[var(--eve)]' : 'text-[var(--success)]'
                }`}>
                  {cryptoInfo.security_violations}
                </span>
              </div>
            </div>
          </div>
        )}

        {securityRecommendations.length > 0 && (
          <div className="border-t border-[var(--surface-border)] pt-4">
            <h4 className="text-sm font-medium text-[var(--text-primary)] mb-2 flex items-center">
              <AlertTriangle className="w-4 h-4 mr-2 text-[var(--warning)]" />
              Security Recommendations
            </h4>
            <div className="space-y-1">
              {securityRecommendations.slice(0, 3).map((rec, index) => (
                <div key={index} className="text-xs text-[var(--text-secondary)] flex items-start">
                  <span className="text-[var(--warning)] mr-1">•</span>
                  <span>{rec}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {cryptoInfo && (
          <div className="border-t border-[var(--surface-border)] pt-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-[var(--text-secondary)]">Key Rotation</span>
              <div className="flex items-center space-x-1">
                {cryptoInfo.needs_key_rotation ? (
                  <>
                    <Clock className="w-4 h-4 text-[var(--warning)]" />
                    <span className="text-sm text-[var(--warning)] font-medium">Recommended</span>
                  </>
                ) : (
                  <>
                    <CheckCircle className="w-4 h-4 text-[var(--success)]" />
                    <span className="text-sm text-[var(--success)] font-medium">Current</span>
                  </>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};


export default CryptoMonitor ;


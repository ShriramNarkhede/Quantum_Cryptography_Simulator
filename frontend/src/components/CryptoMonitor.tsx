// src/components/CryptoMonitor.tsx
import React from 'react';
import { Shield, Key, Activity, AlertTriangle, CheckCircle, Clock } from 'lucide-react';
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
    <div className="bg-white border rounded-lg shadow-sm">
      <div className="p-4 border-b bg-gray-50">
        <div className="flex items-center space-x-2">
          <Shield className="w-5 h-5 text-blue-600" />
          <h3 className="text-lg font-medium text-gray-900">Crypto Monitor</h3>
        </div>
      </div>

      <div className="p-4 space-y-4">
        {/* Encryption Status */}
        <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
          <div className="flex items-center space-x-3">
            <span className="text-2xl">{encryptionStatus.icon}</span>
            <div>
              <div className={`font-medium ${encryptionStatus.color}`}>
                {encryptionStatus.description}
              </div>
              <div className="text-sm text-gray-600">
                {encryptionStatus.status === 'none' ? 'No encryption active' : 
                 encryptionStatus.status === 'hybrid' ? 'Maximum security mode' :
                 'Quantum security active'}
              </div>
            </div>
          </div>
        </div>

        {/* Crypto Statistics */}
        {cryptoInfo && (
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Messages</span>
                <span className="font-medium">{cryptoInfo.crypto_stats.message_count}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Files</span>
                <span className="font-medium">{cryptoInfo.crypto_stats.file_count}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Key Usage</span>
                <span className="font-medium">
                  {formatBytes(cryptoInfo.crypto_stats.total_key_stream_bytes)}
                </span>
              </div>
            </div>
            
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">QBER</span>
                <span className={`font-medium ${
                  cryptoInfo.qber && cryptoInfo.qber > cryptoInfo.qber_threshold 
                    ? 'text-red-600' : 'text-green-600'
                }`}>
                  {cryptoInfo.qber ? `${(cryptoInfo.qber * 100).toFixed(2)}%` : 'N/A'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Key Age</span>
                <span className="font-medium">
                  {formatTime(cryptoInfo.key_age_seconds)}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Violations</span>
                <span className={`font-medium ${
                  cryptoInfo.security_violations > 0 ? 'text-red-600' : 'text-green-600'
                }`}>
                  {cryptoInfo.security_violations}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Security Recommendations */}
        {securityRecommendations.length > 0 && (
          <div className="border-t pt-4">
            <h4 className="text-sm font-medium text-gray-700 mb-2 flex items-center">
              <AlertTriangle className="w-4 h-4 mr-2 text-yellow-500" />
              Security Recommendations
            </h4>
            <div className="space-y-1">
              {securityRecommendations.slice(0, 3).map((rec, index) => (
                <div key={index} className="text-xs text-gray-600 flex items-start">
                  <span className="text-yellow-500 mr-1">•</span>
                  <span>{rec}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Key Rotation Status */}
        {cryptoInfo && (
          <div className="border-t pt-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Key Rotation</span>
              <div className="flex items-center space-x-1">
                {cryptoInfo.needs_key_rotation ? (
                  <>
                    <Clock className="w-4 h-4 text-yellow-500" />
                    <span className="text-sm text-yellow-600 font-medium">Recommended</span>
                  </>
                ) : (
                  <>
                    <CheckCircle className="w-4 h-4 text-green-500" />
                    <span className="text-sm text-green-600 font-medium">Current</span>
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
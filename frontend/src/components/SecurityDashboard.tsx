// src/components/SecurityDashboard.tsx
import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { Shield, AlertTriangle, Activity, TrendingUp, CheckCircle } from 'lucide-react';
import type { CryptoInfo, QBERDataPoint, SessionHealthAssessment, SecurityViolation } from '../types';

interface SecurityDashboardProps {
  cryptoInfo: CryptoInfo | null;
  qberHistory: QBERDataPoint[];
  securityViolations: SecurityViolation[];
  sessionHealth: SessionHealthAssessment;
}

const SecurityDashboard: React.FC<SecurityDashboardProps> = ({
  cryptoInfo,
  qberHistory,
  securityViolations,
  sessionHealth
}) => {
  // Prepare QBER chart data
  const qberChartData = qberHistory.map((point, index) => ({
    index,
    qber: point.qber * 100,
    threshold: point.threshold * 100,
    timestamp: new Date(point.timestamp).toLocaleTimeString()
  }));

  // Health score color
  const getHealthColor = (score: number) => {
    if (score >= 90) return 'text-green-600';
    if (score >= 70) return 'text-blue-600';
    if (score >= 50) return 'text-yellow-600';
    return 'text-red-600';
  };

  const getHealthBgColor = (score: number) => {
    if (score >= 90) return 'bg-green-500/10 border border-green-400/30';
    if (score >= 70) return 'bg-blue-500/10 border border-blue-400/30';
    if (score >= 50) return 'bg-yellow-500/10 border border-yellow-400/30';
    return 'bg-red-500/10 border border-red-400/30';
  };

  // Risk level colors
  const getRiskColor = (risk: SessionHealthAssessment['risk_level']) => {
    switch (risk) {
      case 'MINIMAL': return 'text-green-300 bg-green-500/15 border border-green-400/30';
      case 'LOW': return 'text-blue-300 bg-blue-500/15 border border-blue-400/30';
      case 'MEDIUM': return 'text-yellow-300 bg-yellow-500/15 border border-yellow-400/30';
      case 'HIGH': return 'text-orange-300 bg-orange-500/15 border border-orange-400/30';
      case 'CRITICAL': return 'text-red-300 bg-red-500/15 border border-red-400/30';
      default: return 'text-[var(--text-secondary)] bg-white/10 border border-white/20';
    }
  };

  // Security metrics for pie chart
  const securityMetrics = cryptoInfo ? [
    { name: 'Secure Messages', value: cryptoInfo.crypto_stats.message_count, color: '#10b981' },
    { name: 'Encrypted Files', value: cryptoInfo.crypto_stats.file_count, color: '#3b82f6' },
    { name: 'Key Stream Used', value: Math.floor(cryptoInfo.crypto_stats.total_key_stream_bytes / 1024), color: '#8b5cf6' },
  ] : [];

  const surfaceStyle = { background: 'var(--card-surface)', borderColor: 'var(--card-border)' };
  const subtleSurfaceStyle = { background: 'var(--bg-secondary)', borderColor: 'var(--card-border)' };

  return (
    <div className="glass-card glow-border space-y-6">
      <div className="flex items-center justify-between pb-2 border-b border-[var(--card-border)]">
        <div className="flex items-center gap-2">
          <Shield className="w-6 h-6 text-[var(--info)]" />
          <h2 className="text-xl font-semibold text-[var(--text-primary)]">Security Dashboard</h2>
        </div>
        <div className={`px-3 py-1 rounded-full text-sm font-medium ${getRiskColor(sessionHealth.risk_level)}`}>
          Risk: {sessionHealth.risk_level}
        </div>
      </div>

      <div className="space-y-6">
        {/* Health Score and Overview */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Health Score */}
          <div className={`p-4 rounded-lg border ${getHealthBgColor(sessionHealth.score)}`}>
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-medium text-[var(--text-secondary)]">Session Health</h3>
                <div className={`text-3xl font-bold ${getHealthColor(sessionHealth.score)}`}>
                  {sessionHealth.score.toFixed(0)}
                </div>
                <div className="text-xs text-[var(--text-muted)]">out of 100</div>
              </div>
              <Activity className={`w-8 h-8 ${getHealthColor(sessionHealth.score)}`} />
            </div>
          </div>

          {/* QBER Status */}
          <div className="p-4 rounded-lg border" style={surfaceStyle}>
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-medium text-[var(--text-secondary)]">Current QBER</h3>
                <div className={`text-3xl font-bold ${
                  cryptoInfo?.qber && cryptoInfo.qber > cryptoInfo.qber_threshold 
                    ? 'text-red-500' : 'text-[var(--info)]'
                }`}>
                  {cryptoInfo?.qber ? `${(cryptoInfo.qber * 100).toFixed(1)}%` : '0.0%'}
                </div>
                <div className="text-xs text-[var(--text-muted)]">
                  Threshold: {cryptoInfo ? (cryptoInfo.qber_threshold * 100).toFixed(1) : '11.0'}%
                </div>
              </div>
              <TrendingUp className={`w-8 h-8 ${
                cryptoInfo?.qber && cryptoInfo.qber > cryptoInfo.qber_threshold 
                  ? 'text-red-500' : 'text-[var(--info)]'
              }`} />
            </div>
          </div>

          {/* Security Violations */}
          <div className="p-4 rounded-lg border" style={surfaceStyle}>
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-medium text-[var(--text-secondary)]">Violations</h3>
                <div className={`text-3xl font-bold ${
                  securityViolations.length > 0 ? 'text-red-600' : 'text-green-600'
                }`}>
                  {securityViolations.length}
                </div>
                <div className="text-xs text-[var(--text-muted)]">security incidents</div>
              </div>
              <AlertTriangle className={`w-8 h-8 ${
                securityViolations.length > 0 ? 'text-red-600' : 'text-green-600'
              }`} />
            </div>
          </div>
        </div>

        {/* Charts Row */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* QBER Trend Chart */}
          <div className="p-4 border rounded-lg" style={surfaceStyle}>
            <h3 className="text-lg font-medium text-[var(--text-primary)] mb-4">QBER Trend</h3>
            {qberChartData.length > 0 ? (
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={qberChartData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="index" />
                    <YAxis domain={[0, Math.max(15, Math.max(...qberChartData.map(d => d.qber)) * 1.2)]} />
                    <Tooltip 
                      formatter={(value: number, name: string) => [
                        `${value.toFixed(2)}%`, 
                        name === 'qber' ? 'QBER' : 'Threshold'
                      ]}
                      labelFormatter={(index) => `Measurement ${index + 1}`}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="qber" 
                      stroke="#3b82f6" 
                      strokeWidth={2}
                      name="qber"
                    />
                    <Line 
                      type="monotone" 
                      dataKey="threshold" 
                      stroke="#f59e0b" 
                      strokeDasharray="5 5"
                      strokeWidth={2}
                      name="threshold"
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="h-64 flex items-center justify-center text-[var(--text-muted)]">
                No QBER data available
              </div>
            )}
          </div>

          {/* Crypto Usage Chart */}
          <div className="p-4 border rounded-lg" style={surfaceStyle}>
            <h3 className="text-lg font-medium text-[var(--text-primary)] mb-4">Crypto Usage</h3>
            {securityMetrics.length > 0 && securityMetrics.some(m => m.value > 0) ? (
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={securityMetrics}
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      dataKey="value"
                      label={({ name, value }) => `${name}: ${value}`}
                    >
                      {securityMetrics.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="h-64 flex items-center justify-center text-[var(--text-muted)]">
                No crypto operations yet
              </div>
            )}
          </div>
        </div>

        {/* Security Issues and Recommendations */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Current Issues */}
          <div className="p-4 border rounded-lg" style={surfaceStyle}>
            <h3 className="text-lg font-medium text-[var(--text-primary)] mb-4">Current Issues</h3>
            <div className="space-y-2 max-h-40 overflow-y-auto">
              {sessionHealth.issues.length > 0 ? (
                sessionHealth.issues.map((issue, index) => (
                  <div key={index} className="flex items-start space-x-2">
                    <AlertTriangle className="w-4 h-4 text-yellow-500 mt-0.5 flex-shrink-0" />
                    <span className="text-sm text-[var(--text-secondary)]">{issue}</span>
                  </div>
                ))
              ) : (
                <div className="text-sm text-green-500">No issues detected</div>
              )}
            </div>
          </div>

          {/* Recommendations */}
          <div className="p-4 border rounded-lg" style={surfaceStyle}>
            <h3 className="text-lg font-medium text-[var(--text-primary)] mb-4">Recommendations</h3>
            <div className="space-y-2 max-h-40 overflow-y-auto">
              {sessionHealth.recommendations.length > 0 ? (
                sessionHealth.recommendations.map((rec, index) => (
                  <div key={index} className="flex items-start space-x-2">
                    <CheckCircle className="w-4 h-4 text-[var(--info)] mt-0.5 flex-shrink-0" />
                    <span className="text-sm text-[var(--text-secondary)]">{rec}</span>
                  </div>
                ))
              ) : (
                <div className="text-sm text-[var(--info)]">No recommendations needed</div>
              )}
            </div>
          </div>
        </div>

        {/* Recent Security Violations */}
        {securityViolations.length > 0 && (
          <div className="p-4 border rounded-lg" style={surfaceStyle}>
            <h3 className="text-lg font-medium text-[var(--text-primary)] mb-4">Recent Security Violations</h3>
            <div className="space-y-2 max-h-32 overflow-y-auto">
              {securityViolations.slice(-5).reverse().map((violation, index) => (
                <div key={index} className="flex items-start justify-between p-2 rounded text-sm bg-red-500/10 border border-red-400/30">
                  <span className="text-red-200">{violation.violation}</span>
                  <span className="text-red-300 text-xs">
                    {new Date(violation.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Crypto Details */}
        {cryptoInfo && (
          <div className="p-4 border rounded-lg" style={subtleSurfaceStyle}>
            <h3 className="text-lg font-medium text-[var(--text-primary)] mb-4">Cryptographic Details</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <div className="text-[var(--text-muted)]">Mode</div>
                <div className="font-medium text-[var(--text-primary)]">
                  {cryptoInfo.hybrid_mode ? 'Hybrid (BB84+PQC)' : 'Pure BB84'}
                </div>
              </div>
              <div>
                <div className="text-[var(--text-muted)]">Key Length</div>
                <div className="font-medium text-[var(--text-primary)]">{cryptoInfo.final_key_length} bytes</div>
              </div>
              <div>
                <div className="text-[var(--text-muted)]">Messages</div>
                <div className="font-medium text-[var(--text-primary)]">{cryptoInfo.crypto_stats.message_count}</div>
              </div>
              <div>
                <div className="text-[var(--text-muted)]">Files</div>
                <div className="font-medium text-[var(--text-primary)]">{cryptoInfo.crypto_stats.file_count}</div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default SecurityDashboard ;

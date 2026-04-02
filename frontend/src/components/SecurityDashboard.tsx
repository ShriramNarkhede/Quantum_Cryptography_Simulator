// src/components/SecurityDashboard.tsx
import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { Shield, AlertTriangle, Activity, TrendingUp, CheckCircle, Lock } from 'lucide-react';
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
    if (score >= 90) return 'text-[var(--system-green)]';
    if (score >= 70) return 'text-[var(--system-blue)]';
    if (score >= 50) return 'text-[var(--system-orange)]';
    return 'text-[var(--system-red)]';
  };

  const getHealthBgColor = (score: number) => {
    // Using subtle iOS-style fills
    if (score >= 90) return 'bg-green-500/10 text-green-700';
    if (score >= 70) return 'bg-blue-500/10 text-blue-700';
    if (score >= 50) return 'bg-orange-500/10 text-orange-700';
    return 'bg-red-500/10 text-red-700';
  };

  // Risk level colors
  const getRiskColor = (risk: SessionHealthAssessment['risk_level']) => {
    switch (risk) {
      case 'MINIMAL': return 'text-green-700 bg-green-500/15 border-green-200';
      case 'LOW': return 'text-blue-700 bg-blue-500/15 border-blue-200';
      case 'MEDIUM': return 'text-orange-700 bg-orange-500/15 border-orange-200';
      case 'HIGH': return 'text-red-700 bg-red-500/15 border-red-200';
      case 'CRITICAL': return 'text-red-800 bg-red-100 border-red-300';
      default: return 'text-gray-600 bg-gray-100 border-gray-200';
    }
  };

  // Security metrics for pie chart
  const securityMetrics = cryptoInfo ? [
    { name: 'Secure Messages', value: cryptoInfo.crypto_stats.message_count, color: 'var(--system-green)' },
    { name: 'Encrypted Files', value: cryptoInfo.crypto_stats.file_count, color: 'var(--system-blue)' },
    { name: 'Key Stream Used', value: Math.floor(cryptoInfo.crypto_stats.total_key_stream_bytes / 1024), color: 'var(--system-indigo)' },
  ] : [];

  return (
    <div className="glass-card space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between pb-4 border-b border-[var(--card-border)]">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-[var(--system-blue)]/10 rounded-full">
            <Shield className="w-6 h-6 text-[var(--system-blue)]" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-[var(--text-primary)] tracking-tight">Security Dashboard</h2>
            <p className="text-xs text-[var(--text-secondary)] uppercase tracking-wider font-semibold opacity-70">Real-time Threat Monitoring</p>
          </div>
        </div>
        <div className={`px-4 py-1.5 rounded-full text-xs font-bold tracking-wide border ${getRiskColor(sessionHealth.risk_level)}`}>
          RISK: {sessionHealth.risk_level}
        </div>
      </div>

      <div className="space-y-6">
        {/* Health Score and Overview */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Health Score */}
          <div className="p-5 rounded-2xl material-thin border border-[var(--card-border)] shadow-sm backdrop-blur-md">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wide">Session Health</h3>
              <Activity className={`w-5 h-5 ${getHealthColor(sessionHealth.score)}`} />
            </div>
            <div className="flex items-baseline gap-2">
              <div className={`text-4xl font-bold tracking-tighter ${getHealthColor(sessionHealth.score)}`}>
                {sessionHealth.score.toFixed(0)}
              </div>
              <div className="text-sm text-[var(--text-muted)] font-medium">/ 100</div>
            </div>
            <div className="mt-3 h-1.5 w-full bg-gray-200 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${getHealthBgColor(sessionHealth.score).split(' ')[0].replace('/10', '')}`}
                style={{ width: `${sessionHealth.score}%` }}
              />
            </div>
          </div>

          {/* QBER Status */}
          <div className="p-5 rounded-2xl material-thin border border-[var(--card-border)] shadow-sm backdrop-blur-md">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wide">Current QBER</h3>
              <TrendingUp className={`w-5 h-5 ${cryptoInfo?.qber && cryptoInfo.qber > cryptoInfo.qber_threshold
                  ? 'text-[var(--system-red)]' : 'text-[var(--system-green)]'
                }`} />
            </div>
            <div className="flex items-baseline gap-2">
              <div className={`text-4xl font-bold tracking-tighter ${cryptoInfo?.qber && cryptoInfo.qber > cryptoInfo.qber_threshold
                  ? 'text-[var(--system-red)]' : 'text-[var(--system-cyan)]'
                }`}>
                {cryptoInfo?.qber ? `${(cryptoInfo.qber * 100).toFixed(1)}%` : '0.0%'}
              </div>
            </div>
            <div className="mt-1 text-xs text-[var(--text-muted)] font-medium">
              Threshold Limit: <span className="text-[var(--text-primary)]">{cryptoInfo ? (cryptoInfo.qber_threshold * 100).toFixed(1) : '11.0'}%</span>
            </div>
          </div>

          {/* Security Violations */}
          <div className="p-5 rounded-2xl material-thin border border-[var(--card-border)] shadow-sm backdrop-blur-md">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wide">Violations</h3>
              <AlertTriangle className={`w-5 h-5 ${securityViolations.length > 0 ? 'text-[var(--system-red)]' : 'text-[var(--system-green)]'
                }`} />
            </div>
            <div className={`text-4xl font-bold tracking-tighter ${securityViolations.length > 0 ? 'text-[var(--system-red)]' : 'text-[var(--system-green)]'
              }`}>
              {securityViolations.length}
            </div>
            <div className="mt-1 text-xs text-[var(--text-muted)] font-medium">
              Incidents Recorded
            </div>
          </div>
        </div>

        {/* Charts Row */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* QBER Trend Chart */}
          <div className="p-6 rounded-2xl material-thin border border-[var(--card-border)] shadow-sm">
            <h3 className="text-base font-bold text-[var(--text-primary)] mb-6">QBER Trend Analysis</h3>
            {qberChartData.length > 0 ? (
              <div className="h-64 -ml-4">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={qberChartData}>
                    <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.1} />
                    <XAxis dataKey="index" stroke="var(--text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                    <YAxis
                      stroke="var(--text-muted)"
                      fontSize={12}
                      tickLine={false}
                      axisLine={false}
                      domain={[0, Math.max(15, Math.max(...qberChartData.map(d => d.qber)) * 1.2)]}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: 'var(--bg-secondary)',
                        borderColor: 'var(--card-border)',
                        borderRadius: '12px',
                        boxShadow: '0 4px 12px rgba(0,0,0,0.1)'
                      }}
                      itemStyle={{ color: 'var(--text-primary)' }}
                      labelStyle={{ color: 'var(--text-secondary)' }}
                      formatter={(value: number, name: string) => [
                        `${value.toFixed(2)}%`,
                        name === 'qber' ? 'QBER' : 'Threshold'
                      ]}
                      labelFormatter={(index) => `Measurement ${index + 1}`}
                    />
                    <Line
                      type="monotone"
                      dataKey="qber"
                      stroke="var(--system-blue)"
                      strokeWidth={3}
                      dot={false}
                      activeDot={{ r: 6, strokeWidth: 0 }}
                      name="qber"
                    />
                    <Line
                      type="monotone"
                      dataKey="threshold"
                      stroke="var(--system-orange)"
                      strokeDasharray="4 4"
                      strokeWidth={2}
                      dot={false}
                      name="threshold"
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="h-64 flex flex-col items-center justify-center text-[var(--text-muted)] gap-3 bg-[var(--bg-primary)]/30 rounded-xl border border-dashed border-gray-300">
                <Activity className="w-8 h-8 opacity-40" />
                <span className="text-sm">No QBER data available</span>
              </div>
            )}
          </div>

          {/* Crypto Usage Chart */}
          <div className="p-6 rounded-2xl material-thin border border-[var(--card-border)] shadow-sm">
            <h3 className="text-base font-bold text-[var(--text-primary)] mb-6">Cryptographic Breakdown</h3>
            {securityMetrics.length > 0 && securityMetrics.some(m => m.value > 0) ? (
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={securityMetrics}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={80}
                      paddingAngle={5}
                      dataKey="value"
                      label={({ name, value }) => `${name}`} // Simplified label
                    >
                      {securityMetrics.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: 'var(--bg-secondary)',
                        borderColor: 'var(--card-border)',
                        borderRadius: '12px',
                        boxShadow: '0 4px 12px rgba(0,0,0,0.1)'
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="h-64 flex flex-col items-center justify-center text-[var(--text-muted)] gap-3 bg-[var(--bg-primary)]/30 rounded-xl border border-dashed border-gray-300">
                <Lock className="w-8 h-8 opacity-40" />
                <span className="text-sm">No crypto operations yet</span>
              </div>
            )}
          </div>
        </div>

        {/* Security Issues and Recommendations */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Current Issues */}
          <div className="p-5 rounded-2xl material-thin border border-[var(--card-border)] shadow-sm">
            <h3 className="text-base font-bold text-[var(--text-primary)] mb-4">Detected Vulnerabilities</h3>
            <div className="space-y-3 max-h-48 overflow-y-auto pr-2 custom-scrollbar">
              {sessionHealth.issues.length > 0 ? (
                sessionHealth.issues.map((issue, index) => (
                  <div key={index} className="flex items-start gap-3 p-3 rounded-xl bg-orange-50 border border-orange-100/50">
                    <AlertTriangle className="w-5 h-5 text-orange-500 flex-shrink-0 mt-0.5" />
                    <span className="text-sm text-gray-800 font-medium leading-tight">{issue}</span>
                  </div>
                ))
              ) : (
                <div className="flex flex-col items-center justify-center py-8 text-center">
                  <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mb-3">
                    <CheckCircle className="w-6 h-6 text-green-600" />
                  </div>
                  <div className="text-sm font-medium text-green-700">All systems secure</div>
                  <div className="text-xs text-green-600/70 mt-1">No vulnerabilities detected</div>
                </div>
              )}
            </div>
          </div>

          {/* Recommendations */}
          <div className="p-5 rounded-2xl material-thin border border-[var(--card-border)] shadow-sm">
            <h3 className="text-base font-bold text-[var(--text-primary)] mb-4">Security Recommendations</h3>
            <div className="space-y-3 max-h-48 overflow-y-auto pr-2 custom-scrollbar">
              {sessionHealth.recommendations.length > 0 ? (
                sessionHealth.recommendations.map((rec, index) => (
                  <div key={index} className="flex items-start gap-3 p-3 rounded-xl bg-blue-50 border border-blue-100/50">
                    <div className="mt-0.5 w-5 h-5 rounded-full bg-blue-100 flex items-center justify-center flex-shrink-0">
                      <span className="text-[10px] text-blue-600 font-bold">{index + 1}</span>
                    </div>
                    <span className="text-sm text-gray-800 font-medium leading-tight">{rec}</span>
                  </div>
                ))
              ) : (
                <div className="flex flex-col items-center justify-center py-8 text-center opacity-70">
                  <CheckCircle className="w-8 h-8 text-[var(--system-blue)] mb-2" />
                  <div className="text-sm font-medium text-[var(--text-secondary)]">Optimization complete</div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Recent Security Violations Table */}
        {securityViolations.length > 0 && (
          <div className="rounded-2xl overflow-hidden border border-[var(--card-border)]">
            <div className="bg-gray-50/50 p-4 border-b border-gray-100">
              <h3 className="text-base font-bold text-[var(--text-primary)]">Security Incident Log</h3>
            </div>
            <div className="divide-y divide-gray-100/50 bg-white/40 backdrop-blur-sm">
              {securityViolations.slice(-5).reverse().map((violation, index) => (
                <div key={index} className="flex items-center justify-between p-4 hover:bg-white/60 transition-colors">
                  <div className="flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></div>
                    <span className="text-sm font-medium text-red-900">{violation.violation}</span>
                  </div>
                  <span className="text-xs font-mono text-[var(--text-muted)] bg-gray-100 px-2 py-1 rounded-md">
                    {new Date(violation.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Crypto Details Footer */}
        {cryptoInfo && (
          <div className="p-4 rounded-xl bg-[var(--bg-primary)]/50 border border-[var(--card-border)] backdrop-blur-sm">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6 text-sm">
              <div className="space-y-1">
                <div className="text-[10px] font-bold text-[var(--text-muted)] uppercase tracking-wider">Encryption Mode</div>
                <div className="font-semibold text-[var(--text-primary)] flex items-center gap-2">
                  <div className="w-2 h-2 bg-indigo-500 rounded-full"></div>
                  {cryptoInfo.hybrid_mode ? 'Hybrid (BB84+PQC)' : 'Pure BB84'}
                </div>
              </div>
              <div className="space-y-1">
                <div className="text-[10px] font-bold text-[var(--text-muted)] uppercase tracking-wider">Key Length</div>
                <div className="font-mono font-medium text-[var(--text-primary)]">{cryptoInfo.final_key_length} bytes</div>
              </div>
              <div className="space-y-1">
                <div className="text-[10px] font-bold text-[var(--text-muted)] uppercase tracking-wider">Messages Processed</div>
                <div className="font-mono font-medium text-[var(--text-primary)]">{cryptoInfo.crypto_stats.message_count}</div>
              </div>
              <div className="space-y-1">
                <div className="text-[10px] font-bold text-[var(--text-muted)] uppercase tracking-wider">Files Secured</div>
                <div className="font-mono font-medium text-[var(--text-primary)]">{cryptoInfo.crypto_stats.file_count}</div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default SecurityDashboard;

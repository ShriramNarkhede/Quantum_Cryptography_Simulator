import React, { useState, useEffect, useMemo } from 'react';
import { Play, AlertTriangle } from 'lucide-react';
import type { BB84Progress, CryptoInfo, QBERDataPoint } from '../types';
import { useMediaQuery } from '../hooks/useMediaQuery';

interface BB84SimulatorProps {
    progress: BB84Progress | null;
    sessionKey: Uint8Array | null;
    onStartBB84: (useHybrid?: boolean) => void | Promise<void>;
    onRetrySessionKey?: () => void | Promise<void>;
    userRole: 'alice' | 'bob' | 'eve';
    eveDetected: boolean;
    cryptoInfo?: CryptoInfo | null;
    qberHistory?: QBERDataPoint[];
}

const BB84Simulator: React.FC<BB84SimulatorProps> = ({
    progress,
    sessionKey,
    onStartBB84,
    onRetrySessionKey,
    userRole,
    eveDetected,
    cryptoInfo: _cryptoInfo,
    qberHistory: qberHistoryProp
}) => {
    const [qberHistory, setQberHistory] = useState<{ time: number, qber: number }[]>([]);
    const isCompact = useMediaQuery('(max-width: 640px)');
    const [mobileDetailsOpen, setMobileDetailsOpen] = useState(false);

    useEffect(() => {
        if (qberHistoryProp && qberHistoryProp.length > 0) {
            setQberHistory(qberHistoryProp.map(p => ({ time: p.timestamp, qber: p.qber * 100 })));
        }
    }, [qberHistoryProp]);

    useEffect(() => {
        if (progress?.qber !== undefined) {
            setQberHistory(prev => {
                const updated = [...prev, { time: Date.now(), qber: progress.qber! * 100 }];
                return updated.slice(-32);
            });
        }
    }, [progress?.qber]);

    const stageSequence = [
        { id: 'alice_preparation', label: 'Alice Prepares', color: 'from-cyan-400/70 via-blue-500/60 to-indigo-500/60' },
        { id: 'transmission', label: 'Qubit Transmission', color: 'from-blue-400/60 via-purple-500/60 to-pink-500/60' },
        { id: 'bob_measurement', label: 'Bob Measures', color: 'from-purple-400/60 via-indigo-400/60 to-blue-500/60' },
        { id: 'sifting', label: 'Sifting', color: 'from-emerald-400/60 via-teal-500/60 to-cyan-500/60' },
        { id: 'qber_test', label: 'QBER Test', color: 'from-amber-400/60 via-orange-500/60 to-rose-500/60' },
        { id: 'complete', label: 'Privacy Amplification', color: 'from-emerald-500/60 via-green-500/60 to-lime-500/50' }
    ];

    const canStartSimulation = userRole === 'alice' && !progress?.stage;
    const qberPercent = (progress?.qber ?? 0) * 100;
    const thresholdPct = (progress?.threshold ?? 0.11) * 100;
    const visualization = useMemo(() => {
        return Array.from({ length: 12 }, (_, index) => {
            const aliceBasis = Math.random() > 0.5 ? '+' : '×';
            const bobBasis = Math.random() > 0.5 ? '+' : '×';
            const matched = aliceBasis === bobBasis;
            const aliceBit = Math.random() > 0.5 ? 1 : 0;
            const bobResult = matched ? aliceBit : Math.random() > 0.5 ? 1 : 0;
            const eveIntercept = userRole === 'eve' ? Math.random() > 0.6 : Math.random() > 0.9;
            return {
                index,
                aliceBit,
                aliceBasis,
                bobBasis,
                bobResult,
                matched,
                eveIntercept
            };
        });
    }, [progress?.stage, userRole]);

    const particleNodes = useMemo(() => (
        Array.from({ length: 10 }, (_, idx) => {
            const top = 20 + Math.random() * 40;
            const delay = idx * 0.8;
        return (
                <span
                    key={`particle-${idx}`}
                    style={{
                        top: `${top}%`,
                        animationDelay: `${delay}s`,
                        left: `${Math.random() * 20}%`
                    }}
                    className={`qubit-particle ${Math.random() > 0.8 && eveDetected ? 'eve' : ''}`}
                />
            );
        })
    ), [eveDetected]);

    const qberTrendPoints = qberHistory.slice(-15);
    const comparisonEntries = visualization.slice(0, 8);

    const detailedContent = (
        <>
            <header className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                <div>
                    <p className="metric-label">BB84 Visualization Dashboard</p>
                    <h2 className="text-3xl font-semibold text-[var(--text-primary)]">Quantum Channel · {userRole.toUpperCase()}</h2>
                    <p className="text-sm text-[var(--text-secondary)]">
                        {userRole === 'alice' && 'Control qubit generation & start new sessions'}
                        {userRole === 'bob' && 'Monitor incoming qubits and validate bases'}
                        {userRole === 'eve' && 'Simulate adversarial presence on the channel'}
                    </p>
                </div>
                {canStartSimulation && (
                    <button
                        onClick={() => onStartBB84()}
                        className="quantum-button bg-gradient-to-r from-cyan-500 to-blue-500 text-white flex items-center gap-2"
                    >
                        <Play className="w-4 h-4" />
                        Start BB84
                    </button>
                )}
            </header>

            {eveDetected && (
                <div className="mt-6 rounded-2xl border border-rose-400/30 bg-gradient-to-r from-rose-900/50 to-orange-900/30 p-4 flex items-center gap-3">
                    <AlertTriangle className="text-rose-200" />
                    <div>
                        <p className="text-sm font-semibold text-[var(--text-primary)]">Eavesdropping detected via QBER spike</p>
                        <p className="text-xs text-rose-200">Take immediate action: pause comms or re-run BB84.</p>
                    </div>
                </div>
            )}

            <div className="mt-8 grid xl:grid-cols-[1.8fr,1fr] gap-6">
                <div className="space-y-6">
                    <div className="rounded-3xl border border-[var(--surface-border)] bg-[var(--panel-surface)] p-5 space-y-4">
                        <div className="flex items-center justify-between text-sm text-[var(--text-secondary)]">
                            <span>Alice • Bits & Bases</span>
                            <span>Bob • Measurements</span>
                        </div>

                        <div className="space-y-3">
                            {['alice', 'bob'].map((actor) => (
                                <div key={actor} className="flex items-center gap-3">
                                    <span className={`session-chip ${actor}`}>{actor === 'alice' ? 'Alice' : 'Bob'}</span>
                                    <div className="flex-1 flex gap-2 overflow-x-auto">
                                        {visualization.map((bit) => (
                                            <div
                                                key={`${actor}-${bit.index}`}
                                                className={`bit-grid-cell ${bit.matched ? 'match' : ''} w-11 h-14 rounded-2xl border flex flex-col items-center justify-center text-xs font-mono ${
                                                    bit.eveIntercept && actor === 'alice' ? 'ring-2 ring-rose-400/60' : ''
                                                }`}
                                            >
                                                <span className="text-base font-semibold">
                                                    {actor === 'alice' ? bit.aliceBit : bit.bobResult}
                                                </span>
                                                <span className="text-[10px] bit-grid-cell__basis">
                                                    {actor === 'alice' ? bit.aliceBasis : bit.bobBasis}
                                                </span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    <div className="qubit-stream">
                        {particleNodes}
                        <div className="relative z-10 flex items-center justify-between px-6 py-4 text-sm text-[var(--text-primary)]">
                            <span>Qubits in flight</span>
                            <span className="flex items-center gap-2">
                                <div className="w-2 h-2 rounded-full bg-cyan-300 animate-pulse" />
                                Pulsing = active transmission
                            </span>
                    </div>
                </div>

                    <div className="rounded-3xl border border-[var(--surface-border)] bg-[var(--panel-surface)] p-5 grid md:grid-cols-2 gap-4">
                        <div>
                            <p className="metric-label">Stage</p>
                            <p className="text-2xl font-semibold text-[var(--text-primary)]">
                                {progress?.message || progress?.stage?.replace('_', ' ').toUpperCase() || 'Idle'}
                            </p>
                            <div className="mt-3 h-2 rounded-full bg-[var(--panel-muted)]">
                                <div
                                    className={`h-full rounded-full ${eveDetected ? 'bg-gradient-to-r from-amber-500 to-rose-500' : 'bg-gradient-to-r from-cyan-500 via-blue-500 to-purple-500'}`}
                                    style={{ width: `${Math.round((progress?.progress ?? 0) * 100)}%` }}
                                />
                            </div>
                        </div>
                        <div>
                            <p className="metric-label mb-2">Live Comparison</p>
                            <div className="rounded-2xl border border-[var(--surface-border)] bg-[var(--panel-surface)] p-3 flex flex-col gap-3">
                                <div className="grid grid-cols-[56px,1fr,70px] text-xs text-[var(--table-header)]">
                                    <span>Bit</span>
                                    <span>Alice vs Bob</span>
                                    <span className="text-right pr-2">Match</span>
                                </div>
                                <div className="space-y-1">
                                    {comparisonEntries.map((bit) => (
                                        <div
                                            key={`row-${bit.index}`}
                                            className="grid grid-cols-[56px,1fr,70px] text-sm text-[var(--text-primary)] items-center py-0.5 rounded-md bg-[var(--table-row)]"
                                        >
                                            <span className="font-mono pl-1">{bit.index.toString().padStart(2, '0')}</span>
                                            <span className="font-mono">{bit.aliceBit}/{bit.bobResult} ({bit.aliceBasis}/{bit.bobBasis})</span>
                                            <span className={`text-right pr-2 ${bit.matched ? 'text-emerald-500' : 'text-slate-500'}`}>
                                                {bit.matched ? '✓' : '×'}
                                        </span>
                                    </div>
                                    ))}
                                    <p className="text-[11px] text-[var(--table-header)] mt-1 pl-1">Showing last {comparisonEntries.length} bits</p>
                                    </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="space-y-6">
                    <div className="rounded-3xl border border-[var(--surface-border)] bg-[var(--panel-surface)] p-5 flex flex-col items-center gap-4">
                        <div
                            className="qber-ring"
                            style={{ // @ts-ignore custom property
                                '--qber-angle': `${Math.min(100, qberPercent)}%`
                            }}
                        >
                            <strong>{qberPercent.toFixed(2)}%</strong>
                        </div>
                        <p className="text-sm text-[var(--text-secondary)] text-center">
                            Live QBER · Threshold {thresholdPct.toFixed(1)}%
                        </p>
                        {qberPercent > thresholdPct && (
                            <span className="text-xs text-rose-200">Warning: error rate beyond safe envelope</span>
                        )}
                    </div>

                    <div className="rounded-3xl border border-[var(--surface-border)] bg-[var(--panel-surface)] p-5 space-y-4">
                        <p className="metric-label">Channel Health</p>
                            <div className="space-y-2">
                            <div className="flex items-center justify-between text-sm text-[var(--text-secondary)]">
                                <span>Sifted Bits</span>
                                <span className="font-semibold text-[var(--text-primary)]">
                                    {progress?.sifted_length ?? 0}/{progress?.original_length ?? 0}
                                    </span>
                                </div>
                            <div className="flex items-center justify-between text-sm text-[var(--text-secondary)]">
                                <span>Final key</span>
                                <span className="font-semibold text-emerald-500">{progress?.final_key_length ?? '--'} bytes</span>
                            </div>
                            <div className="flex items-center justify-between text-sm text-[var(--text-secondary)]">
                                <span>Session key</span>
                                <span className="font-semibold text-[var(--text-primary)]">
                                    {sessionKey ? `${sessionKey.length * 8} bits ready` : 'Awaiting'}
                                </span>
                                        </div>
                                    </div>
                        {!sessionKey && progress?.success && onRetrySessionKey && (
                                        <button
                                className="quantum-button bg-[var(--panel-muted)] border border-[var(--surface-border)] text-[var(--text-primary)] w-full"
                                            onClick={onRetrySessionKey}
                                        >
                                Retry key retrieval
                                        </button>
                        )}
                    </div>

                    <div className="rounded-3xl border border-[var(--surface-border)] bg-[var(--panel-surface)] p-5 space-y-4">
                        <p className="metric-label">Stage Timeline</p>
                        <div className="space-y-3">
                            {stageSequence.map((stage, idx) => {
                                const active = progress?.stage === stage.id;
                                const completed = stageSequence.findIndex(s => s.id === progress?.stage) > idx;
                                return (
                                    <div key={stage.id} className="flex items-center gap-3">
                                        <div className={`w-10 h-10 rounded-2xl bg-gradient-to-br ${stage.color} flex items-center justify-center text-sm text-white`}>
                                            {idx + 1}
                                        </div>
                                        <div className="flex-1">
                                            <p className="text-sm text-[var(--text-primary)] font-medium">{stage.label}</p>
                                            <div className="h-1 rounded-full bg-[var(--panel-muted)] mt-2">
                                                <div
                                                    className={`h-full rounded-full ${completed || active ? 'bg-gradient-to-r from-emerald-400 to-cyan-500' : 'bg-[var(--panel-muted)]'} ${active ? 'animate-pulse' : ''}`}
                                                    style={{ width: `${completed ? 100 : active ? Math.max(8, (progress?.progress ?? 0) * 100) : 8}%` }}
                                                />
                                            </div>
                                        </div>
                                    </div>
                                );
                            })}
                </div>
                    </div>

                    <div className="rounded-3xl border border-[var(--surface-border)] bg-[var(--panel-surface)] p-5 space-y-3">
                        <p className="metric-label">QBER Trend</p>
                        <div className="h-24">
                            <svg width="100%" height="100%" viewBox="0 0 200 100">
                                <polyline
                                    fill="none"
                                    stroke={eveDetected ? '#f87171' : '#38bdf8'}
                                    strokeWidth="2"
                                    points={qberTrendPoints.map((point, index) => {
                                        const x = (index / (qberTrendPoints.length - 1 || 1)) * 200;
                                        const y = 100 - Math.min(100, point.qber);
                                        return `${x},${y}`;
                                    }).join(' ')}
                                />
                                <line
                                    x1="0"
                                    y1={100 - thresholdPct}
                                    x2="200"
                                    y2={100 - thresholdPct}
                                    stroke="#fbbf24"
                                    strokeDasharray="4 4"
                                    strokeWidth="1"
                                />
                            </svg>
                        </div>
                        <div className="flex justify-between text-xs text-[var(--table-header)]">
                            <span>Recent</span>
                            <span>{qberTrendPoints.length} samples</span>
                        </div>
                    </div>
                </div>
            </div>
        </>
    );

    if (isCompact) {
        const totalBits = progress?.original_length ?? 0;
        const matchedBits = progress?.sifted_length ?? 0;
        const qberDisplay = progress?.qber ? `${(progress.qber * 100).toFixed(2)}%` : '—';

        return (
            <section className="glass-card glow-border space-y-4">
                <div className="flex items-center justify-between">
                    <div>
                        <p className="metric-label">Quantum Flow</p>
                        <h2 className="text-xl font-semibold text-[var(--text-primary)]">BB84 Overview</h2>
                    </div>
                    <button
                        onClick={() => setMobileDetailsOpen(prev => !prev)}
                        className="copy-button"
                    >
                        {mobileDetailsOpen ? 'Hide Details' : 'View Details'}
                    </button>
                </div>

                <div className="grid grid-cols-2 gap-4 text-sm text-[var(--text-secondary)]">
                    <div>
                        <p className="metric-label">Total Bits</p>
                        <p className="metric-value text-[var(--text-primary)]">{totalBits}</p>
                    </div>
                    <div>
                        <p className="metric-label">Matched Bases</p>
                        <p className="metric-value text-[var(--text-primary)]">{matchedBits}</p>
                    </div>
                    <div>
                        <p className="metric-label">QBER</p>
                        <p className="metric-value text-[var(--text-primary)]">{qberDisplay}</p>
                    </div>
                    <div>
                        <p className="metric-label">Stage</p>
                        <p className="metric-value text-[var(--text-primary)]">{progress?.stage?.replace('_', ' ') ?? 'Idle'}</p>
                    </div>
                </div>

                {mobileDetailsOpen && detailedContent}
            </section>
        );
    }

    return (
        <section className="glass-card glow-border">
            {detailedContent}
        </section>
    );
};

export default BB84Simulator;

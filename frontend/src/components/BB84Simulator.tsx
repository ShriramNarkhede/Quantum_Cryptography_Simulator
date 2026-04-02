import React, { useState, useEffect, useMemo } from 'react';
import { Play, AlertTriangle, ArrowRight, Activity, Shield, Disc } from 'lucide-react';
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
        { id: 'alice_preparation', label: 'Preparation', color: 'from-cyan-400 to-blue-500' },
        { id: 'transmission', label: 'Transmission', color: 'from-blue-400 to-indigo-500' },
        { id: 'bob_measurement', label: 'Measurement', color: 'from-indigo-400 to-purple-500' },
        { id: 'sifting', label: 'Sifting', color: 'from-purple-400 to-pink-500' },
        { id: 'qber_test', label: 'QBER Check', color: 'from-pink-400 to-rose-500' },
        { id: 'complete', label: 'Final Key', color: 'from-emerald-400 to-teal-500' }
    ];

    const canStartSimulation = userRole === 'alice' && !progress?.stage;
    const qberPercent = (progress?.qber ?? 0) * 100;
    const thresholdPct = (progress?.threshold ?? 0.11) * 100;

    // Visualization logic remains similar but simplified for new UI
    const visualization = useMemo(() => {
        return Array.from({ length: 12 }, (_, index) => {
            const aliceBasis = Math.random() > 0.5 ? '+' : '×';
            const bobBasis = Math.random() > 0.5 ? '+' : '×';
            const matched = aliceBasis === bobBasis;
            const aliceBit = Math.random() > 0.5 ? 1 : 0;
            const bobResult = matched ? aliceBit : Math.random() > 0.5 ? 1 : 0;
            const eveIntercept = userRole === 'eve' ? Math.random() > 0.6 : Math.random() > 0.9;
            return { index, aliceBit, aliceBasis, bobBasis, bobResult, matched, eveIntercept };
        });
    }, [progress?.stage, userRole]);

    const particleNodes = useMemo(() => (
        Array.from({ length: 8 }, (_, idx) => {
            const top = 20 + Math.random() * 40;
            const delay = idx * 1.2;
            return (
                <span
                    key={`particle-${idx}`}
                    style={{
                        top: `${top}%`,
                        animationDelay: `${delay}s`,
                        left: `${Math.random() * 10}%`
                    }}
                    className={`absolute w-1.5 h-1.5 rounded-full filter blur-[1px] opacity-0 animate-pulse 
                        ${eveDetected ? 'bg-red-400 shadow-[0_0_8px_rgba(248,113,113,0.8)]' : 'bg-cyan-400 shadow-[0_0_8px_rgba(34,211,238,0.8)]'}
                        transition-colors duration-500
                    `}
                />
            );
        })
    ), [eveDetected]);

    const qberTrendPoints = qberHistory.slice(-20);
    const comparisonEntries = visualization.slice(0, 8);

    const detailedContent = (
        <>
            {/* Header Section */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 mb-8">
                <div>
                    <div className="flex items-center gap-2 mb-1">
                        <div className={`w-2 h-2 rounded-full ${progress?.stage ? 'bg-[var(--system-green)] animate-pulse' : 'bg-[var(--text-muted)]'}`} />
                        <p className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-widest">Quantum Distribution Protocol</p>
                    </div>
                    <h2 className="text-2xl font-bold text-[var(--text-primary)]">BB84 Simulation</h2>
                    <p className="text-sm text-[var(--text-secondary)] mt-1 max-w-lg">
                        Real-time simulation of quantum key distribution states, measuring polarization and detecting interference.
                    </p>
                </div>

                {canStartSimulation && (
                    <button
                        onClick={() => onStartBB84()}
                        className="quantum-button bg-[var(--system-blue)] text-white hover:brightness-110 shadow-lg shadow-blue-500/20 group flex items-center justify-center gap-2"
                    >
                        <Play className="w-4 h-4 fill-current group-hover:scale-110 transition-transform" />
                        <span>Initiate Protocol</span>
                    </button>
                )}
            </div>

            {/* Alert Banner */}
            {eveDetected && (
                <div className="mb-8 p-4 rounded-2xl bg-red-500/10 border border-red-500/20 backdrop-blur-md flex items-center gap-4 animate-in slide-in-from-top-2">
                    <div className="p-2 bg-red-500/20 rounded-full">
                        <AlertTriangle className="w-6 h-6 text-red-500" />
                    </div>
                    <div>
                        <h3 className="text-sm font-bold text-red-700">Eavesdropper Isolation Protocol Active</h3>
                        <p className="text-xs text-red-600/80">High error rate detected (QBER &gt; {thresholdPct.toFixed(1)}%). Channel is insecure.</p>
                    </div>
                </div>
            )}

            <div className="grid xl:grid-cols-[1.5fr,1fr] gap-6">
                {/* Left Column: Visualization */}
                <div className="space-y-6">
                    {/* Bits Visualization */}
                    <div className="glass-card !p-0 overflow-hidden relative min-h-[240px] flex flex-col">
                        <div className="absolute inset-0 bg-gradient-to-br from-[var(--bg-secondary)]/50 to-transparent pointer-events-none" />

                        {/* Stream Effect Background */}
                        <div className="absolute inset-0 opacity-20">
                            {/* Simplified stream visual using CSS gradients instead of many DOM nodes */}
                            <div className="absolute top-1/2 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-[var(--system-cyan)] to-transparent" />
                            {particleNodes}
                        </div>

                        <div className="relative z-10 p-6 flex-1 flex flex-col justify-center gap-8">
                            {/* Alice Row */}
                            <div className="flex items-center gap-4">
                                <span className="w-16 text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider text-right">Alice</span>
                                <div className="flex-1 flex items-center gap-2 overflow-x-auto pb-2 no-scrollbar mask-gradient-right">
                                    {visualization.map((bit) => (
                                        <div key={`alice-${bit.index}`} className="flex flex-col items-center gap-1 min-w-[32px]">
                                            <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-sm font-bold border 
                                            ${bit.eveIntercept ? 'border-red-500/50 bg-red-500/10 text-red-500' : 'border-[var(--system-cyan)]/30 bg-[var(--system-cyan)]/10 text-[var(--system-cyan)]'}`}>
                                                {bit.aliceBit}
                                            </div>
                                            <span className="text-[10px] text-[var(--text-muted)] font-mono">{bit.aliceBasis}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {/* Connector Lines (Visual only) */}
                            <div className="h-px w-full bg-gradient-to-r from-transparent via-[var(--card-border)] to-transparent opacity-50" />

                            {/* Bob Row */}
                            <div className="flex items-center gap-4">
                                <span className="w-16 text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider text-right">Bob</span>
                                <div className="flex-1 flex items-center gap-2 overflow-x-auto pb-2 no-scrollbar mask-gradient-right">
                                    {visualization.map((bit) => (
                                        <div key={`bob-${bit.index}`} className="flex flex-col items-center gap-1 min-w-[32px]">
                                            <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-sm font-bold border transition-colors duration-500
                                            ${bit.matched
                                                    ? 'border-[var(--system-green)]/30 bg-[var(--system-green)]/10 text-[var(--system-green)]'
                                                    : 'border-[var(--text-muted)]/30 bg-[var(--text-muted)]/5 text-[var(--text-muted)]'}`}>
                                                {bit.bobResult}
                                            </div>
                                            <span className="text-[10px] text-[var(--text-muted)] font-mono">{bit.bobBasis}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>

                        <div className="px-6 py-3 bg-[var(--card-surface)]/50 backdrop-blur-sm border-t border-[var(--card-border)] flex justify-between items-center text-xs">
                            <span className="text-[var(--text-secondary)]">Quantum State Transmission</span>
                            <div className="flex items-center gap-4">
                                <div className="flex items-center gap-1.5">
                                    <div className="w-2 h-2 rounded-full bg-[var(--system-cyan)]" />
                                    <span className="text-[var(--text-muted)]">Basis Match</span>
                                </div>
                                <div className="flex items-center gap-1.5">
                                    <div className="w-2 h-2 rounded-full bg-[var(--text-muted)] opacity-50" />
                                    <span className="text-[var(--text-muted)]">Discarded</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Timeline */}
                    <div className="glass-card p-6">
                        <h3 className="text-sm font-bold text-[var(--text-primary)] mb-6">Protocol Sequence</h3>
                        <div className="relative">
                            <div className="absolute left-6 top-0 bottom-0 w-px bg-[var(--card-border)]" />
                            <div className="space-y-6 relative">
                                {stageSequence.map((stage, idx) => {
                                    const active = progress?.stage === stage.id;
                                    const completed = stageSequence.findIndex(s => s.id === progress?.stage) > idx; // Simplified
                                    // Or simplified logic: if we are past this stage index
                                    // Better logic for completed: current stage index > this index
                                    const currentStageIdx = stageSequence.findIndex(s => s.id === progress?.stage);
                                    const isCompleted = currentStageIdx > idx || (progress?.success && idx === stageSequence.length - 1);

                                    return (
                                        <div key={stage.id} className={`flex items-start gap-4 transition-opacity ${active || isCompleted ? 'opacity-100' : 'opacity-40'}`}>
                                            <div className={`relative z-10 w-12 h-12 rounded-2xl flex items-center justify-center text-lg font-bold shadow-sm transition-all duration-300
                                                ${active
                                                    ? 'bg-[var(--system-blue)] text-white scale-110 shadow-blue-500/30'
                                                    : isCompleted
                                                        ? 'bg-[var(--system-green)] text-white'
                                                        : 'bg-[var(--bg-secondary)] text-[var(--text-muted)] border border-[var(--card-border)]'
                                                }`}>
                                                {isCompleted ? <ArrowRight className="w-5 h-5 rotate-90 md:rotate-0" /> : idx + 1}
                                            </div>
                                            <div className="pt-2 flex-1">
                                                <h4 className={`text-sm font-bold ${active ? 'text-[var(--system-blue)]' : 'text-[var(--text-primary)]'}`}>
                                                    {stage.label}
                                                </h4>
                                                {active && (
                                                    <div className="mt-2 h-1.5 w-full max-w-[200px] bg-[var(--bg-secondary)] rounded-full overflow-hidden">
                                                        <div className="h-full bg-[var(--system-blue)] animate-progress-indeterminate" />
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    </div>
                </div>

                {/* Right Column: Metrics */}
                <div className="space-y-6">
                    {/* QBER Radial */}
                    <div className="glass-card p-6 flex flex-col items-center justify-center text-center relative overflow-hidden">
                        <div className="absolute top-0 right-0 p-4 opacity-10">
                            <Activity className="w-32 h-32" />
                        </div>
                        <h3 className="text-sm font-semibold text-[var(--text-secondary)] mb-4 uppercase tracking-wider">Live Error Rate</h3>
                        <div className="relative w-40 h-40 flex items-center justify-center">
                            {/* SVG Ring */}
                            <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                                <circle cx="50" cy="50" r="45" fill="none" stroke="var(--bg-secondary)" strokeWidth="8" />
                                <circle
                                    cx="50" cy="50" r="45" fill="none"
                                    stroke={qberPercent > thresholdPct ? 'var(--system-red)' : 'var(--system-blue)'}
                                    strokeWidth="8"
                                    strokeDasharray="283"
                                    strokeDashoffset={283 - (283 * Math.min(qberPercent, 100) / 100)}
                                    className="transition-all duration-1000 ease-out"
                                    strokeLinecap="round"
                                />
                            </svg>
                            <div className="absolute flex flex-col items-center">
                                <span className={`text-3xl font-bold tracking-tighter ${qberPercent > thresholdPct ? 'text-[var(--system-red)]' : 'text-[var(--text-primary)]'}`}>
                                    {qberPercent.toFixed(1)}%
                                </span>
                                <span className="text-[10px] text-[var(--text-muted)] font-medium">QBER</span>
                            </div>
                        </div>
                        <div className="mt-4 px-4 py-2 rounded-xl bg-[var(--bg-secondary)] text-xs text-[var(--text-muted)]">
                            Threshold: <span className="text-[var(--text-primary)] font-bold">{thresholdPct.toFixed(1)}%</span>
                        </div>
                    </div>

                    {/* Key Stats */}
                    <div className="glass-card p-6 space-y-6">
                        <div className="flex items-center gap-3 mb-2">
                            <Shield className="w-5 h-5 text-[var(--system-indigo)]" />
                            <h3 className="text-sm font-bold text-[var(--text-primary)]">Key Generation</h3>
                        </div>

                        <div className="space-y-4">
                            <div className="p-3 rounded-xl bg-[var(--bg-secondary)] border border-[var(--card-border)] flex justify-between items-center">
                                <span className="text-xs text-[var(--text-secondary)]">Raw Bits</span>
                                <span className="text-sm font-mono font-bold text-[var(--text-primary)]">{progress?.original_length ?? 0}</span>
                            </div>
                            <div className="p-3 rounded-xl bg-[var(--bg-secondary)] border border-[var(--card-border)] flex justify-between items-center">
                                <span className="text-xs text-[var(--text-secondary)]">Sifted Bits</span>
                                <span className="text-sm font-mono font-bold text-[var(--system-blue)]">{progress?.sifted_length ?? 0}</span>
                            </div>
                            <div className="p-3 rounded-xl bg-[var(--system-green)]/10 border border-[var(--system-green)]/20 flex justify-between items-center">
                                <span className="text-xs text-[var(--system-green)] font-semibold">Final Key</span>
                                <span className="text-sm font-mono font-bold text-[var(--system-green)]">
                                    {progress?.final_key_length && userRole !== 'eve' ? `${progress.final_key_length} bytes` : '---'}
                                </span>
                            </div>
                        </div>

                        {!sessionKey && progress?.success && onRetrySessionKey && (
                            <button
                                onClick={onRetrySessionKey}
                                className="w-full py-3 rounded-xl bg-[var(--text-primary)] text-[var(--bg-primary)] font-bold text-sm hover:opacity-90 transition-opacity"
                            >
                                Retry Key Exchange
                            </button>
                        )}
                    </div>
                </div>
            </div>
        </>
    );

    // Mobile / Compact View
    if (isCompact) {
        return (
            <div className="glass-card space-y-4">
                <div className="flex items-center justify-between">
                    <div>
                        <h2 className="text-lg font-bold text-[var(--text-primary)]">BB84 Status</h2>
                        <p className="text-xs text-[var(--text-secondary)]">Stage: {progress?.stage?.replace('_', ' ') ?? 'Idle'}</p>
                    </div>
                    <button onClick={() => setMobileDetailsOpen(!mobileDetailsOpen)} className="p-2 rounded-full bg-[var(--bg-secondary)]">
                        {mobileDetailsOpen ? <ArrowRight className="-rotate-90 w-4 h-4" /> : <ArrowRight className="rotate-90 w-4 h-4" />}
                    </button>
                </div>

                <div className="grid grid-cols-3 gap-2 text-center">
                    <div className="p-2 rounded-lg bg-[var(--bg-secondary)]">
                        <div className="text-[10px] text-[var(--text-muted)]">QBER</div>
                        <div className={`text-sm font-bold ${qberPercent > thresholdPct ? 'text-red-500' : 'text-blue-500'}`}>{qberPercent.toFixed(1)}%</div>
                    </div>
                    <div className="p-2 rounded-lg bg-[var(--bg-secondary)]">
                        <div className="text-[10px] text-[var(--text-muted)]">Sifted</div>
                        <div className="text-sm font-bold text-[var(--text-primary)]">{progress?.sifted_length ?? 0}</div>
                    </div>
                    <div className="p-2 rounded-lg bg-[var(--bg-secondary)]">
                        <div className="text-[10px] text-[var(--text-muted)]">Key</div>
                        <div className="text-sm font-bold text-[var(--system-green)]">{progress?.final_key_length ?? '-'}</div>
                    </div>
                </div>

                {mobileDetailsOpen && (
                    <div className="mt-4 pt-4 border-t border-[var(--card-border)]">
                        {detailedContent}
                    </div>
                )}
            </div>
        );
    }

    return (
        <section className="dashboard-section relative">
            {/* Background glow for this section */}
            <div className="absolute -inset-4 bg-gradient-to-r from-blue-500/5 to-cyan-500/5 blur-3xl rounded-[3rem] -z-10" />

            {detailedContent}
        </section>
    );
};

export default BB84Simulator;

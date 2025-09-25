import React, { useState, useEffect } from 'react';
import { Play, Pause, RotateCcw, Zap, Eye, EyeOff, AlertTriangle } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import type { BB84Progress } from '../types';

interface BB84SimulatorProps {
    progress: BB84Progress | null;
    sessionKey: Uint8Array | null;
    onStartBB84: () => void;
    userRole: 'alice' | 'bob' | 'eve';
    eveDetected: boolean;
}

const BB84Simulator: React.FC<BB84SimulatorProps> = ({
    progress,
    sessionKey,
    onStartBB84,
    userRole,
    eveDetected
}) => {
    const [showDetails, setShowDetails] = useState(false);
    const [qberHistory, setQberHistory] = useState<{ time: number, qber: number }[]>([]);

    // Update QBER history when progress changes
    useEffect(() => {
        if (progress?.qber !== undefined) {
            setQberHistory(prev => {
                const newEntry = { time: Date.now(), qber: progress.qber! * 100 };
                const updated = [...prev, newEntry];
                // Keep only last 50 points
                return updated.slice(-50);
            });
        }
    }, [progress?.qber]);

    const getStageColor = (stage: string) => {
        if (eveDetected) return 'text-red-600';
        if (progress?.success) return 'text-green-600';

        switch (stage) {
            case 'alice_preparation':
            case 'qubit_preparation':
                return 'text-alice';
            case 'transmission':
            case 'bob_measurement':
                return 'text-bob';
            case 'eve_attack':
                return 'text-eve';
            case 'sifting':
            case 'qber_test':
            case 'complete':
                return 'text-quantum-600';
            default:
                return 'text-gray-600';
        }
    };

    const getProgressBarColor = () => {
        if (eveDetected) return 'bg-red-500';
        if (sessionKey) return 'bg-green-500';
        return 'bg-blue-500';
    };

    const canStartSimulation = () => {
        return userRole === 'alice' && !progress?.stage;
    };

    // Generate visualization data for the current user's perspective
    const getVisualizationData = () => {
        if (!progress) return null;

        // Simulate some bits for visualization
        const sampleBits = Array.from({ length: 20 }, (_, i) => ({
            index: i,
            aliceBit: Math.random() > 0.5 ? 1 : 0,
            aliceBasis: Math.random() > 0.5 ? 'X' : 'Z',
            bobBasis: Math.random() > 0.5 ? 'X' : 'Z',
            bobResult: Math.random() > 0.5 ? 1 : 0,
            matched: Math.random() > 0.5,
            eveIntercept: userRole === 'eve' && Math.random() > 0.7
        }));

        return sampleBits;
    };

    const renderQubitVisualization = () => {
        const bits = getVisualizationData();
        if (!bits) return null;

        return (
            <div className="space-y-4">
                <h4 className="text-sm font-medium text-gray-700">Qubit Transmission (Sample)</h4>
                <div className="overflow-x-auto">
                    <div className="flex space-x-1 min-w-max pb-2">
                        {bits.map((bit, i) => (
                            <div
                                key={i}
                                className={`w-8 h-8 rounded-full border-2 flex items-center justify-center text-xs font-bold transition-all ${bit.matched
                                        ? 'border-green-500 bg-green-100 text-green-700'
                                        : 'border-gray-300 bg-gray-100 text-gray-500'
                                    } ${bit.eveIntercept ? 'ring-2 ring-red-500' : ''}`}
                                title={`Bit ${i}: Alice(${bit.aliceBit},${bit.aliceBasis}) Bob(${bit.bobResult},${bit.bobBasis}) ${bit.matched ? '✓' : '✗'}`}
                            >
                                {userRole === 'alice' ? bit.aliceBit :
                                    userRole === 'bob' ? bit.bobResult :
                                        bit.eveIntercept ? '👁' : '?'}
                            </div>
                        ))}
                    </div>
                </div>
                <div className="text-xs text-gray-500 space-y-1">
                    <div className="flex items-center space-x-4">
                        <div className="flex items-center space-x-1">
                            <div className="w-3 h-3 rounded-full bg-green-100 border border-green-500"></div>
                            <span>Matching bases</span>
                        </div>
                        <div className="flex items-center space-x-1">
                            <div className="w-3 h-3 rounded-full bg-gray-100 border border-gray-300"></div>
                            <span>Different bases</span>
                        </div>
                        {userRole === 'eve' && (
                            <div className="flex items-center space-x-1">
                                <div className="w-3 h-3 rounded-full border border-red-500 ring-1 ring-red-500"></div>
                                <span>Eve intercept</span>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        );
    };

    const renderQBERChart = () => {
        if (qberHistory.length === 0) return null;

        const threshold = (progress?.threshold || 0.11) * 100;

        return (
            <div className="space-y-2">
                <h4 className="text-sm font-medium text-gray-700">QBER Over Time</h4>
                <div className="h-32">
                    <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={qberHistory.map((point, i) => ({ ...point, index: i }))}>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="index" hide />
                            <YAxis domain={[0, Math.max(threshold * 1.5, Math.max(...qberHistory.map(p => p.qber)) * 1.1)]} />
                            <Tooltip
                                formatter={(value: number) => [`${value.toFixed(2)}%`, 'QBER']}
                                labelFormatter={(index: number) => `Measurement ${index + 1}`}
                            />
                            <Line
                                type="monotone"
                                dataKey="qber"
                                stroke={eveDetected ? '#ef4444' : '#3b82f6'}
                                strokeWidth={2}
                                dot={{ fill: eveDetected ? '#ef4444' : '#3b82f6', r: 2 }}
                            />
                            {/* Threshold line */}
                            <Line
                                type="monotone"
                                dataKey={() => threshold}
                                stroke="#f59e0b"
                                strokeDasharray="5 5"
                                strokeWidth={1}
                                dot={false}
                            />
                        </LineChart>
                    </ResponsiveContainer>
                </div>
                <div className="text-xs text-gray-500">
                    Current QBER: {progress?.qber ? (progress.qber * 100).toFixed(2) : '0.00'}%
                    (Threshold: {threshold.toFixed(1)}%)
                </div>
            </div>
        );
    };

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-xl font-semibold text-gray-900">Quantum Key Distribution</h2>
                    <p className="text-sm text-gray-600">
                        {userRole === 'alice' ? 'You are the sender (Alice)' :
                            userRole === 'bob' ? 'You are the receiver (Bob)' :
                                'You are the eavesdropper (Eve)'}
                    </p>
                </div>

                <div className="flex items-center space-x-2">
                    {canStartSimulation() && (
                        <button
                            onClick={onStartBB84}
                            disabled={!!progress?.stage}
                            className="flex items-center space-x-2 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                            <Play className="w-4 h-4" />
                            <span>Start BB84</span>
                        </button>
                    )}

                    <button
                        onClick={() => setShowDetails(!showDetails)}
                        className="flex items-center space-x-2 bg-gray-100 text-gray-700 px-3 py-2 rounded-lg hover:bg-gray-200 transition-colors"
                    >
                        {showDetails ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                        <span>{showDetails ? 'Hide' : 'Show'} Details</span>
                    </button>
                </div>
            </div>

            {/* Progress Bar */}
            {progress && (
                <div className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                        <span className={`font-medium ${getStageColor(progress.stage)}`}>
                            {progress.message || `Stage: ${progress.stage}`}
                        </span>
                        <span className="text-gray-600">
                            {Math.round((progress.progress || 0) * 100)}%
                        </span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-3">
                        <div
                            className={`h-3 rounded-full transition-all duration-500 ${getProgressBarColor()}`}
                            style={{ width: `${(progress.progress || 0) * 100}%` }}
                        />
                    </div>
                </div>
            )}

            {/* Eve Detection Alert */}
            {eveDetected && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                    <div className="flex items-center space-x-2">
                        <AlertTriangle className="w-5 h-5 text-red-600 eve-detected" />
                        <div>
                            <h3 className="text-sm font-medium text-red-800">Eavesdropping Detected!</h3>
                            <p className="text-sm text-red-700">
                                High quantum bit error rate indicates potential security breach. Session compromised.
                            </p>
                        </div>
                    </div>
                </div>
            )}

            {/* Main Content Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Left Panel - Status & Stats */}
                <div className="space-y-4">
                    {/* Current Status Card */}
                    <div className="bg-white border rounded-lg p-4">
                        <h3 className="text-lg font-medium text-gray-900 mb-4">Current Status</h3>

                        {!progress ? (
                            <div className="text-center py-8">
                                <Zap className="w-12 h-12 text-gray-400 mx-auto mb-3" />
                                <p className="text-gray-600">
                                    {userRole === 'alice'
                                        ? 'Ready to start BB84 key generation'
                                        : 'Waiting for Alice to start BB84 protocol'
                                    }
                                </p>
                            </div>
                        ) : (
                            <div className="space-y-3">
                                <div className="flex items-center justify-between">
                                    <span className="text-sm text-gray-600">Stage:</span>
                                    <span className={`text-sm font-medium ${getStageColor(progress.stage)}`}>
                                        {progress.stage.replace('_', ' ').toUpperCase()}
                                    </span>
                                </div>

                                {progress.qber !== undefined && (
                                    <div className="flex items-center justify-between">
                                        <span className="text-sm text-gray-600">QBER:</span>
                                        <span className={`text-sm font-medium ${progress.qber > (progress.threshold || 0.11) ? 'text-red-600' : 'text-green-600'
                                            }`}>
                                            {(progress.qber * 100).toFixed(2)}%
                                        </span>
                                    </div>
                                )}

                                {progress.sifted_length !== undefined && progress.original_length !== undefined && (
                                    <div className="flex items-center justify-between">
                                        <span className="text-sm text-gray-600">Sifted Key:</span>
                                        <span className="text-sm font-medium text-blue-600">
                                            {progress.sifted_length}/{progress.original_length} bits
                                        </span>
                                    </div>
                                )}

                                {progress.final_key_length && (
                                    <div className="flex items-center justify-between">
                                        <span className="text-sm text-gray-600">Final Key:</span>
                                        <span className="text-sm font-medium text-green-600">
                                            {progress.final_key_length} bytes
                                        </span>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>

                    {/* Session Key Status */}
                    <div className="bg-white border rounded-lg p-4">
                        <h3 className="text-lg font-medium text-gray-900 mb-4">Session Key</h3>

                        {sessionKey ? (
                            <div className="space-y-3">
                                <div className="flex items-center space-x-2">
                                    <div className="w-3 h-3 rounded-full bg-green-500"></div>
                                    <span className="text-sm font-medium text-green-700">Key Established</span>
                                </div>
                                <div className="text-xs text-gray-600">
                                    <div>Length: {sessionKey.length} bytes</div>
                                    <div>Format: AES-256 Compatible</div>
                                    <div className="font-mono bg-gray-100 p-2 rounded mt-2">
                                        {Array.from(sessionKey.slice(0, 8)).map(b =>
                                            b.toString(16).padStart(2, '0')
                                        ).join(' ')}...
                                    </div>
                                </div>
                            </div>
                        ) : (
                            <div className="text-center py-4">
                                <div className="w-3 h-3 rounded-full bg-gray-300 mx-auto mb-2"></div>
                                <span className="text-sm text-gray-600">No session key available</span>
                            </div>
                        )}
                    </div>
                </div>

                {/* Right Panel - Visualizations */}
                <div className="space-y-4">
                    {/* Qubit Visualization */}
                    <div className="bg-white border rounded-lg p-4">
                        <h3 className="text-lg font-medium text-gray-900 mb-4">Quantum Transmission</h3>
                        {renderQubitVisualization()}
                    </div>

                    {/* QBER Chart */}
                    {qberHistory.length > 0 && (
                        <div className="bg-white border rounded-lg p-4">
                            {renderQBERChart()}
                        </div>
                    )}
                </div>
            </div>

            {/* Detailed Information (Collapsible) */}
            {showDetails && (
                <div className="bg-gray-50 border rounded-lg p-6">
                    <h3 className="text-lg font-medium text-gray-900 mb-4">BB84 Protocol Details</h3>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {/* Protocol Steps */}
                        <div>
                            <h4 className="text-sm font-medium text-gray-700 mb-3">Protocol Steps</h4>
                            <div className="space-y-2 text-sm">
                                <div className={`flex items-center space-x-2 ${progress?.stage === 'alice_preparation' ? 'text-blue-600 font-medium' : 'text-gray-600'
                                    }`}>
                                    <div className={`w-2 h-2 rounded-full ${progress?.stage === 'alice_preparation' ? 'bg-blue-600' : 'bg-gray-300'
                                        }`}></div>
                                    <span>1. Alice prepares random qubits</span>
                                </div>
                                <div className={`flex items-center space-x-2 ${progress?.stage === 'transmission' ? 'text-blue-600 font-medium' : 'text-gray-600'
                                    }`}>
                                    <div className={`w-2 h-2 rounded-full ${progress?.stage === 'transmission' ? 'bg-blue-600' : 'bg-gray-300'
                                        }`}></div>
                                    <span>2. Qubits transmitted to Bob</span>
                                </div>
                                <div className={`flex items-center space-x-2 ${progress?.stage === 'bob_measurement' ? 'text-blue-600 font-medium' : 'text-gray-600'
                                    }`}>
                                    <div className={`w-2 h-2 rounded-full ${progress?.stage === 'bob_measurement' ? 'bg-blue-600' : 'bg-gray-300'
                                        }`}></div>
                                    <span>3. Bob measures in random bases</span>
                                </div>
                                <div className={`flex items-center space-x-2 ${progress?.stage === 'sifting' ? 'text-blue-600 font-medium' : 'text-gray-600'
                                    }`}>
                                    <div className={`w-2 h-2 rounded-full ${progress?.stage === 'sifting' ? 'bg-blue-600' : 'bg-gray-300'
                                        }`}></div>
                                    <span>4. Sifting: Compare bases publicly</span>
                                </div>
                                <div className={`flex items-center space-x-2 ${progress?.stage === 'qber_test' ? 'text-blue-600 font-medium' : 'text-gray-600'
                                    }`}>
                                    <div className={`w-2 h-2 rounded-full ${progress?.stage === 'qber_test' ? 'bg-blue-600' : 'bg-gray-300'
                                        }`}></div>
                                    <span>5. Test subset for QBER</span>
                                </div>
                                <div className={`flex items-center space-x-2 ${progress?.stage === 'complete' ? 'text-green-600 font-medium' : 'text-gray-600'
                                    }`}>
                                    <div className={`w-2 h-2 rounded-full ${progress?.stage === 'complete' ? 'bg-green-600' : 'bg-gray-300'
                                        }`}></div>
                                    <span>6. Privacy amplification</span>
                                </div>
                            </div>
                        </div>

                        {/* Your Role Information */}
                        <div>
                            <h4 className="text-sm font-medium text-gray-700 mb-3">Your Role: {userRole.charAt(0).toUpperCase() + userRole.slice(1)}</h4>
                            <div className="text-sm text-gray-600 space-y-2">
                                {userRole === 'alice' && (
                                    <>
                                        <p>• Generate random bits and bases</p>
                                        <p>• Prepare qubits in chosen states</p>
                                        <p>• Send qubits to Bob</p>
                                        <p>• Compare bases publicly for sifting</p>
                                        <p>• Reveal test bits for QBER calculation</p>
                                    </>
                                )}
                                {userRole === 'bob' && (
                                    <>
                                        <p>• Choose random measurement bases</p>
                                        <p>• Measure received qubits</p>
                                        <p>• Compare bases with Alice for sifting</p>
                                        <p>• Reveal test bits for QBER calculation</p>
                                        <p>• Generate shared secret key</p>
                                    </>
                                )}
                                {userRole === 'eve' && (
                                    <>
                                        <p>• Intercept qubits between Alice and Bob</p>
                                        <p>• Measure in chosen bases (introduces errors)</p>
                                        <p>• Re-send qubits to Bob</p>
                                        <p>• Your presence increases QBER</p>
                                        <p>• Detection occurs when QBER &gt; threshold</p>
                                    </>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Security Information */}
                    <div className="mt-6 pt-4 border-t border-gray-200">
                        <h4 className="text-sm font-medium text-gray-700 mb-2">Security Properties</h4>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs text-gray-600">
                            <div>
                                <div className="font-medium mb-1">Information-theoretic security</div>
                                <div>Security based on quantum mechanics, not computational assumptions</div>
                            </div>
                            <div>
                                <div className="font-medium mb-1">Eavesdropping detection</div>
                                <div>Any measurement by Eve disturbs quantum states, increasing error rate</div>
                            </div>
                            <div>
                                <div className="font-medium mb-1">Perfect forward secrecy</div>
                                <div>Each session generates a unique ephemeral key</div>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default BB84Simulator;
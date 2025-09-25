import React, { useState } from 'react';
import { Eye, Zap, Radio, Trash2, Play, Pause, RotateCcw, AlertTriangle } from 'lucide-react';
import type { EveParams } from '../types';

interface EveControlPanelProps {
  sessionId: string;
  onEveParamsChange: (params: EveParams) => void;
}

const EveControlPanel: React.FC<EveControlPanelProps> = ({
  sessionId,
  onEveParamsChange
}) => {
  const [attackType, setAttackType] = useState<EveParams['attack_type']>('none');
  const [fraction, setFraction] = useState(0.5);
  const [noiseProbability, setNoiseProbability] = useState(0.1);
  const [lossProbability, setLossProbability] = useState(0.1);
  const [isAttacking, setIsAttacking] = useState(false);

  const handleStartAttack = () => {
    const params: EveParams = {
      attack_type: attackType,
      params: {
        fraction: ['intercept_resend', 'partial_intercept'].includes(attackType) ? fraction : undefined,
        noise_probability: attackType === 'depolarizing' ? noiseProbability : undefined,
        loss_probability: attackType === 'qubit_loss' ? lossProbability : undefined,
      }
    };

    onEveParamsChange(params);
    setIsAttacking(attackType !== 'none');
  };

  const handleStopAttack = () => {
    const params: EveParams = {
      attack_type: 'none',
      params: {}
    };
    
    onEveParamsChange(params);
    setIsAttacking(false);
    setAttackType('none');
  };

  const getAttackDescription = (type: EveParams['attack_type']) => {
    switch (type) {
      case 'intercept_resend':
        return 'Intercept qubits, measure them, and resend new qubits. Classic BB84 attack causing ~25% QBER.';
      case 'partial_intercept':
        return 'Intercept only a fraction of qubits to remain stealthy while still gaining information.';
      case 'depolarizing':
        return 'Introduce random bit/phase flips to simulate noisy channel or sophisticated attack.';
      case 'qubit_loss':
        return 'Drop qubits entirely, simulating lossy channel or denial-of-service attack.';
      default:
        return 'No attack selected. Alice and Bob will communicate securely.';
    }
  };

  const getTheoreticalQBER = () => {
    switch (attackType) {
      case 'intercept_resend':
        return `~${(fraction * 25).toFixed(1)}%`;
      case 'partial_intercept':
        return `~${(fraction * 25).toFixed(1)}%`;
      case 'depolarizing':
        return `~${(noiseProbability * 50).toFixed(1)}%`;
      case 'qubit_loss':
        return 'Variable';
      default:
        return '0%';
    }
  };

  const getDetectionProbability = () => {
    const threshold = 0.11; // 11% QBER threshold
    
    switch (attackType) {
      case 'intercept_resend':
        return fraction * 0.25 > threshold ? 'High' : 'Low';
      case 'partial_intercept':
        return fraction * 0.25 > threshold ? 'High' : 'Low';
      case 'depolarizing':
        return noiseProbability * 0.5 > threshold ? 'High' : 'Low';
      default:
        return 'None';
    }
  };

  return (
    <div className="bg-white border rounded-lg shadow-sm">
      {/* Header */}
      <div className="p-4 border-b bg-red-50">
        <div className="flex items-center space-x-2">
          <Eye className="w-5 h-5 text-red-600" />
          <h3 className="text-lg font-medium text-red-900">Eve Control Panel</h3>
          <div className={`px-2 py-1 rounded-full text-xs font-medium ${
            isAttacking ? 'bg-red-100 text-red-800' : 'bg-gray-100 text-gray-600'
          }`}>
            {isAttacking ? 'ATTACKING' : 'PASSIVE'}
          </div>
        </div>
        <p className="text-sm text-red-700 mt-1">
          Simulate quantum eavesdropping attacks on the BB84 protocol
        </p>
      </div>

      <div className="p-4 space-y-6">
        {/* Attack Type Selection */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Attack Type
          </label>
          <div className="space-y-2">
            {/* None */}
            <div
              className={`p-3 rounded-lg border cursor-pointer transition-all ${
                attackType === 'none' 
                  ? 'border-gray-400 bg-gray-50' 
                  : 'border-gray-200 hover:border-gray-300'
              }`}
              onClick={() => setAttackType('none')}
            >
              <div className="flex items-center space-x-2">
                <input 
                  type="radio" 
                  checked={attackType === 'none'} 
                  onChange={() => setAttackType('none')}
                  className="text-gray-600"
                />
                <span className="font-medium text-gray-900">No Attack</span>
              </div>
              <p className="text-xs text-gray-600 ml-6">Passive observation only</p>
            </div>

            {/* Intercept-Resend */}
            <div
              className={`p-3 rounded-lg border cursor-pointer transition-all ${
                attackType === 'intercept_resend' 
                  ? 'border-red-400 bg-red-50' 
                  : 'border-gray-200 hover:border-red-300'
              }`}
              onClick={() => setAttackType('intercept_resend')}
            >
              <div className="flex items-center space-x-2">
                <input 
                  type="radio" 
                  checked={attackType === 'intercept_resend'} 
                  onChange={() => setAttackType('intercept_resend')}
                  className="text-red-600"
                />
                <span className="font-medium text-gray-900">Intercept & Resend</span>
              </div>
              <p className="text-xs text-gray-600 ml-6">Classic attack - measure and resend qubits</p>
            </div>

            {/* Partial Intercept */}
            <div
              className={`p-3 rounded-lg border cursor-pointer transition-all ${
                attackType === 'partial_intercept' 
                  ? 'border-orange-400 bg-orange-50' 
                  : 'border-gray-200 hover:border-orange-300'
              }`}
              onClick={() => setAttackType('partial_intercept')}
            >
              <div className="flex items-center space-x-2">
                <input 
                  type="radio" 
                  checked={attackType === 'partial_intercept'} 
                  onChange={() => setAttackType('partial_intercept')}
                  className="text-orange-600"
                />
                <span className="font-medium text-gray-900">Partial Intercept</span>
              </div>
              <p className="text-xs text-gray-600 ml-6">Stealthy attack - intercept only some qubits</p>
            </div>

            {/* Depolarizing */}
            <div
              className={`p-3 rounded-lg border cursor-pointer transition-all ${
                attackType === 'depolarizing' 
                  ? 'border-purple-400 bg-purple-50' 
                  : 'border-gray-200 hover:border-purple-300'
              }`}
              onClick={() => setAttackType('depolarizing')}
            >
              <div className="flex items-center space-x-2">
                <input 
                  type="radio" 
                  checked={attackType === 'depolarizing'} 
                  onChange={() => setAttackType('depolarizing')}
                  className="text-purple-600"
                />
                <span className="font-medium text-gray-900">Depolarizing Noise</span>
              </div>
              <p className="text-xs text-gray-600 ml-6">Introduce random bit/phase flips</p>
            </div>

            {/* Qubit Loss */}
            <div
              className={`p-3 rounded-lg border cursor-pointer transition-all ${
                attackType === 'qubit_loss' 
                  ? 'border-yellow-400 bg-yellow-50' 
                  : 'border-gray-200 hover:border-yellow-300'
              }`}
              onClick={() => setAttackType('qubit_loss')}
            >
              <div className="flex items-center space-x-2">
                <input 
                  type="radio" 
                  checked={attackType === 'qubit_loss'} 
                  onChange={() => setAttackType('qubit_loss')}
                  className="text-yellow-600"
                />
                <span className="font-medium text-gray-900">Qubit Loss</span>
              </div>
              <p className="text-xs text-gray-600 ml-6">Drop qubits to simulate lossy channel</p>
            </div>
          </div>
        </div>

        {/* Attack Parameters */}
        {attackType !== 'none' && (
          <div className="space-y-4">
            <h4 className="text-sm font-medium text-gray-700">Attack Parameters</h4>
            
            {/* Fraction for intercept attacks */}
            {['intercept_resend', 'partial_intercept'].includes(attackType) && (
              <div>
                <label className="block text-sm text-gray-600 mb-2">
                  Intercept Fraction: {(fraction * 100).toFixed(0)}%
                </label>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.05"
                  value={fraction}
                  onChange={(e) => setFraction(parseFloat(e.target.value))}
                  className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer slider"
                />
                <div className="flex justify-between text-xs text-gray-500 mt-1">
                  <span>0%</span>
                  <span>50%</span>
                  <span>100%</span>
                </div>
              </div>
            )}

            {/* Noise probability for depolarizing */}
            {attackType === 'depolarizing' && (
              <div>
                <label className="block text-sm text-gray-600 mb-2">
                  Noise Probability: {(noiseProbability * 100).toFixed(0)}%
                </label>
                <input
                  type="range"
                  min="0"
                  max="0.5"
                  step="0.01"
                  value={noiseProbability}
                  onChange={(e) => setNoiseProbability(parseFloat(e.target.value))}
                  className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer slider"
                />
                <div className="flex justify-between text-xs text-gray-500 mt-1">
                  <span>0%</span>
                  <span>25%</span>
                  <span>50%</span>
                </div>
              </div>
            )}

            {/* Loss probability for qubit loss */}
            {attackType === 'qubit_loss' && (
              <div>
                <label className="block text-sm text-gray-600 mb-2">
                  Loss Probability: {(lossProbability * 100).toFixed(0)}%
                </label>
                <input
                  type="range"
                  min="0"
                  max="0.5"
                  step="0.01"
                  value={lossProbability}
                  onChange={(e) => setLossProbability(parseFloat(e.target.value))}
                  className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer slider"
                />
                <div className="flex justify-between text-xs text-gray-500 mt-1">
                  <span>0%</span>
                  <span>25%</span>
                  <span>50%</span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Attack Description */}
        <div className="bg-gray-50 p-3 rounded-lg">
          <h4 className="text-sm font-medium text-gray-700 mb-2">Attack Description</h4>
          <p className="text-xs text-gray-600">
            {getAttackDescription(attackType)}
          </p>
        </div>

        {/* Expected Impact */}
        {attackType !== 'none' && (
          <div className="bg-yellow-50 border border-yellow-200 p-3 rounded-lg">
            <div className="flex items-center space-x-2 mb-2">
              <AlertTriangle className="w-4 h-4 text-yellow-600" />
              <h4 className="text-sm font-medium text-yellow-800">Expected Impact</h4>
            </div>
            <div className="text-xs text-yellow-700 space-y-1">
              <div>Theoretical QBER: {getTheoreticalQBER()}</div>
              <div>Detection Probability: {getDetectionProbability()}</div>
              <div>Threshold: 11% QBER</div>
            </div>
          </div>
        )}

        {/* Control Buttons */}
        <div className="flex space-x-2">
          {!isAttacking ? (
            <button
              onClick={handleStartAttack}
              disabled={attackType === 'none'}
              className="flex items-center space-x-2 bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <Play className="w-4 h-4" />
              <span>Start Attack</span>
            </button>
          ) : (
            <button
              onClick={handleStopAttack}
              className="flex items-center space-x-2 bg-gray-600 text-white px-4 py-2 rounded-lg hover:bg-gray-700 transition-colors"
            >
              <Pause className="w-4 h-4" />
              <span>Stop Attack</span>
            </button>
          )}

          <button
            onClick={() => {
              setAttackType('none');
              setFraction(0.5);
              setNoiseProbability(0.1);
              setLossProbability(0.1);
              handleStopAttack();
            }}
            className="flex items-center space-x-2 bg-gray-100 text-gray-700 px-4 py-2 rounded-lg hover:bg-gray-200 transition-colors"
          >
            <RotateCcw className="w-4 h-4" />
            <span>Reset</span>
          </button>
        </div>

        {/* Session Info */}
        <div className="pt-4 border-t border-gray-200">
          <div className="text-xs text-gray-500">
            <div>Session: <code className="bg-gray-100 px-1 rounded">{sessionId}</code></div>
            <div className="mt-1">
              Status: {isAttacking ? '🔴 Actively attacking' : '🟢 Passive monitoring'}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EveControlPanel;
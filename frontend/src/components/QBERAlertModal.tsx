import React from 'react';

interface QBERAlertModalProps {
  qber: number;
  threshold: number;
  onViewDetails: () => void;
  onAbort: () => void;
  onClose: () => void;
}

const QBERAlertModal: React.FC<QBERAlertModalProps> = ({
  qber,
  threshold,
  onViewDetails,
  onAbort,
  onClose
}) => {
  return (
    <div className="modal-overlay" role="alertdialog" aria-modal="true">
      <div className="qber-alert relative">
        <div className="mb-6">
          <div className="mx-auto w-16 h-16 rounded-full border border-rose-400 flex items-center justify-center text-3xl text-rose-300 animate-pulse">
            !
          </div>
          <h2 className="text-3xl font-bold text-white mt-4">Session Compromised</h2>
          <p className="text-slate-300 mt-2">Quantum Bit Error Rate surpassed safe threshold.</p>
        </div>

        <div className="flex justify-around my-6">
          <div>
            <p className="metric-label">Live QBER</p>
            <p className="metric-value text-rose-300">{(qber * 100).toFixed(2)}%</p>
          </div>
          <div>
            <p className="metric-label">Threshold</p>
            <p className="metric-value text-amber-300">{(threshold * 100).toFixed(1)}%</p>
          </div>
        </div>

        <div className="modal-actions flex flex-col sm:flex-row gap-3 justify-center mt-4">
          <button onClick={onViewDetails} className="bg-white/10 border border-white/20 text-white quantum-button">
            View Details
          </button>
          <button onClick={onAbort} className="bg-gradient-to-r from-rose-600 to-amber-500 text-white quantum-button">
            Abort Session
          </button>
        </div>

        <button onClick={onClose} className="absolute top-4 right-4 text-slate-400 hover:text-white">
          ✕
        </button>
      </div>
    </div>
  );
};

export default QBERAlertModal;




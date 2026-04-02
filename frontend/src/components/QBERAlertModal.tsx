import React, { useEffect, useState } from 'react';
import { AlertTriangle, XOctagon, X, ArrowRight } from 'lucide-react';

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
  const [visible, setVisible] = useState(false);

  // Animation on mount
  useEffect(() => {
    requestAnimationFrame(() => setVisible(true));
  }, []);

  const handleClose = () => {
    setVisible(false);
    setTimeout(onClose, 300);
  };

  return (
    <div
      className={`fixed inset-0 z-50 flex items-center justify-center p-4 transition-all duration-300 ${visible ? 'backdrop-blur-sm bg-black/40' : 'backdrop-blur-none bg-transparent opacity-0'}`}
      role="alertdialog"
      aria-modal="true"
    >
      <div
        className={`relative w-full max-w-md rounded-[32px] overflow-hidden material-thick shadow-2xl border border-red-500/30 transform transition-all duration-500 ${visible ? 'scale-100 translate-y-0 opacity-100' : 'scale-95 translate-y-8 opacity-0'}`}
      >
        {/* Background Glints */}
        <div className="absolute -top-20 -right-20 w-64 h-64 bg-red-500/20 blur-[80px] rounded-full pointer-events-none" />
        <div className="absolute -bottom-20 -left-20 w-64 h-64 bg-orange-500/20 blur-[80px] rounded-full pointer-events-none" />

        <div className="relative p-8 text-center">
          {/* Icon */}
          <div className="mx-auto w-20 h-20 rounded-full bg-gradient-to-br from-red-500/10 to-orange-500/10 border border-red-500/20 flex items-center justify-center mb-6 shadow-inner relative">
            <div className="absolute inset-0 rounded-full bg-red-500/10 animate-ping opacity-20" />
            <AlertTriangle className="w-10 h-10 text-red-500" />
          </div>

          {/* Text */}
          <h2 className="text-2xl font-bold text-[var(--text-primary)] mb-2">Security Breach Detected</h2>
          <p className="text-sm text-[var(--text-secondary)] mb-8 leading-relaxed">
            Quantum Bit Error Rate (QBER) has exceeded the safety threshold. This indicates a high probability of eavesdropping on the channel.
          </p>

          {/* Metrics */}
          <div className="grid grid-cols-2 gap-4 mb-8">
            <div className="p-4 rounded-2xl bg-red-500/5 border border-red-500/10">
              <p className="text-[10px] font-bold text-red-600/70 uppercase tracking-wider mb-1">Current QBER</p>
              <p className="text-2xl font-bold text-red-600">{(qber * 100).toFixed(2)}%</p>
            </div>
            <div className="p-4 rounded-2xl bg-[var(--bg-secondary)] border border-[var(--card-border)]">
              <p className="text-[10px] font-bold text-[var(--text-muted)] uppercase tracking-wider mb-1">Threshold</p>
              <p className="text-2xl font-bold text-[var(--text-secondary)]">{(threshold * 100).toFixed(1)}%</p>
            </div>
          </div>

          {/* Actions */}
          <div className="flex flex-col gap-3">
            <button
              onClick={() => {
                onAbort();
                handleClose();
              }}
              className="w-full py-3.5 rounded-xl bg-gradient-to-r from-red-500 to-orange-600 text-white font-bold shadow-lg shadow-red-500/20 hover:shadow-red-500/40 active:scale-[0.98] transition-all flex items-center justify-center gap-2"
            >
              <XOctagon className="w-5 h-5" />
              Abort Protocol
            </button>

            <button
              onClick={() => {
                onViewDetails();
                handleClose();
              }}
              className="w-full py-3.5 rounded-xl bg-[var(--bg-secondary)] text-[var(--text-primary)] font-semibold border border-[var(--card-border)] hover:bg-[var(--bg-primary)] active:scale-[0.98] transition-all flex items-center justify-center gap-2"
            >
              Analyze Threat
              <ArrowRight className="w-4 h-4 ml-1 opacity-50" />
            </button>
          </div>
        </div>

        {/* Close Button */}
        <button
          onClick={handleClose}
          className="absolute top-4 right-4 p-2 rounded-full text-[var(--text-secondary)] hover:bg-[var(--bg-secondary)] transition-colors"
        >
          <X className="w-5 h-5" />
        </button>
      </div>
    </div>
  );
};

export default QBERAlertModal;

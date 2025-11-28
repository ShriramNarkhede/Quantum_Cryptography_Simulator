import React from 'react';
import { Upload, Download, ShieldCheck, LockKeyhole, FileText } from 'lucide-react';
import type { FileTransferInfo } from '../types';

interface FileTransferModuleProps {
  transfers: FileTransferInfo[];
  disabled: boolean;
  onUpload: (file: File) => void | Promise<void>;
  onDownload: (messageId: string, encrypted: boolean) => void;
}

const FileTransferModule: React.FC<FileTransferModuleProps> = ({
  transfers,
  disabled,
  onUpload,
  onDownload
}) => {
  const [dragging, setDragging] = React.useState(false);
  const [selectedFile, setSelectedFile] = React.useState<File | null>(null);
  const [progress, setProgress] = React.useState(0);
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  const handleFiles = async (file: File) => {
    if (disabled) return;
    setSelectedFile(file);
    setProgress(0.1);
    setTimeout(() => setProgress(0.45), 200);
    await onUpload(file);
    setProgress(1);
    setTimeout(() => {
      setSelectedFile(null);
      setProgress(0);
    }, 600);
  };

  const onDrop = (event: React.DragEvent) => {
    event.preventDefault();
    setDragging(false);
    const file = event.dataTransfer.files?.[0];
    if (file) {
      handleFiles(file);
    }
  };

  return (
    <section className="glass-card glow-border flex flex-col gap-4">
      <header className="flex items-center justify-between">
        <div>
          <p className="metric-label">Quantum File Bridge</p>
          <h3 className="text-xl font-semibold text-white">Encrypted File Transfer</h3>
        </div>
        <span className="session-chip">
          <ShieldCheck className="w-4 h-4 text-emerald-300" />
          <span className="text-xs">AES-256 · GCM</span>
        </span>
      </header>

      <div
        className={`drag-zone ${dragging ? 'drag-over' : ''} ${disabled ? 'opacity-40 cursor-not-allowed' : ''}`}
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
      >
        <Upload className="w-6 h-6 mx-auto mb-2 text-cyan-300" />
        <p className="text-sm text-slate-200">Drag & drop files here</p>
        <p className="text-xs text-slate-400">or</p>
        <button
          onClick={() => fileInputRef.current?.click()}
          className="quantum-button bg-white/10 border border-white/20 text-white mt-2"
          disabled={disabled}
        >
          Browse Files
        </button>
        <input
          ref={fileInputRef}
          type="file"
          hidden
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleFiles(file);
          }}
        />
      </div>

      {selectedFile && (
        <div className="rounded-2xl bg-black/40 border border-cyan-500/30 p-4 space-y-3">
          <div className="flex items-center justify-between text-sm">
            <span className="font-medium text-cyan-200">{selectedFile.name}</span>
            <span className="text-slate-400">{(selectedFile.size / 1024).toFixed(1)} KB</span>
          </div>
          <div className="h-2 rounded-full bg-white/10 overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-500"
              style={{ width: `${progress * 100}%` }}
            />
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-300">
            <LockKeyhole className="w-4 h-4 text-cyan-200" />
            Encrypting with AES-256-GCM + One-Time Pad overlay
          </div>
        </div>
      )}

      <div>
        <p className="metric-label mb-2">Recent Transfers</p>
        <div className="space-y-3 max-h-48 overflow-y-auto pr-1">
          {transfers.length === 0 && (
            <div className="text-sm text-slate-400">No secure files exchanged yet.</div>
          )}
          {transfers.map((transfer) => (
            <div key={transfer.message_id} className="flex items-center justify-between rounded-xl bg-white/5 p-3 border border-white/5">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/30 to-blue-500/30 flex items-center justify-center">
                  <FileText className="w-5 h-5 text-cyan-200" />
                </div>
                <div>
                  <p className="text-sm font-medium text-white">{transfer.filename}</p>
                  <p className="text-xs text-slate-400">
                    {(transfer.file_size / 1024).toFixed(1)} KB · {new Date(transfer.timestamp).toLocaleTimeString()}
                  </p>
                </div>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => onDownload(transfer.message_id, false)}
                  className="session-chip alice text-xs"
                  disabled={!transfer.download_ready}
                >
                  <Download className="w-4 h-4" />
                  Decrypt
                </button>
                <button
                  onClick={() => onDownload(transfer.message_id, true)}
                  className="session-chip bob text-xs"
                >
                  <LockKeyhole className="w-4 h-4" />
                  Raw
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default FileTransferModule;




import React, { useState, useRef, useEffect } from 'react';
import { Send, Lock, Unlock, Download, Upload, AlertCircle, MessageCircle } from 'lucide-react';
import type{ User } from '../types';

interface Message {
  message_id: string;
  sender_id: string;
  content?: string;
  encrypted_content?: string;
  timestamp: string;
  type: 'sent' | 'received' | 'system';
  file_info?: {
    filename: string;
    file_size: number;
    encrypted: boolean;
    download_ready: boolean;
  };
}

interface ChatInterfaceProps {
  messages: Message[];
  onSendMessage: (content: string) => void;
  onDecryptMessage?: (messageId: string) => void; // optional: hook for external decryption flow
  onFileUpload?: (file: File) => void; // optional: delegate file uploads to parent
  onFileDownload?: (messageId: string, encrypted: boolean) => void; // optional: delegate file downloads to parent
  currentUser: User | null;
  sessionKey: Uint8Array | null;
  sessionId?: string; // session ID for API calls
  disabled: boolean;
  autoScroll?: boolean;
}

const ChatInterface: React.FC<ChatInterfaceProps> = ({
  messages,
  onSendMessage,
  onDecryptMessage,
  onFileUpload,
  onFileDownload,
  currentUser,
  sessionKey,
  sessionId,
  disabled,
  autoScroll = true
}) => {
  // Render a short preview that looks like encrypted text instead of a static placeholder
  const getEncryptedPreview = (cipher?: string): string => {
    if (!cipher) return '[Encrypted]';
    const compact = cipher.replace(/\s+/g, '');
    if (compact.length <= 20) return compact;
    const head = compact.slice(0, 24);
    const tail = compact.slice(-8);
    return `${head}…${tail}`;
  };
  const [newMessage, setNewMessage] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [encryptProgress, setEncryptProgress] = useState<number>(0);
  const [showEncryption, setShowEncryption] = useState(false);
  const [showKeyConfirmDialog, setShowKeyConfirmDialog] = useState<{
    mode: 'encrypt' | 'decrypt' | null;
    messageId?: string;
  }>({ mode: null });
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Auto-scroll to bottom when new messages arrive (configurable)
  useEffect(() => {
    if (!autoScroll) return;
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, autoScroll]);

  const handleSendMessage = () => {
    if (!newMessage.trim() || disabled) return;

    onSendMessage(newMessage.trim());
    setNewMessage('');
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
    }
  };

  const handleFileUpload = async () => {
    if (!selectedFile || disabled) return;

    if (!sessionKey) {
      console.error('No session key available for encryption. Please complete the BB84 key generation first.');
      return;
    }

    // Validate session key before showing dialog
    if (sessionKey.length !== 32) {
      console.error(`Session key is not ready (${sessionKey.length} bytes). Please wait for key generation to complete or retry.`);
      return;
    }

    // Show confirmation dialog
    setShowKeyConfirmDialog({ mode: 'encrypt' });
  };

  // Decryption is handled server-side; UI triggers via onDecryptMessage

  const formatTimestamp = (timestamp: string): string => {
    return new Date(timestamp).toLocaleTimeString();
  };

  const getRoleName = (senderId: string): string => {
    if (senderId === 'system') return 'System';
    if (senderId === currentUser?.user_id) return 'You';
    return 'Other User'; // In real implementation, look up by user ID
  };

  const getEncryptionStatus = (): { icon: React.ReactNode; text: string; color: string } => {
    if (!sessionKey) {
      return {
        icon: <Unlock className="w-4 h-4" />,
        text: 'No encryption key',
        color: 'text-red-600'
      };
    }
    if (disabled) {
      return {
        icon: <AlertCircle className="w-4 h-4" />,
        text: 'Channel compromised',
        color: 'text-red-600'
      };
    }
    return {
      icon: <Lock className="w-4 h-4" />,
      text: 'OTP Encrypted',
      color: 'text-green-600'
    };
  };

  const encryptionStatus = getEncryptionStatus();

  return (
    <div className="glass-card glow-border flex flex-col h-[620px] relative overflow-hidden">
      <div className="absolute inset-0 opacity-30 pointer-events-none" aria-hidden="true">
        <div className="quantum-particles" />
      </div>
      <div className="relative flex-1 flex flex-col">
        <div className="flex items-center justify-between pb-4 border-b border-white/10">
          <div className="flex items-center gap-3">
            <MessageCircle className="w-5 h-5 text-cyan-300" />
            <div>
              <h3 className="text-lg font-semibold text-white">Secure Chat Tunnel</h3>
              <p className="text-xs text-slate-300">End-to-end OTP with quantum key refresh</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className={`session-chip ${disabled ? 'eve' : 'alice'}`}>
              {encryptionStatus.icon}
              <span className="text-xs">{encryptionStatus.text}</span>
            </div>
            <button
              onClick={() => setShowEncryption(!showEncryption)}
              className="copy-button"
              title="Encryption details"
            >
              <AlertCircle className="w-4 h-4" />
            </button>
          </div>
        </div>

        {showEncryption && (
          <div className="mt-4 rounded-2xl bg-black/30 border border-white/10 p-3 text-xs text-slate-200 space-y-1">
            <div>Algorithm: OTP + AES-256-GCM transport</div>
            <div>Key length: {sessionKey ? `${sessionKey.length * 8} bits` : '—'}</div>
            <div>Status: {sessionKey ? 'Information-theoretically secure' : 'Awaiting key'}</div>
          </div>
        )}

        <div className="flex-1 mt-4 overflow-y-auto space-y-4 pr-2">
          {messages.length === 0 ? (
            <div className="text-center text-slate-300 py-12">
              <MessageCircle className="w-12 h-12 text-slate-600 mx-auto mb-4" />
              <p>No transmissions yet</p>
              <p className="text-xs text-slate-500">{sessionKey ? 'Channel ready' : 'Generate key to begin'}</p>
            </div>
          ) : (
            messages.map((message, index) => {
              const isSystem = message.type === 'system';
              const isSender = message.type === 'sent';
              const roleClass = (() => {
                if (isSystem) return '';
                if (isSender) {
                  if (currentUser?.role === 'alice') return 'alice';
                  if (currentUser?.role === 'bob') return 'bob';
                  return 'eve';
                }
                return currentUser?.role === 'alice' ? 'bob' : 'alice';
              })();

              return (
                <div
                  key={`${message.message_id}-${index}`}
                  className={`flex ${isSystem ? 'justify-center' : isSender ? 'justify-end' : 'justify-start'}`}
                >
                  {isSystem ? (
                    <div className="session-chip">{message.content}</div>
                  ) : (
                    <div className={`secure-message ${roleClass}`}>
                      <div className="flex items-center justify-between mb-2 text-xs text-slate-200 gap-3">
                        <span className="font-semibold tracking-wide">
                          {getRoleName(message.sender_id)}
                        </span>
                        <span className="text-slate-400">{formatTimestamp(message.timestamp)}</span>
                      </div>
                      <div className="text-sm leading-relaxed">
                        {message.file_info ? (
                          <div className="rounded-2xl bg-black/40 border border-white/10 p-3 space-y-2">
                            <div className="flex items-center gap-2 text-xs uppercase tracking-widest text-slate-300">
                              <Upload className="w-4 h-4" />
                              <span>Secure File</span>
                            </div>
                            <p className="text-white text-sm font-medium">{message.file_info.filename}</p>
                            <p className="text-xs text-slate-400">
                              {(message.file_info.file_size / 1024).toFixed(1)} KB • AES-256-GCM
                            </p>
                            <div className="flex flex-wrap gap-2">
                              {onDecryptMessage && message.type === 'received' && currentUser?.role !== 'eve' && (
                                <button
                                  onClick={() => onDecryptMessage(message.message_id)}
                                  className="session-chip alice text-xs"
                                >
                                  <Lock className="w-3 h-3" />
                                  Decrypt
                                </button>
                              )}
                              {message.file_info.download_ready && (
                                <>
                                  <button
                                    onClick={() => {
                                      if (!sessionKey) {
                                        console.error('No session key available for decryption.');
                                        return;
                                      }
                                      setShowKeyConfirmDialog({ mode: 'decrypt', messageId: message.message_id });
                                    }}
                                    className="session-chip bob text-xs"
                                  >
                                    <Download className="w-3 h-3" /> Download
                                  </button>
                                  {onFileDownload && (
                                    <button
                                      onClick={() => onFileDownload(message.message_id, true)}
                                      className="session-chip eve text-xs"
                                    >
                                      <Lock className="w-3 h-3" />
                                      Raw
                                    </button>
                                  )}
                                </>
                              )}
                            </div>
                          </div>
                        ) : (
                          <>
                            <p>{message.content || getEncryptedPreview(message.encrypted_content)}</p>
                            {message.encrypted_content && !message.content && onDecryptMessage && message.type === 'received' && currentUser?.role !== 'eve' && (
                              <button
                                onClick={() => onDecryptMessage(message.message_id)}
                                className="session-chip alice text-xs mt-2"
                              >
                                <Lock className="w-3 h-3" />
                                Decrypt
                              </button>
                            )}
                          </>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}
          <div ref={messagesEndRef} />
        </div>

        {selectedFile && (
          <div className="mt-4 rounded-2xl bg-cyan-500/10 border border-cyan-300/30 p-4">
            <div className="flex items-center justify-between text-sm">
              <span className="text-cyan-100">{selectedFile.name}</span>
              <span className="text-slate-300">{(selectedFile.size / 1024).toFixed(1)} KB</span>
            </div>
            <div className="mt-2 h-2 rounded-full bg-white/10 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-500"
                style={{ width: `${Math.round((encryptProgress || 0) * 100)}%` }}
              />
            </div>
            <div className="mt-3 flex items-center justify-end gap-3 text-xs text-slate-300">
              <button onClick={() => setSelectedFile(null)}>Cancel</button>
              <button
                className="session-chip alice"
                disabled={disabled}
                onClick={handleFileUpload}
              >
                <Upload className="w-4 h-4" />
                Encrypt & Send
              </button>
            </div>
          </div>
        )}

        <div className="mt-auto pt-4">
          <div className="flex items-end gap-3">
            <div className="flex-1 rounded-2xl bg-black/40 border border-white/10 px-4 py-3">
              <textarea
                value={newMessage}
                onChange={(e) => setNewMessage(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder={disabled ? 'Channel unavailable' : 'Compose quantum-secure message…'}
                disabled={disabled}
                rows={2}
                className="w-full bg-transparent text-white placeholder:text-slate-500 focus:outline-none resize-none"
              />
            </div>
            <button
              onClick={() => fileInputRef.current?.click()}
              className="quantum-button bg-white/10 border border-white/20 text-white"
              disabled={disabled}
            >
              <Upload className="w-4 h-4" />
            </button>
            <button
              onClick={handleSendMessage}
              disabled={disabled || !newMessage.trim()}
              className="quantum-button bg-gradient-to-r from-cyan-500 to-blue-500 text-white flex items-center gap-2 disabled:opacity-50"
            >
              <Send className="w-4 h-4" />
              Send
            </button>
          </div>
          {newMessage && !disabled && (
            <div className="typing-indicator mt-2 text-xs text-slate-300 flex items-center gap-2">
              <span></span>
              <span></span>
              <span></span>
              <span className="ml-2 text-slate-300">Encrypting…</span>
            </div>
          )}
          <p className="mt-3 text-[11px] text-slate-400">
            {disabled
              ? (!sessionKey ? 'No quantum key available' : 'Channel paused due to high QBER')
              : 'Press Enter to transmit with OTP sealing'}
          </p>
        </div>
      </div>

      <input
        ref={fileInputRef}
        type="file"
        onChange={handleFileSelect}
        className="hidden"
        accept="*/*"
      />

      {/* Key Confirmation Dialog */}
      {showKeyConfirmDialog.mode && (
        <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-lg w-80 p-4">
            <h4 className="text-sm font-medium text-gray-900 mb-2">
              {showKeyConfirmDialog.mode === 'encrypt' ? 'Encrypt File with Session Key' : 'Decrypt File with Session Key'}
            </h4>
            <p className="text-xs text-gray-600 mb-3">
              {showKeyConfirmDialog.mode === 'encrypt' 
                ? 'Use your quantum-generated session key to encrypt this file before sending?'
                : 'Use your quantum-generated session key to decrypt this file for download?'
              }
            </p>
            <div className="mt-3 flex justify-end space-x-2">
              <button 
                className="text-sm text-gray-600 hover:text-gray-800" 
                onClick={() => setShowKeyConfirmDialog({ mode: null })}
              >
                Cancel
              </button>
              <button
                className="text-sm bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700"
                onClick={async () => {
                  if (showKeyConfirmDialog.mode === 'encrypt' && selectedFile) {
                    try {
                      // New flow: send plaintext to backend; backend handles encryption.
                      setEncryptProgress(0);

                      if (onFileUpload) {
                        await onFileUpload(selectedFile);
                      } else {
                        // Fallback: post a stub message
                        onSendMessage(`📎 File: ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)`);
                      }

                      // Reset UI state
                      setSelectedFile(null);
                      setShowKeyConfirmDialog({ mode: null });
                      setEncryptProgress(0);
                      if (fileInputRef.current) fileInputRef.current.value = '';
                    } catch (e) {
                      console.error('File send failed:', e);
                    }
                  } else if (showKeyConfirmDialog.mode === 'decrypt' && showKeyConfirmDialog.messageId) {
                    try {
                      setEncryptProgress(0);
                      
                      // Fetch encrypted file from server
                      const apiService = (await import('../services/apiService')).default;
                      const response = await apiService.downloadEncryptedFile(
                        sessionId || 'current-session-id',
                        showKeyConfirmDialog.messageId,
                        currentUser?.user_id || 'current-user'
                      );
                      
                      // Convert base64 to Uint8Array
                      // The server has already decrypted the file, so we just need to convert the data
                      const binaryString = atob(response.file_data);
                      const decryptedData = new Uint8Array(binaryString.length);
                      for (let i = 0; i < binaryString.length; i++) {
                        decryptedData[i] = binaryString.charCodeAt(i);
                      }
                      
                      console.log('Downloaded decrypted file data from server:');
                      console.log('- File size:', decryptedData.length, 'bytes');
                      console.log('- Filename:', response.filename);
                      
                      // Create blob and trigger download
                      const decryptedArray = new Uint8Array(decryptedData.length);
                      decryptedArray.set(decryptedData);
                      const decryptedBlob = new Blob([decryptedArray], { type: 'application/octet-stream' });
                      const url = URL.createObjectURL(decryptedBlob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = response.filename || 'decrypted_file';
                      document.body.appendChild(a);
                      a.click();
                      document.body.removeChild(a);
                      URL.revokeObjectURL(url);
                      
                      setShowKeyConfirmDialog({ mode: null });
                      setEncryptProgress(0);
                    } catch (e) {
                      console.error('File download error:', e);
                      
                      let errorMessage = 'File download failed. ';
                      if (e instanceof Error) {
                        if (e.message.includes('Failed to decrypt file')) {
                          errorMessage += 'The server could not decrypt the file. This might be because the session key has changed or the file is corrupted.';
                        } else if (e.message.includes('File message not found')) {
                          errorMessage += 'The file message was not found. It may have been deleted or the session has expired.';
                        } else {
                          errorMessage += e.message;
                        }
                      } else {
                        errorMessage += 'Unknown error occurred. Please check console for details.';
                      }
                      
                      console.error(errorMessage);
                    }
                  }
                }}
              >
                Yes, Use Session Key
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};

export default ChatInterface;


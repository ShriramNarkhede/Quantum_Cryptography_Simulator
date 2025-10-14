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
  onEnsureSessionKeyReady?: () => Promise<boolean>; // optional: ensure session key is ready
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
  onEnsureSessionKeyReady,
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
  const [isEncrypting, setIsEncrypting] = useState<boolean>(false);
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

  const getRoleColor = (senderId: string): string => {
    if (senderId === 'system') return 'text-gray-600';
    if (senderId === currentUser?.user_id) return 'text-blue-600';
    
    // Determine color based on message position/context
    return 'text-green-600'; // Assume other party
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
    <div className="bg-white border rounded-lg shadow-sm flex flex-col h-[600px]">
      {/* Header */}
      <div className="p-4 border-b bg-gray-50">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <MessageCircle className="w-5 h-5 text-gray-600" />
            <h3 className="text-lg font-medium text-gray-900">Secure Chat</h3>
          </div>
          
          <div className="flex items-center space-x-2">
            <div className={`flex items-center space-x-1 ${encryptionStatus.color}`}>
              {encryptionStatus.icon}
              <span className="text-sm font-medium">{encryptionStatus.text}</span>
            </div>
            
            <button
              onClick={() => setShowEncryption(!showEncryption)}
              className="text-gray-400 hover:text-gray-600"
              title="Toggle encryption details"
            >
              <AlertCircle className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Encryption Details */}
        {showEncryption && (
          <div className="mt-3 pt-3 border-t border-gray-200">
            <div className="text-xs text-gray-600 space-y-1">
              <div>Encryption: {sessionKey ? 'One-Time Pad (OTP)' : 'None'}</div>
              <div>Key Length: {sessionKey ? `${sessionKey.length * 8} bits` : 'N/A'}</div>
              <div>Security: {sessionKey ? 'Information-theoretically secure' : 'Unencrypted'}</div>
            </div>
          </div>
        )}
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {messages.length === 0 ? (
          <div className="text-center text-gray-500 py-8">
            <MessageCircle className="w-12 h-12 text-gray-300 mx-auto mb-3" />
            <p>No messages yet</p>
            <p className="text-sm">{sessionKey ? 'Start chatting securely!' : 'Generate a session key first'}</p>
          </div>
        ) : (
          messages.map((message, index) => (
            <div
              key={`${message.message_id}-${index}-${message.timestamp}`}
              className={`flex ${message.type === 'sent' ? 'justify-end' : 
                         message.type === 'system' ? 'justify-center' : 'justify-start'}`}
            >
              {message.type === 'system' ? (
                <div className="bg-gray-100 text-gray-600 px-3 py-1 rounded-full text-sm">
                  {message.content}
                </div>
              ) : (
                <div className={`max-w-xs lg:max-w-md ${
                  message.type === 'sent' ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-900'
                } rounded-lg p-3`}>
                  <div className="flex items-start justify-between mb-1">
                    <span className={`text-xs font-medium ${
                      message.type === 'sent' ? 'text-blue-100' : getRoleColor(message.sender_id)
                    }`}>
                      {getRoleName(message.sender_id)}
                    </span>
                    <span className={`text-xs ml-2 ${
                      message.type === 'sent' ? 'text-blue-100' : 'text-gray-500'
                    }`}>
                      {formatTimestamp(message.timestamp)}
                    </span>
                  </div>
                  
                  <div className="text-sm">
                    {message.file_info ? (
                      <div className="p-3 bg-gray-50 rounded border">
                        <div className="flex items-center space-x-2 mb-2">
                          <Upload className="w-4 h-4 text-gray-600" />
                          <div className="flex-1">
                            <div className="font-medium text-sm">{message.file_info.filename}</div>
                            <div className="text-xs text-gray-500">
                              {(message.file_info.file_size / 1024).toFixed(1)} KB
                              {message.file_info.encrypted && ' • Encrypted'}
                            </div>
                          </div>
                        </div>
                        
                        {message.file_info.encrypted && (
                          <div className="space-y-2">
                            <div className="flex items-center space-x-1 text-xs text-gray-500">
                              <Lock className="w-3 h-3" />
                              <span>Encrypted file</span>
                            </div>
                            <div className="flex flex-wrap gap-2">
                              {onDecryptMessage && message.type === 'received' && currentUser?.role !== 'eve' && (
                                <button
                                  onClick={() => onDecryptMessage(message.message_id)}
                                  className="px-2 py-1 text-xs bg-blue-100 text-blue-700 rounded hover:bg-blue-200"
                                >
                                  Decrypt
                                </button>
                              )}
                              {message.file_info.download_ready && (
                                <>
                                  <button
                                    onClick={() => {
                                      if (!sessionKey) {
                                        console.error('No session key available for decryption. Please complete the BB84 key generation first.');
                                        return;
                                      }
                                      setShowKeyConfirmDialog({ mode: 'decrypt', messageId: message.message_id });
                                    }}
                                    className="px-2 py-1 text-xs bg-green-100 text-green-700 rounded hover:bg-green-200 flex items-center space-x-1"
                                    title="Download decrypted file"
                                  >
                                    <Download className="w-3 h-3" />
                                    <span>Download Decrypted</span>
                                  </button>
                                  {onFileDownload && (
                                    <button
                                      onClick={() => onFileDownload(message.message_id, true)}
                                      className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded hover:bg-gray-200 flex items-center space-x-1"
                                      title="Download encrypted file"
                                    >
                                      <Lock className="w-3 h-3" />
                                      <Download className="w-3 h-3" />
                                      <span>Download Encrypted</span>
                                    </button>
                                  )}
                                </>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    ) : (
                      message.content || (message.encrypted_content ? getEncryptedPreview(message.encrypted_content) : '[No content]')
                    )}
                  </div>

                  {/* Encryption indicator */}
                  {message.encrypted_content && (
                    <div className="flex items-center justify-between mt-2">
                      <div className={`flex items-center space-x-1 ${
                        message.type === 'sent' ? 'text-blue-200' : 'text-gray-500'
                      }`}>
                        <Lock className="w-3 h-3" />
                        <span className="text-xs">Encrypted</span>
                      </div>
                      {onDecryptMessage && message.type === 'received' && currentUser?.role !== 'eve' && (
                        <button
                          onClick={() => onDecryptMessage(message.message_id)}
                          className="text-blue-600 hover:text-blue-800 text-xs"
                        >
                          Decrypt
                        </button>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Area */}
      <div className="p-4 border-t bg-gray-50">
        {/* File Upload Section */}
        {selectedFile && (
          <div className="mb-3 p-3 bg-blue-50 border border-blue-200 rounded-lg">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Upload className="w-4 h-4 text-blue-600" />
                <span className="text-sm text-blue-800">
                  {selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB)
                </span>
              </div>
              <div className="flex items-center space-x-3">
                {isEncrypting && (
                  <div className="text-xs text-blue-800">
                    Encrypting… {Math.round(encryptProgress * 100)}%
                  </div>
                )}
                <button
                  onClick={handleFileUpload}
                  disabled={disabled}
                  className="text-sm bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700 disabled:opacity-50"
                >
                  Send
                </button>
                <button
                  onClick={() => setSelectedFile(null)}
                  className="text-sm text-blue-600 hover:text-blue-800"
                >
                  Cancel
                </button>
              </div>
            </div>
            {isEncrypting && (
              <div className="mt-2 w-full bg-blue-100 rounded h-2">
                <div className="h-2 bg-blue-600 rounded" style={{ width: `${Math.round(encryptProgress * 100)}%` }} />
              </div>
            )}
          </div>
        )}

        {/* Message Input */}
        <div className="flex items-end space-x-2">
          <div className="flex-1">
            <textarea
              value={newMessage}
              onChange={(e) => setNewMessage(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder={disabled ? 
                'Cannot send messages (no key or channel compromised)' : 
                'Type a message...'
              }
              disabled={disabled}
              rows={2}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:bg-gray-100 disabled:cursor-not-allowed"
            />
          </div>

          {/* File Upload Button */}
          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={disabled}
            className="p-2 text-gray-500 hover:text-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
            title="Upload file"
          >
            <Upload className="w-5 h-5" />
          </button>

          {/* Send Button */}
          <button
            onClick={handleSendMessage}
            disabled={disabled || !newMessage.trim()}
            className="p-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
            title="Send message"
          >
            <Send className="w-5 h-5" />
          </button>
        </div>

        {/* Status Text */}
        <div className="mt-2 text-xs text-gray-500">
          {disabled ? (
            <span className="text-red-600">
              {!sessionKey ? 'No encryption key available' : 'Channel may be compromised by Eve'}
            </span>
          ) : (
            <span>
              Messages are encrypted with quantum-generated key • Press Enter to send
            </span>
          )}
        </div>

        {/* Hidden File Input */}
        <input
          ref={fileInputRef}
          type="file"
          onChange={handleFileSelect}
          className="hidden"
          accept="*/*"
        />
      </div>

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
                      setIsEncrypting(true);
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
                      setIsEncrypting(false);
                      setEncryptProgress(0);
                      if (fileInputRef.current) fileInputRef.current.value = '';
                    } catch (e) {
                      console.error('File send failed:', e);
                      setIsEncrypting(false);
                    }
                  } else if (showKeyConfirmDialog.mode === 'decrypt' && showKeyConfirmDialog.messageId) {
                    try {
                      setIsEncrypting(true);
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
                      setIsEncrypting(false);
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
                      setIsEncrypting(false);
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
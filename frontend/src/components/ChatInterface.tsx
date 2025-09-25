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
}

interface ChatInterfaceProps {
  messages: Message[];
  onSendMessage: (content: string) => void;
  currentUser: User | null;
  sessionKey: Uint8Array | null;
  disabled: boolean;
}

const ChatInterface: React.FC<ChatInterfaceProps> = ({
  messages,
  onSendMessage,
  currentUser,
  sessionKey,
  disabled
}) => {
  const [newMessage, setNewMessage] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [showEncryption, setShowEncryption] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

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

  const handleFileUpload = () => {
    if (!selectedFile || disabled) return;

    // Simple file "encryption" for demo - in real implementation, use AES-GCM
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = `📎 File: ${selectedFile.name} (${selectedFile.size} bytes) [Encrypted with session key]`;
      onSendMessage(content);
      setSelectedFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    };
    reader.readAsArrayBuffer(selectedFile);
  };

  const decryptMessage = (encryptedContent: string): string => {
    // Simple demo decryption - in real implementation, use proper OTP/AES
    try {
      return atob(encryptedContent); // Base64 decode for demo
    } catch {
      return '[Decryption failed]';
    }
  };

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
          messages.map((message) => (
            <div
              key={message.message_id}
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
                    {message.content || (message.encrypted_content ? decryptMessage(message.encrypted_content) : '[No content]')}
                  </div>

                  {/* Encryption indicator */}
                  {message.encrypted_content && (
                    <div className={`flex items-center space-x-1 mt-1 ${
                      message.type === 'sent' ? 'text-blue-200' : 'text-gray-500'
                    }`}>
                      <Lock className="w-3 h-3" />
                      <span className="text-xs">Encrypted</span>
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
              <div className="flex space-x-2">
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
    </div>
  );
};

export default ChatInterface;
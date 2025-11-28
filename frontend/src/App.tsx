import React, { useState, useEffect, useCallback } from 'react';
import { Shield, Wifi, WifiOff, AlertTriangle, Menu, X } from 'lucide-react';
import SessionManager from './components/SessionManager';
import BB84Simulator from './components/BB84Simulator';
import ChatInterface from './components/ChatInterface';
import EveControlPanel from './components/EveControlPanel';
import CryptoMonitor from './components/CryptoMonitor';
import SecurityDashboard from "./components/SecurityDashboard";
import SessionControlPanel from './components/SessionControlPanel';
import KeyStatusPanel from './components/KeyStatusPanel';
import FileTransferModule from './components/FileTransferModule';
import QBERAlertModal from './components/QBERAlertModal';
import ThemeToggle from './components/ThemeToggle';
import CollapsibleSection from './components/CollapsibleSection';
import socketService from './services/socketService';
import apiService from './services/apiService';
import cryptoService from './services/cryptoService';
import AuthPage from './components/AuthPage';
import { useBreakpoint } from './hooks/useBreakpoint';
import type{ 
  User, 
  Session, 
  BB84Progress, 
  SecureMessage, 
  AppState,
  QBERDataPoint,
  SecurityViolation
} from './types';

const App: React.FC = () => {
  const [authToken, setAuthToken] = useState<string | null>(() => {
    try {
      return typeof window !== 'undefined' ? localStorage.getItem('auth_token') : null;
    } catch { return null; }
  });
  const [state, setState] = useState<AppState>({
    currentUser: null,
    currentSession: null,
    sessionKey: null,
    bb84Progress: null,
    cryptoInfo: null,
    isConnected: false,
    serverOnline: false,
    messages: [],
    eveDetected: false,
    qberHistory: [],
    securityViolations: [],
    fileTransfers: []
  });

  const [showSecurityDashboard, setShowSecurityDashboard] = useState(false);
  const [notifications, setNotifications] = useState<Array<{
    id: string;
    type: 'info' | 'warning' | 'error' | 'success';
    message: string;
    timestamp: Date;
  }>>([]);
  const [highContrast, setHighContrast] = useState(false);
  const [showQBERModal, setShowQBERModal] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const { isMobile, isTablet, isDesktop } = useBreakpoint();
  const isNarrowScreen = !isDesktop;

  useEffect(() => {
    if (!isNarrowScreen) {
      setMobileMenuOpen(false);
    }
  }, [isNarrowScreen]);

  // Initialize app on mount
  useEffect(() => {
    initializeApp();
    return () => {
      cleanup();
    };
  }, []);

  // Track auth token changes
  useEffect(() => {
    try {
      const t = typeof window !== 'undefined' ? localStorage.getItem('auth_token') : null;
      setAuthToken(t);
    } catch {}
  }, []);

  // Auto-refresh server health
  useEffect(() => {
    const healthCheckInterval = setInterval(async () => {
      const serverOnline = await apiService.checkServerHealth();
      setState(prev => ({ ...prev, serverOnline }));
    }, 30000); // Check every 30 seconds

    return () => clearInterval(healthCheckInterval);
  }, []);

  useEffect(() => {
    document.body.classList.toggle('high-contrast', highContrast);
  }, [highContrast]);

  const formatSessionId = useCallback((value?: string) => {
    if (!value) return '—';
    const compact = value.replace(/[^a-zA-Z0-9]/g, '').slice(0, 12).toUpperCase();
    return compact.replace(/(.{4})/g, '$1-').replace(/-$/, '');
  }, []);

  // Periodically refresh crypto info while a session is active
  useEffect(() => {
    if (!state.currentSession) return;

    let cancelled = false;

    const refresh = async () => {
      try {
        const info = await apiService.getSessionSecurity(state.currentSession!.session_id);
        if (!cancelled) {
          cryptoService.updateCryptoInfo(info);
          setState(prev => ({ ...prev, cryptoInfo: info }));
        }
      } catch {
        // ignore periodic errors
      }
    };

    // immediate refresh and then every 5s
    refresh();
    const id = setInterval(refresh, 5000);
    return () => { cancelled = true; clearInterval(id); };
  }, [state.currentSession]);

  const initializeApp = async () => {
    try {
      // Check server health first
      const serverOnline = await apiService.checkServerHealth();
      setState(prev => ({ ...prev, serverOnline }));

      if (serverOnline) {
        await setupSocketConnection();
        addNotification('success', 'Connected to BB84 QKD server');
      } else {
        addNotification('error', 'Server is offline. Please check backend connection.');
      }
    } catch (error) {
      console.error('Failed to initialize app:', error);
      addNotification('error', 'Failed to initialize application');
    }
  };

  const handleLogout = () => {
    apiService.removeAuthToken();
    setAuthToken(null);
    addNotification('info', 'Logged out');
  };

  const setupSocketConnection = async () => {
    socketService.connect();
    
    // Connection events
    socketService.on('connect', () => {
      setState(prev => ({ ...prev, isConnected: true }));
      addNotification('success', 'Real-time connection established');
    });

    socketService.on('disconnect', (reason: string) => {
      setState(prev => ({ ...prev, isConnected: false }));
      addNotification('warning', `Connection lost: ${reason}`);
    });

    // BB84 events with enhanced crypto support
    socketService.onBB84Started(({ n_bits, hybrid_mode }) => {
      addNotification('info', `BB84 started: ${n_bits} qubits${hybrid_mode ? ' (Hybrid mode)' : ''}`);
    });

    socketService.onBB84Progress((progress: BB84Progress) => {
      setState(prev => ({ ...prev, bb84Progress: progress }));
      
      // Update QBER history
      if (progress.qber !== undefined) {
        const qberPoint: QBERDataPoint = {
          timestamp: Date.now(),
          qber: progress.qber,
          threshold: progress.threshold || 0.11,
          stage: progress.stage
        };
        cryptoService.addQBERDataPoint(qberPoint);
        setState(prev => ({ 
          ...prev, 
          qberHistory: [...prev.qberHistory, qberPoint].slice(-100) 
        }));
      }
      
      if (progress.qber_exceeded) {
        setState(prev => ({ ...prev, eveDetected: true }));
        addNotification('error', 'Eavesdropping detected via QBER analysis!');
        setShowQBERModal(true);
      }
    });

    socketService.onBB84Complete(async (result) => {
      if (result.success) {
        // Update crypto info first
        if (result.crypto_info) {
          cryptoService.updateCryptoInfo(result.crypto_info);
          setState(prev => ({ ...prev, cryptoInfo: result.crypto_info }));
        }
        
        // Fetch the real session key from the backend with improved timing
        if (state.currentSession) {
          console.log('BB84 completed successfully, starting automatic key retrieval...');
          
          // Wait a bit for the backend to be ready, then fetch the key
          setTimeout(async () => {
            try {
              console.log('Attempting to fetch session key after BB84 completion...');
              if (state.currentSession) {
                await fetchSessionKey(state.currentSession.session_id, result.hybrid_mode);
              }
              
              // Verify the key was retrieved successfully
              const verifyKey = cryptoService.getSessionKey();
              if (verifyKey && verifyKey.length === 32) {
                console.log('Session key automatically retrieved successfully!');
                addNotification('success', 'Session key ready for encryption');
              } else {
                console.log('Session key not ready, scheduling multiple retries...');
                // Try multiple retries with increasing delays
                const retryDelays = [1000, 2000, 3000]; // 1s, 2s, 3s
                let retryCount = 0;
                
                const attemptRetry = async () => {
                  if (retryCount >= retryDelays.length) {
                    console.error('All automatic retries failed');
                    addNotification('warning', 'Session key retrieval failed. Please use "Retry Key Retrieval" button.');
                    return;
                  }
                  
                  const delay = retryDelays[retryCount];
                  retryCount++;
                  
                  console.log(`Retrying session key retrieval (attempt ${retryCount}/${retryDelays.length}) in ${delay}ms...`);
                  
                  setTimeout(async () => {
                    try {
                      if (state.currentSession) {
                        await fetchSessionKey(state.currentSession.session_id, result.hybrid_mode);
                      }
                      
                      // Check if it worked
                      const verifyKey = cryptoService.getSessionKey();
                      if (verifyKey && verifyKey.length === 32) {
                        console.log('Session key retrieved on retry attempt!');
                        addNotification('success', 'Session key ready for encryption');
                      } else {
                        // Try next retry
                        attemptRetry();
                      }
                    } catch (retryError) {
                      console.error(`Retry attempt ${retryCount} failed:`, retryError);
                      // Try next retry
                      attemptRetry();
                    }
                  }, delay);
                };
                
                attemptRetry();
              }
            } catch (error) {
              console.error('Failed to fetch session key after BB84 completion:', error);
              addNotification('warning', 'Session key retrieval failed. Please use "Retry Key Retrieval" button.');
            }
          }, 1000); // Wait 1 second for backend to be ready
        }
        
        addNotification('success', `Secure session established${result.hybrid_mode ? ' with hybrid security' : ''}`);
      } else {
        addNotification('error', 'BB84 key generation failed');
      }
      
      setState(prev => ({ 
        ...prev, 
        bb84Progress: { ...result, stage: 'complete', progress: 1.0 }
      }));
    });

    socketService.onBB84Error(({ error }) => {
      addNotification('error', `BB84 error: ${error}`);
    });

    // Enhanced message events
    socketService.onEncryptedMessageReceived((message) => {
      // Avoid duplicates by message_id and content
      setState(prev => {
        const exists = prev.messages.some(m => 
          m.message_id === message.message_id || 
          (m.message_type === 'chat_otp' && 
           m.sender_id === message.sender_id && 
           Math.abs(new Date(m.timestamp).getTime() - new Date(message.timestamp).getTime()) < 5000) // Within 5 seconds
        );
        if (exists) {
          console.log('Duplicate message detected, skipping:', message.message_id);
          return prev;
        }

        const secureMessage: SecureMessage = {
          message_id: message.message_id,
          sender_id: message.sender_id,
          message_type: 'chat_otp',
          encrypted_payload: message.encrypted_payload,
          timestamp: message.timestamp,
          seq_no: message.seq_no,
          verified: true,
          size_bytes: 0
        };

        return { ...prev, messages: [...prev.messages, secureMessage].slice(-100) };
      });
    });

    socketService.onMessageDecrypted(({ message_id, decrypted_content }) => {
      setState(prev => ({
        ...prev,
        messages: prev.messages.map(msg => 
          msg.message_id === message_id 
            ? { ...msg, decrypted_content }
            : msg
        )
      }));
      
      // Cache decrypted content
      cryptoService.cacheDecryptedContent(message_id, decrypted_content);
    });

    // File transfer events
    socketService.onEncryptedFileReceived((fileInfo) => {
      // Avoid duplicates by message_id and content
      setState(prev => {
        const exists = prev.messages.some(m => 
          m.message_id === fileInfo.message_id || 
          (m.message_type === 'file_xchacha20' && 
           m.sender_id === fileInfo.sender_id && 
           (m.encrypted_payload as any)?.filename === fileInfo.filename &&
           Math.abs(new Date(m.timestamp).getTime() - new Date(fileInfo.timestamp).getTime()) < 5000) // Within 5 seconds
        );
        if (exists) {
          console.log('Duplicate file message detected, skipping:', fileInfo.message_id);
          return prev;
        }

        // Create a file message for the chat
        const fileMessage: SecureMessage = {
          message_id: fileInfo.message_id,
          sender_id: fileInfo.sender_id,
          message_type: 'file_xchacha20',
          encrypted_payload: {
            ciphertext: '', // Will be filled by server
            nonce: '',
            aad: '',
            filename: fileInfo.filename,
            file_seq_no: 0,
            session_id: state.currentSession?.session_id || '',
            crypto_type: 'xchacha20_poly1305',
            file_size: fileInfo.file_size
          },
          timestamp: fileInfo.timestamp,
          verified: true,
          size_bytes: fileInfo.file_size
        };

        return {
          ...prev,
          messages: [...prev.messages, fileMessage].slice(-100),
          fileTransfers: [...prev.fileTransfers, {
            message_id: fileInfo.message_id,
            filename: fileInfo.filename,
            file_size: fileInfo.file_size,
            sender_id: fileInfo.sender_id,
            timestamp: fileInfo.timestamp,
            encrypted: true,
            download_ready: true
          }]
        };
      });
      
      addNotification('info', `Encrypted file received: ${fileInfo.filename}`);
    });

    // Eve events
    socketService.onEveStatusUpdate(({ attack_type }) => {
      addNotification('warning', `Eve attack updated: ${attack_type}`);
    });

    socketService.onEveDetected(({ qber, threshold }) => {
      setState(prev => ({ ...prev, eveDetected: true }));
      addNotification('error', `Eve detected! QBER: ${(qber * 100).toFixed(2)}% (Threshold: ${(threshold * 100).toFixed(1)}%)`);
    });

    // User events
    socketService.onUserJoined((user) => {
      addNotification('info', `${user.role.charAt(0).toUpperCase() + user.role.slice(1)} joined the session`);
    });

    socketService.onUserDisconnected((user) => {
      addNotification('warning', `${user.role.charAt(0).toUpperCase() + user.role.slice(1)} disconnected`);
    });

    // Session events
    socketService.onSessionTerminated(() => {
      addNotification('warning', 'Session terminated');
      handleSessionEnd();
    });

    // Security events
    socketService.onSecurityViolation((violation) => {
      const normalized: SecurityViolation = {
        timestamp: violation.timestamp,
        violation: violation.violation,
        severity: (violation.severity === 'low' || violation.severity === 'medium' || violation.severity === 'high' || violation.severity === 'critical')
          ? violation.severity
          : 'medium',
        session_id: violation.session_id ?? (state.currentSession?.session_id || '')
      };

      setState(prev => ({
        ...prev,
        securityViolations: [...prev.securityViolations, normalized]
      }));
      addNotification('error', `Security violation: ${normalized.violation}`);
    });

    // Error handling
    socketService.on('error', (error) => {
      console.error('Socket error:', error);
      const message = (error && (error.message || error.error || error.detail)) || 'Connection error occurred';
      addNotification('error', message);
    });
  };

  const addNotification = useCallback((type: 'info' | 'warning' | 'error' | 'success', message: string) => {
    const notification = {
      id: `${Date.now()}-${Math.random()}`,
      type,
      message,
      timestamp: new Date()
    };
    
    setNotifications(prev => [...prev, notification].slice(-10)); // Keep last 10
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== notification.id));
    }, 5000);
  }, []);

  const fetchSessionKey = useCallback(async (sessionId: string, hybridMode: boolean = false) => {
    try {
      console.log('Fetching session key for session:', sessionId);
      const keyResponse = await apiService.getSessionKey(sessionId);
      console.log('Key response:', keyResponse);
      
      if (keyResponse.key && keyResponse.key_length === 32) {
        console.log('Raw key string:', keyResponse.key);
        console.log('Key string length:', keyResponse.key.length);
        
        // Ensure the hex string is valid and has even length
        const cleanHex = keyResponse.key.replace(/[^0-9a-fA-F]/g, '');
        if (cleanHex.length !== 64) { // 32 bytes = 64 hex characters
          throw new Error(`Invalid hex string length: ${cleanHex.length} (expected 64)`);
        }
        
        let sessionKey = new Uint8Array(cleanHex.match(/.{2}/g)!.map(byte => parseInt(byte, 16)));
        console.log('Session key length:', sessionKey.length, 'bytes');
        console.log('Session key (first 8 bytes):', Array.from(sessionKey.slice(0, 8)));
        console.log('Session key (all bytes):', Array.from(sessionKey));
        
        if (sessionKey.length !== 32) {
          console.warn(`Key length is ${sessionKey.length} bytes, adjusting to 32 bytes`);
          // Pad or truncate to exactly 32 bytes
          const adjustedKey = new Uint8Array(32);
          if (sessionKey.length < 32) {
            // Pad with zeros
            adjustedKey.set(sessionKey, 0);
          } else {
            // Truncate to 32 bytes
            adjustedKey.set(sessionKey.slice(0, 32));
          }
          sessionKey = adjustedKey;
          console.log('Adjusted session key length:', sessionKey.length, 'bytes');
        }
        
        cryptoService.setSessionKey(sessionKey);
        setState(prev => ({ ...prev, sessionKey }));
        addNotification('success', `Session key retrieved successfully${hybridMode ? ' (Hybrid mode)' : ''}`);
        
        // Force a re-render to update the UI
        setTimeout(() => {
          setState(prev => ({ ...prev, sessionKey }));
        }, 100);
      } else {
        console.error('Invalid key response:', keyResponse);
        addNotification('error', 'Invalid session key received from server');
      }
    } catch (error) {
      console.error('Failed to fetch session key:', error);
      addNotification('error', 'Failed to retrieve session key');
    }
  }, [addNotification]);

  const handleSessionJoin = async (user: User, session: Session) => {
    try {
      setState(prev => ({ 
        ...prev, 
        currentUser: user, 
        currentSession: session,
        messages: [],
        eveDetected: false,
        qberHistory: []
      }));
      
      if (user.user_id && session.session_id) {
        socketService.joinSession(session.session_id, user.user_id);
      }

      // Get initial session security info
      try {
        const cryptoInfo = await apiService.getSessionSecurity(session.session_id);
        cryptoService.updateCryptoInfo(cryptoInfo);
        setState(prev => ({ ...prev, cryptoInfo }));
      } catch (error) {
        console.warn('Could not fetch initial crypto info:', error);
      }

      addNotification('success', `Joined session as ${user.role.charAt(0).toUpperCase() + user.role.slice(1)}`);
    } catch (error) {
      console.error('Error joining session:', error);
      addNotification('error', 'Failed to join session');
    }
  };

  const handleSessionEnd = () => {
    setState(prev => ({
      ...prev,
      currentUser: null,
      currentSession: null,
      sessionKey: null,
      bb84Progress: null,
      cryptoInfo: null,
      messages: [],
      eveDetected: false,
      qberHistory: [],
      fileTransfers: []
    }));
    
    cryptoService.clear();
    addNotification('info', 'Session ended - all data cleared');
  };

  const handleStartBB84 = async (useHybrid: boolean = false) => {
    if (!state.currentSession) return;

    try {
      await apiService.startBB84Simulation(
        state.currentSession.session_id, 
        1000, 
        0.1, 
        useHybrid
      );
      
      setState(prev => ({ 
        ...prev, 
        sessionKey: null, 
        bb84Progress: null, 
        eveDetected: false,
        qberHistory: []
      }));
      
      addNotification('info', `BB84 key generation started${useHybrid ? ' with hybrid mode' : ''}`);
    } catch (error) {
      const errorMsg = apiService.handleApiError(error);
      addNotification('error', `Error starting BB84: ${errorMsg}`);
    }
  };

  const handleRetrySessionKey = async () => {
    if (!state.currentSession) return;
    
    addNotification('info', 'Retrying session key retrieval...');
    try {
      await fetchSessionKey(state.currentSession.session_id, false);
      
      // Verify the key was retrieved
      const verifyKey = cryptoService.getSessionKey();
      if (verifyKey && verifyKey.length === 32) {
        addNotification('success', 'Session key retrieved successfully!');
      } else {
        addNotification('error', 'Session key retrieval failed. Please try again.');
      }
    } catch (error) {
      console.error('Manual retry failed:', error);
      addNotification('error', 'Session key retrieval failed. Please check console for details.');
    }
  };

  const handleSendMessage = async (content: string) => {
    if (!state.currentUser || !state.currentSession || !state.sessionKey) return;

    try {
      // Create local message for immediate display
      const localMessage: SecureMessage = {
        message_id: `local_${Date.now()}`,
        sender_id: state.currentUser.user_id,
        message_type: 'chat_otp',
        encrypted_payload: {
          ciphertext: '[Encrypting...]',
          hmac_tag: '',
          seq_no: 0,
          timestamp: Date.now(),
          session_id: state.currentSession.session_id,
          crypto_type: 'otp_hmac_sha3'
        },
        timestamp: new Date().toISOString(),
        verified: false,
        size_bytes: content.length,
        decrypted_content: content
      };

      setState(prev => ({
        ...prev,
        messages: [...prev.messages, localMessage]
      }));

      // Send via socket for server-side encryption
      socketService.sendEncryptedMessage(
        state.currentSession.session_id,
        state.currentUser.user_id,
        content
      );
    } catch (error) {
      console.error('Error sending message:', error);
      addNotification('error', 'Failed to send message');
    }
  };

  const handleFileUpload = async (file: File) => {
    if (!state.currentUser || !state.currentSession || !state.sessionKey) return;

    try {
      const result = await apiService.sendEncryptedFile(
        state.currentSession.session_id,
        state.currentUser.user_id,
        file
      );
      
      // Don't create local message - let the socket event handle it
      // This prevents duplicate messages with the same ID
      
      // Refresh crypto stats after uploading a file
      try {
        const info = await apiService.getSessionSecurity(state.currentSession.session_id);
        cryptoService.updateCryptoInfo(info);
        setState(prev => ({ ...prev, cryptoInfo: info }));
      } catch {}

      addNotification('success', `File encrypted and sent: ${result.filename}`);
    } catch (error) {
      const errorMsg = apiService.handleApiError(error);
      addNotification('error', `File upload failed: ${errorMsg}`);
    }
  };

  const handleFileDownload = async (messageId: string, encrypted: boolean) => {
    if (!state.currentSession || !state.currentUser) return;

    try {
      let result;
      if (encrypted) {
        // Download raw encrypted file
        result = await apiService.downloadRawEncryptedFile(
          state.currentSession.session_id,
          messageId,
          state.currentUser.user_id
        );
      } else {
        // Download decrypted file
        result = await apiService.downloadEncryptedFile(
          state.currentSession.session_id,
          messageId,
          state.currentUser.user_id
        );
      }
      
      // Create download link
      const blob = new Blob([Uint8Array.from(atob(result.file_data), c => c.charCodeAt(0))]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = result.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      const fileType = encrypted ? 'encrypted file' : 'decrypted file';
      addNotification('success', `${fileType} downloaded: ${result.filename}`);
    } catch (error) {
      const errorMsg = apiService.handleApiError(error);
      addNotification('error', `File download failed: ${errorMsg}`);
    }
  };

  const handleDecryptMessage = (messageId: string) => {
    if (!state.currentSession || !state.currentUser) return;

    // Ensure message exists and is received & encrypted
    const target = state.messages.find(m => m.message_id === messageId);
    if (!target) return;
    const isReceived = target.sender_id !== state.currentUser?.user_id && target.message_type === 'chat_otp';
    if (!isReceived) return;

    // Check cache first
    const cached = cryptoService.getCachedDecryptedContent(messageId);
    if (cached) {
      setState(prev => ({
        ...prev,
        messages: prev.messages.map(msg => 
          msg.message_id === messageId 
            ? { ...msg, decrypted_content: cached }
            : msg
        )
      }));
      return;
    }

    // Request decryption from server
    socketService.requestMessageDecryption(
      state.currentSession.session_id,
      messageId,
      state.currentUser.user_id
    );
  };

  const cleanup = () => {
    socketService.cleanup();
    cryptoService.clear();
  };

  const renderHeader = () => {
    const hasActiveSession = Boolean(state.currentSession && state.currentUser);

    return (
      <header className="mb-6 space-y-4">
        <div className="glass-card glow-border flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-3">
            {hasActiveSession && (
              <button
                type="button"
                className="copy-button lg:hidden"
                aria-label="Toggle session panel"
                onClick={() => setMobileMenuOpen(prev => !prev)}
              >
                {mobileMenuOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
              </button>
            )}
            <Shield className="hidden sm:block w-10 h-10 text-[var(--info)]" />
            <div>
              <p className="text-xs uppercase tracking-[0.4em] text-[var(--text-muted)]">BB84 QKD Simulator</p>
              <h1 className="font-semibold text-[var(--text-primary)]" style={{ fontSize: 'var(--font-hero)', lineHeight: 1.2 }}>
                Quantum Lab Control
              </h1>
              <p className="text-sm text-[var(--text-secondary)] hidden md:block">Monitor quantum key exchanges with complete clarity</p>
            </div>
          </div>
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-end">
            <div className="flex items-center gap-3 text-sm text-[var(--text-secondary)]">
              {getConnectionStatusIcon()}
              <span>{getConnectionStatusText()}</span>
              <span className={`px-3 py-1 rounded-full text-xs font-medium ${state.serverOnline ? 'text-[var(--success)]' : 'text-[var(--eve)]'}`}>
                {state.serverOnline ? 'Server Online' : 'Server Offline'}
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-2 justify-end">
              {state.currentSession && (
                <div className="hidden md:flex items-center gap-2 font-mono text-sm text-[var(--text-secondary)]">
                  <span className="uppercase text-[var(--text-muted)] text-xs tracking-wide">Session</span>
                  <span>{formatSessionId(state.currentSession.session_id)}</span>
                </div>
              )}
              <ThemeToggle compact={isNarrowScreen} />
              <button
                type="button"
                onClick={() => setHighContrast(prev => !prev)}
                className={`copy-button ${highContrast ? 'text-[var(--success)]' : ''}`}
              >
                {highContrast ? 'Contrast: High' : 'Contrast'}
              </button>
              {authToken && (
                <button
                  onClick={handleLogout}
                  className="copy-button"
                >
                  Logout
                </button>
              )}
            </div>
          </div>
        </div>
        {mobileMenuOpen && hasActiveSession && (
          <div className="glass-card glow-border lg:hidden">
            <SessionControlPanel
              session={state.currentSession}
              user={state.currentUser}
              isConnected={state.isConnected}
              serverOnline={state.serverOnline}
              eveDetected={state.eveDetected}
              sessionKeyReady={!!state.sessionKey}
              highContrast={highContrast}
              onToggleHighContrast={() => setHighContrast(prev => !prev)}
            />
          </div>
        )}
      </header>
    );
  };

  const resolveMessageType = (senderId: string, currentUserId?: string | null): 'system' | 'sent' | 'received' => {
    if (senderId === 'system') return 'system';
    return senderId === currentUserId ? 'sent' : 'received';
  };

  const buildChatMessages = (currentUserId: string | null) => state.messages.map(m => ({
    message_id: m.message_id,
    sender_id: m.sender_id,
    content: m.decrypted_content ?? (m.message_type === 'system' ? (m.encrypted_payload as any)?.content : undefined),
    encrypted_content: m.message_type === 'chat_otp' ? (m.encrypted_payload as any)?.ciphertext : undefined,
    timestamp: m.timestamp,
    type: resolveMessageType(m.sender_id, currentUserId),
    file_info: m.message_type === 'file_xchacha20' ? {
      filename: (m.encrypted_payload as any)?.filename || 'Unknown file',
      file_size: (m.encrypted_payload as any)?.file_size || 0,
      encrypted: true,
      download_ready: true
    } : undefined
  }));

  const renderSecurityInsights = (options?: { stacked?: boolean }) => {
    const stacked = options?.stacked ?? false;
    return (
      <div className="space-y-4">
        <div className={`flex ${stacked ? 'justify-start' : 'justify-end'}`}>
          <button
            onClick={() => setShowSecurityDashboard(prev => !prev)}
            className={`copy-button ${stacked ? 'w-full text-center' : ''}`}
          >
            {showSecurityDashboard ? 'Hide Security Dashboard' : 'Show Security Dashboard'}
          </button>
        </div>
        {showSecurityDashboard && (
          <div className="glass-card glow-border">
            <SecurityDashboard
              cryptoInfo={state.cryptoInfo}
              qberHistory={state.qberHistory}
              securityViolations={state.securityViolations}
              sessionHealth={cryptoService.getSessionHealthAssessment()}
            />
          </div>
        )}
        <div className={`grid gap-6 ${stacked ? '' : 'lg:grid-cols-2'}`}>
          <CryptoMonitor
            cryptoInfo={state.cryptoInfo}
            encryptionStatus={cryptoService.getEncryptionStatus()}
            securityRecommendations={cryptoService.getSecurityRecommendations()}
          />
          <div className="glass-card glow-border space-y-3 text-sm text-[var(--text-secondary)]">
            <p className="metric-label">Session Metrics</p>
            <div className="grid grid-cols-2 gap-4 text-[var(--text-primary)]">
              <div>
                <p className="text-xs uppercase tracking-widest text-[var(--text-muted)]">Secure Messages</p>
                <p className="text-2xl font-semibold">{state.messages.filter(m => m.message_type === 'chat_otp').length}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-widest text-[var(--text-muted)]">Violations</p>
                <p className="text-2xl font-semibold">{state.securityViolations.length}</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };

  const renderDesktopLayout = (
    messages: ReturnType<typeof buildChatMessages>,
    currentUser: User,
    currentSession: Session
  ) => (
    <div className="space-y-8">
      <div className="hidden lg:block">
        <SessionControlPanel
          session={currentSession}
          user={currentUser}
          isConnected={state.isConnected}
          serverOnline={state.serverOnline}
          eveDetected={state.eveDetected}
          sessionKeyReady={!!state.sessionKey}
          highContrast={highContrast}
          onToggleHighContrast={() => setHighContrast(prev => !prev)}
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-1 xl:grid-cols-[1.8fr,1fr] items-start">
        <BB84Simulator
          progress={state.bb84Progress}
          sessionKey={state.sessionKey}
          onStartBB84={handleStartBB84}
          onRetrySessionKey={handleRetrySessionKey}
          userRole={currentUser.role}
          eveDetected={state.eveDetected}
          cryptoInfo={state.cryptoInfo}
          qberHistory={state.qberHistory}
        />
        <KeyStatusPanel
          sessionKey={state.sessionKey}
          progress={state.bb84Progress}
          eveDetected={state.eveDetected}
          cryptoInfo={state.cryptoInfo}
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.4fr,0.9fr,0.9fr]">
        <div className="xl:col-span-1">
          <ChatInterface
            messages={messages}
            onSendMessage={handleSendMessage}
            onDecryptMessage={handleDecryptMessage}
            onFileUpload={handleFileUpload}
            onFileDownload={handleFileDownload}
            currentUser={currentUser}
            sessionKey={state.sessionKey}
            sessionId={currentSession.session_id}
            disabled={!state.sessionKey || state.eveDetected}
            autoScroll={false}
          />
        </div>

        <div>
          <FileTransferModule
            transfers={state.fileTransfers}
            disabled={!state.sessionKey || state.eveDetected}
            onUpload={handleFileUpload}
            onDownload={handleFileDownload}
          />
        </div>

        {currentUser.role === 'eve' && (
          <EveControlPanel
            sessionId={currentSession.session_id}
            onEveParamsChange={(params) => {
              socketService.updateEveParams(currentSession.session_id, params);
            }}
          />
        )}
      </div>

      {renderSecurityInsights()}
    </div>
  );

  const renderTabletLayout = (
    messages: ReturnType<typeof buildChatMessages>,
    currentUser: User,
    currentSession: Session
  ) => (
    <div className="space-y-6">
      <div className="block lg:hidden">
        <SessionControlPanel
          session={currentSession}
          user={currentUser}
          isConnected={state.isConnected}
          serverOnline={state.serverOnline}
          eveDetected={state.eveDetected}
          sessionKeyReady={!!state.sessionKey}
          highContrast={highContrast}
          onToggleHighContrast={() => setHighContrast(prev => !prev)}
        />
      </div>

      <div className="grid gap-6 md:grid-cols-2 items-start">
        <BB84Simulator
          progress={state.bb84Progress}
          sessionKey={state.sessionKey}
          onStartBB84={handleStartBB84}
          onRetrySessionKey={handleRetrySessionKey}
          userRole={currentUser.role}
          eveDetected={state.eveDetected}
          cryptoInfo={state.cryptoInfo}
          qberHistory={state.qberHistory}
        />
        <KeyStatusPanel
          sessionKey={state.sessionKey}
          progress={state.bb84Progress}
          eveDetected={state.eveDetected}
          cryptoInfo={state.cryptoInfo}
        />
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <ChatInterface
          messages={messages}
          onSendMessage={handleSendMessage}
          onDecryptMessage={handleDecryptMessage}
          onFileUpload={handleFileUpload}
          onFileDownload={handleFileDownload}
          currentUser={currentUser}
          sessionKey={state.sessionKey}
            sessionId={currentSession.session_id}
          disabled={!state.sessionKey || state.eveDetected}
          autoScroll={false}
        />
        <FileTransferModule
          transfers={state.fileTransfers}
          disabled={!state.sessionKey || state.eveDetected}
          onUpload={handleFileUpload}
          onDownload={handleFileDownload}
        />
      </div>

      {currentUser.role === 'eve' && (
        <EveControlPanel
          sessionId={currentSession.session_id}
          onEveParamsChange={(params) => {
            socketService.updateEveParams(currentSession.session_id, params);
          }}
        />
      )}

      {renderSecurityInsights({ stacked: true })}
    </div>
  );

  const renderMobileLayout = (
    messages: ReturnType<typeof buildChatMessages>,
    currentUser: User,
    currentSession: Session
  ) => (
    <div className="space-y-4">
      <CollapsibleSection title="Session Overview" defaultOpen>
        <SessionControlPanel
          session={currentSession}
          user={currentUser}
          isConnected={state.isConnected}
          serverOnline={state.serverOnline}
          eveDetected={state.eveDetected}
          sessionKeyReady={!!state.sessionKey}
          highContrast={highContrast}
          onToggleHighContrast={() => setHighContrast(prev => !prev)}
        />
      </CollapsibleSection>

      <CollapsibleSection title="Key Status" subtitle="Live quantum key generation" defaultOpen>
        <KeyStatusPanel
          sessionKey={state.sessionKey}
          progress={state.bb84Progress}
          eveDetected={state.eveDetected}
          cryptoInfo={state.cryptoInfo}
        />
      </CollapsibleSection>

      <CollapsibleSection title="BB84 Process" subtitle="Tap to view detailed visualization">
        <BB84Simulator
          progress={state.bb84Progress}
          sessionKey={state.sessionKey}
          onStartBB84={handleStartBB84}
          onRetrySessionKey={handleRetrySessionKey}
          userRole={currentUser.role}
          eveDetected={state.eveDetected}
          cryptoInfo={state.cryptoInfo}
          qberHistory={state.qberHistory}
        />
      </CollapsibleSection>

      <CollapsibleSection title="Secure Chat" defaultOpen>
        <ChatInterface
          messages={messages}
          onSendMessage={handleSendMessage}
          onDecryptMessage={handleDecryptMessage}
          onFileUpload={handleFileUpload}
          onFileDownload={handleFileDownload}
          currentUser={currentUser}
          sessionKey={state.sessionKey}
          sessionId={currentSession.session_id}
          disabled={!state.sessionKey || state.eveDetected}
          autoScroll={false}
        />
      </CollapsibleSection>

      <CollapsibleSection title="File Transfer">
        <FileTransferModule
          transfers={state.fileTransfers}
          disabled={!state.sessionKey || state.eveDetected}
          onUpload={handleFileUpload}
          onDownload={handleFileDownload}
        />
      </CollapsibleSection>

      {currentUser.role === 'eve' && (
        <CollapsibleSection title="Eve Control Panel">
          <EveControlPanel
            sessionId={currentSession.session_id}
            onEveParamsChange={(params) => {
              socketService.updateEveParams(currentSession.session_id, params);
            }}
          />
        </CollapsibleSection>
      )}

      <CollapsibleSection title="Security Insights">
        {renderSecurityInsights({ stacked: true })}
      </CollapsibleSection>
    </div>
  );

  const renderMainInterface = () => {
    const currentUser = state.currentUser;
    const currentSession = state.currentSession;

    if (!currentUser || !currentSession) {
      return (
        <div className="glass-card glow-border">
          <SessionManager 
            onSessionJoin={handleSessionJoin} 
            serverOnline={state.serverOnline} 
          />
        </div>
      );
    }

    const messages = buildChatMessages(currentUser.user_id);

    if (isMobile) {
      return renderMobileLayout(messages, currentUser, currentSession);
    }

    if (isTablet) {
      return renderTabletLayout(messages, currentUser, currentSession);
    }

    return renderDesktopLayout(messages, currentUser, currentSession);
  };

  const getConnectionStatusIcon = () => {
    if (!state.serverOnline) return <WifiOff className="w-5 h-5 text-red-500" />;
    if (!state.isConnected) return <AlertTriangle className="w-5 h-5 text-yellow-500" />;
    return <Wifi className="w-5 h-5 text-green-500" />;
  };

  const getConnectionStatusText = () => {
    if (!state.serverOnline) return 'Server Offline';
    if (!state.isConnected) return 'Disconnected';
    return 'Connected';
  };

  return (
    <div className="quantum-lab">
      <div className="quantum-particles">
        {Array.from({ length: 28 }).map((_, idx) => (
          <span key={`particle-${idx}`} style={{ left: `${Math.random() * 100}%`, animationDelay: `${idx * 0.4}s` }} />
        ))}
      </div>
      {!authToken && (
        <AuthPage onSuccess={() => {
          const token = typeof window !== 'undefined' ? localStorage.getItem('auth_token') : null;
          setAuthToken(token);
        }} />
      )}
      {authToken && (
        <div className={`quantum-content ${highContrast ? 'high-contrast' : ''}`}>
          {renderHeader()}
          {renderMainInterface()}
        </div>
      )}

      <div className="fixed top-6 right-6 z-50 space-y-3">
        {notifications.map((notification) => (
          <div
            key={notification.id}
            className="glass-card glow-border min-w-[260px]"
          >
            <div className="flex items-start gap-3">
              <div className="text-sm font-semibold text-[var(--text-primary)]">{notification.message}</div>
              <button
                onClick={() => setNotifications(prev => prev.filter(n => n.id !== notification.id))}
                className="text-[var(--text-muted)] hover:text-[var(--text-primary)]"
              >
                ×
              </button>
            </div>
            <p className="text-[11px] text-[var(--text-muted)] mt-2">{notification.timestamp.toLocaleTimeString()}</p>
          </div>
        ))}
      </div>

      {showQBERModal && state.bb84Progress?.qber !== undefined && (
        <QBERAlertModal
          qber={state.bb84Progress.qber}
          threshold={state.bb84Progress.threshold ?? 0.11}
          onViewDetails={() => {
            setShowSecurityDashboard(true);
            setShowQBERModal(false);
          }}
          onAbort={() => {
            handleSessionEnd();
            setShowQBERModal(false);
          }}
          onClose={() => setShowQBERModal(false)}
        />
      )}
    </div>
  );
};

export default App;


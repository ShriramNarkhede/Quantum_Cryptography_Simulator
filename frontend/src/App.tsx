import React, { useState, useEffect } from 'react';
import { Shield, Wifi, WifiOff } from 'lucide-react';
import SessionManager from './components/SessionManager';
import BB84Simulator from './components/BB84Simulator';
import ChatInterface from './components/ChatInterface';
import EveControlPanel from './components/EveControlPanel';
import StatusBar from './components/StatusBar';
import socketService from './services/socketService';
import apiService from './services/apiService';
import type { User, Session, BB84Progress } from './types';

interface AppState {
  currentUser: User | null;
  currentSession: Session | null;
  sessionKey: Uint8Array | null;
  bb84Progress: BB84Progress | null;
  isConnected: boolean;
  serverOnline: boolean;
}

const App: React.FC = () => {
  const [state, setState] = useState<AppState>({
    currentUser: null,
    currentSession: null,
    sessionKey: null,
    bb84Progress: null,
    isConnected: false,
    serverOnline: false,
  });

  const [messages, setMessages] = useState<any[]>([]);
  const [eveDetected, setEveDetected] = useState(false);

  // Initialize app
  useEffect(() => {
    initializeApp();
    return () => {
      socketService.disconnect();
    };
  }, []);

  const initializeApp = async () => {
    // Check server health
    const serverOnline = await apiService.checkServerHealth();
    setState(prev => ({ ...prev, serverOnline }));

    if (serverOnline) {
      // Connect to Socket.IO
      const socket = socketService.connect();
      
      socket.on('connect', () => {
        setState(prev => ({ ...prev, isConnected: true }));
      });

      socket.on('disconnect', () => {
        setState(prev => ({ ...prev, isConnected: false }));
      });

      // Set up BB84 progress listener
      socketService.onBB84Progress((progress: BB84Progress) => {
        setState(prev => ({ ...prev, bb84Progress: progress }));
        
        if (progress.qber_exceeded) {
          setEveDetected(true);
        }
      });

      // Set up BB84 completion listener
      socketService.onBB84Complete((result: any) => {
        if (result.success) {
          // Generate mock session key for demo (in real implementation, this would be derived securely)
          const mockKey = new Uint8Array(32);
          crypto.getRandomValues(mockKey);
          setState(prev => ({ ...prev, sessionKey: mockKey }));
        }
        setState(prev => ({ 
          ...prev, 
          bb84Progress: { ...result, stage: 'complete', progress: 1.0 }
        }));
      });

      // Set up Eve detection listener
      socketService.onEveDetected((data: any) => {
        setEveDetected(true);
        addSystemMessage(`🚨 Eve detected! QBER: ${data.qber.toFixed(3)}, Threshold: ${data.threshold}`);
      });

      // Set up message listener
      socketService.onEncryptedMessageReceived((message: any) => {
        setMessages(prev => [...prev, { ...message, type: 'received' }]);
      });

      // Set up user event listeners
      socketService.onUserJoined((user: any) => {
        addSystemMessage(`${user.role.charAt(0).toUpperCase() + user.role.slice(1)} joined the session`);
      });

      socketService.onUserDisconnected((user: any) => {
        addSystemMessage(`${user.role.charAt(0).toUpperCase() + user.role.slice(1)} disconnected`);
      });

      socketService.onSessionTerminated(() => {
        addSystemMessage('Session terminated');
        handleSessionEnd();
      });
    }
  };

  const addSystemMessage = (content: string) => {
    setMessages(prev => [...prev, {
      message_id: `system_${Date.now()}`,
      sender_id: 'system',
      content,
      timestamp: new Date().toISOString(),
      type: 'system'
    }]);
  };

  const handleSessionJoin = (user: User, session: Session) => {
    setState(prev => ({ ...prev, currentUser: user, currentSession: session }));
    
    if (user.user_id && session.session_id) {
      socketService.joinSession(session.session_id, user.user_id);
    }

    addSystemMessage(`Joined session as ${user.role.charAt(0).toUpperCase() + user.role.slice(1)}`);
    setMessages([]); // Clear previous messages
    setEveDetected(false);
  };

  const handleSessionEnd = () => {
    setState(prev => ({
      ...prev,
      currentUser: null,
      currentSession: null,
      sessionKey: null,
      bb84Progress: null
    }));
    setMessages([]);
    setEveDetected(false);
  };

  const handleStartBB84 = async () => {
    if (!state.currentSession) return;

    try {
      await apiService.startBB84Simulation(state.currentSession.session_id, 1000, 0.1);
      addSystemMessage('BB84 key generation started...');
      setEveDetected(false);
      setState(prev => ({ ...prev, sessionKey: null, bb84Progress: null }));
    } catch (error) {
      const errorMsg = apiService.handleApiError(error);
      addSystemMessage(`Error starting BB84: ${errorMsg}`);
    }
  };

  const handleSendMessage = (content: string) => {
    if (!state.currentUser || !state.currentSession || !state.sessionKey) return;

    // Simple XOR encryption for demo (in real implementation, use proper OTP)
    const encrypted = btoa(content); // Base64 encoding for demo
    
    const messageData = {
      message_id: `msg_${Date.now()}`,
      sender_id: state.currentUser.user_id,
      content,
      encrypted_content: encrypted,
      timestamp: new Date().toISOString(),
      type: 'sent'
    };

    setMessages(prev => [...prev, messageData]);
    socketService.sendEncryptedMessage(
      state.currentSession.session_id,
      state.currentUser.user_id,
      encrypted
    );
  };

  const renderMainInterface = () => {
    if (!state.currentUser || !state.currentSession) {
      return <SessionManager onSessionJoin={handleSessionJoin} serverOnline={state.serverOnline} />;
    }

    return (
      <div className="flex flex-col lg:flex-row gap-6 h-full">
        {/* Left Panel - BB84 Simulation */}
        <div className="flex-1 space-y-4">
          <BB84Simulator
            progress={state.bb84Progress}
            sessionKey={state.sessionKey}
            onStartBB84={handleStartBB84}
            userRole={state.currentUser.role}
            eveDetected={eveDetected}
          />
          
          {state.currentUser.role === 'eve' && (
            <EveControlPanel
              sessionId={state.currentSession.session_id}
              onEveParamsChange={(params) => {
                socketService.updateEveParams(state.currentSession!.session_id, params);
              }}
            />
          )}
        </div>

        {/* Right Panel - Chat */}
        <div className="lg:w-96">
          <ChatInterface
            messages={messages}
            onSendMessage={handleSendMessage}
            currentUser={state.currentUser}
            sessionKey={state.sessionKey}
            disabled={!state.sessionKey || eveDetected}
          />
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="w-8 h-8 text-quantum-600" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">Cryptex</h1>
                <p className="text-sm text-gray-500">Quantum Key Simulator </p>
              </div>
            </div>

            <div className="flex items-center space-x-4">
              {/* Connection Status */}
              <div className="flex items-center space-x-2">
                {state.isConnected ? (
                  <Wifi className="w-5 h-5 text-green-500" />
                ) : (
                  <WifiOff className="w-5 h-5 text-red-500" />
                )}
                <span className={`text-sm font-medium ${
                  state.isConnected ? 'text-green-600' : 'text-red-600'
                }`}>
                  {state.isConnected ? 'Connected' : 'Disconnected'}
                </span>
              </div>

              {/* Server Status */}
              <div className={`px-3 py-1 rounded-full text-sm font-medium ${
                state.serverOnline 
                  ? 'bg-green-100 text-green-800' 
                  : 'bg-red-100 text-red-800'
              }`}>
                Server {state.serverOnline ? 'Online' : 'Offline'}
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Status Bar */}
        <StatusBar
          currentUser={state.currentUser}
          currentSession={state.currentSession}
          bb84Progress={state.bb84Progress}
          eveDetected={eveDetected}
          hasSessionKey={!!state.sessionKey}
        />

        {/* Main Interface */}
        <div className="mt-6 bg-white rounded-lg shadow-sm p-6 min-h-[600px]">
          {renderMainInterface()}
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-white border-t mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <p className="text-center text-sm text-gray-500">
            BB84 QKD Simulation System - Educational Demo Only
          </p>
        </div>
      </footer>
    </div>
  );
};

export default App;
import React, { useState } from 'react';
import { Plus, LogIn, Users, AlertCircle, CheckCircle } from 'lucide-react';
import apiService from '../services/apiService';
import type { User, Session } from '../types';

interface SessionManagerProps {
  onSessionJoin: (user: User, session: Session) => void;
  serverOnline: boolean;
}

const SessionManager: React.FC<SessionManagerProps> = ({ onSessionJoin, serverOnline }) => {
  const [mode, setMode] = useState<'select' | 'create' | 'join'>('select');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  
  // Form states
  const [sessionId, setSessionId] = useState('');
  const [selectedRole, setSelectedRole] = useState<'alice' | 'bob' | 'eve'>('alice');

  const resetState = () => {
    setError(null);
    setSuccess(null);
    setLoading(false);
  };

  const handleCreateSession = async () => {
    if (!serverOnline) {
      setError('Server is offline. Please try again later.');
      return;
    }

    resetState();
    setLoading(true);

    try {
      // Create new session
      const sessionData = await apiService.createSession();
      setSuccess(`Session created! ID: ${sessionData.session_id}`);
      
      // Automatically join as Alice
      const userData = await apiService.joinSession(sessionData.session_id, 'alice');
      
      // Prepare session and user objects
      const session: Session = {
        session_id: sessionData.session_id,
        status: sessionData.status as Session['status'],
        created_at: sessionData.created_at,
        participants: []
      };

      const user: User = {
        user_id: userData.user_id,
        role: 'alice',
        connected: true,
        joined_at: new Date().toISOString(),
        last_activity: new Date().toISOString()
      };

      onSessionJoin(user, session);
    } catch (error) {
      setError(apiService.handleApiError(error));
    } finally {
      setLoading(false);
    }
  };

  const handleJoinSession = async () => {
    if (!serverOnline) {
      setError('Server is offline. Please try again later.');
      return;
    }

    if (!sessionId.trim()) {
      setError('Please enter a session ID');
      return;
    }

    resetState();
    setLoading(true);

    try {
      // First check if session exists
      const sessionStatus = await apiService.getSessionStatus(sessionId);
      const participants = sessionStatus.participants ?? [];
      
      // Check if role is already taken
      const existingRole = participants.find(p => p.role === selectedRole);
      if (existingRole) {
        setError(`Role ${selectedRole} is already taken in this session`);
        setLoading(false);
        return;
      }

      // Join session
      const userData = await apiService.joinSession(sessionId, selectedRole);
      
      // Prepare session and user objects
      const session: Session = {
        session_id: sessionStatus.session_id,
        status: sessionStatus.status as Session['status'],
        created_at: sessionStatus.created_at,
        participants: participants.map(p => ({
          user_id: p.user_id,
          role: p.role as 'alice' | 'bob' | 'eve',
          connected: p.connected,
          joined_at: new Date().toISOString(),
          last_activity: new Date().toISOString()
        }))
      };

      const user: User = {
        user_id: userData.user_id,
        role: selectedRole,
        connected: true,
        joined_at: new Date().toISOString(),
        last_activity: new Date().toISOString()
      };

      onSessionJoin(user, session);
    } catch (error) {
      setError(apiService.handleApiError(error));
    } finally {
      setLoading(false);
    }
  };

  if (!serverOnline) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Server Offline</h2>
          <p className="text-gray-600 mb-4">
            Cannot connect to the BB84 simulation server.
          </p>
          <p className="text-sm text-gray-500">
            Please ensure the backend server is running on localhost:8000
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto">
      <div className="text-center mb-8">
        <h2 className="text-3xl font-bold text-gray-900 mb-2">Welcome to Cryptex</h2>
        <p className="text-gray-600">
          Create a new quantum key distribution session or join an existing one
        </p>
      </div>

      {/* Mode Selection */}
      {mode === 'select' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Create Session Card */}
            <div 
              className="p-6 bg-gradient-to-br from-blue-50 to-indigo-50 rounded-lg border-2 border-transparent hover:border-blue-200 cursor-pointer transition-all"
              onClick={() => setMode('create')}
            >
              <div className="text-center">
                <Plus className="w-12 h-12 text-blue-600 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Create New Session</h3>
                <p className="text-gray-600 text-sm">
                  Start a new QKD session as Alice and wait for Bob to join
                </p>
              </div>
            </div>

            {/* Join Session Card */}
            <div 
              className="p-6 bg-gradient-to-br from-green-50 to-emerald-50 rounded-lg border-2 border-transparent hover:border-green-200 cursor-pointer transition-all"
              onClick={() => setMode('join')}
            >
              <div className="text-center">
                <LogIn className="w-12 h-12 text-green-600 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Join Existing Session</h3>
                <p className="text-gray-600 text-sm">
                  Join an existing session as Alice, Bob, or Eve
                </p>
              </div>
            </div>
          </div>

          {/* Server Status */}
          <div className="mt-8 p-4 bg-green-50 rounded-lg flex items-center">
            <CheckCircle className="w-5 h-5 text-green-600 mr-2" />
            <span className="text-green-800 text-sm">Server is online and ready</span>
          </div>
        </div>
      )}

      {/* Create Session Form */}
      {mode === 'create' && (
        <div className="bg-white p-6 rounded-lg border">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900">Create New Session</h3>
            <button
              onClick={() => setMode('select')}
              className="text-gray-500 hover:text-gray-700"
            >
              ← Back
            </button>
          </div>

          <div className="space-y-4">
            <div className="bg-blue-50 p-4 rounded-lg">
              <div className="flex items-center">
                <Users className="w-5 h-5 text-blue-600 mr-2" />
                <span className="font-medium text-blue-900">You will join as Alice</span>
              </div>
              <p className="text-blue-700 text-sm mt-1">
                Alice generates and sends qubits to Bob in the BB84 protocol
              </p>
            </div>

            {error && (
              <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
                <p className="text-red-800 text-sm">{error}</p>
              </div>
            )}

            {success && (
              <div className="p-3 bg-green-50 border border-green-200 rounded-lg">
                <p className="text-green-800 text-sm">{success}</p>
              </div>
            )}

            <button
              onClick={handleCreateSession}
              disabled={loading}
              className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {loading ? 'Creating Session...' : 'Create Session'}
            </button>
          </div>
        </div>
      )}

      {/* Join Session Form */}
      {mode === 'join' && (
        <div className="bg-white p-6 rounded-lg border">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900">Join Session</h3>
            <button
              onClick={() => setMode('select')}
              className="text-gray-500 hover:text-gray-700"
            >
              ← Back
            </button>
          </div>

          <div className="space-y-4">
            {/* Session ID Input */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Session ID
              </label>
              <input
                type="text"
                value={sessionId}
                onChange={(e) => setSessionId(e.target.value)}
                placeholder="Enter session ID (e.g., abc12345)"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>

            {/* Role Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Choose Your Role
              </label>
              <div className="grid grid-cols-3 gap-2">
                {/* Alice */}
                <div
                  className={`p-3 rounded-lg cursor-pointer border-2 transition-all ${
                    selectedRole === 'alice'
                      ? 'border-alice bg-green-50'
                      : 'border-gray-200 hover:border-green-300'
                  }`}
                  onClick={() => setSelectedRole('alice')}
                >
                  <div className="text-center">
                    <div className="text-sm font-medium text-gray-900">Alice</div>
                    <div className="text-xs text-gray-500">Sender</div>
                  </div>
                </div>

                {/* Bob */}
                <div
                  className={`p-3 rounded-lg cursor-pointer border-2 transition-all ${
                    selectedRole === 'bob'
                      ? 'border-bob bg-blue-50'
                      : 'border-gray-200 hover:border-blue-300'
                  }`}
                  onClick={() => setSelectedRole('bob')}
                >
                  <div className="text-center">
                    <div className="text-sm font-medium text-gray-900">Bob</div>
                    <div className="text-xs text-gray-500">Receiver</div>
                  </div>
                </div>

                {/* Eve */}
                <div
                  className={`p-3 rounded-lg cursor-pointer border-2 transition-all ${
                    selectedRole === 'eve'
                      ? 'border-eve bg-red-50'
                      : 'border-gray-200 hover:border-red-300'
                  }`}
                  onClick={() => setSelectedRole('eve')}
                >
                  <div className="text-center">
                    <div className="text-sm font-medium text-gray-900">Eve</div>
                    <div className="text-xs text-gray-500">Eavesdropper</div>
                  </div>
                </div>
              </div>
            </div>

            {error && (
              <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
                <p className="text-red-800 text-sm">{error}</p>
              </div>
            )}

            <button
              onClick={handleJoinSession}
              disabled={loading || !sessionId.trim()}
              className="w-full bg-green-600 text-white py-2 px-4 rounded-lg hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {loading ? 'Joining Session...' : 'Join Session'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default SessionManager;


import React, { useState } from 'react';
import apiService from '../services/apiService';

interface AuthPageProps {
  onSuccess?: () => void;
}

const AuthPage: React.FC<AuthPageProps> = ({ onSuccess }) => {
  const [mode, setMode] = useState<'login' | 'signup'>('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSubmit = () => {
    if (!username || !password) return false;
    if (mode === 'signup' && password !== confirm) return false;
    if (password.length < 6) return false;
    return true;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit()) return;
    setError(null);
    setLoading(true);
    try {
      if (mode === 'login') {
        await apiService.login(username.trim(), password);
      } else {
        await apiService.signup(username.trim(), password);
      }
      if (onSuccess) onSuccess();
    } catch (err: unknown) {
      setError(apiService.handleApiError(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-purple-50 flex items-center justify-center px-4">
      <div className="w-full max-w-md bg-white rounded-2xl shadow-lg p-6 sm:p-8 border border-gray-100">
        <div className="flex justify-center mb-6 space-x-2">
          <button
            className={`px-4 py-2 rounded-lg text-sm font-medium ${
              mode === 'login' ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
            onClick={() => setMode('login')}
            disabled={loading}
          >
            Login
          </button>
          <button
            className={`px-4 py-2 rounded-lg text-sm font-medium ${
              mode === 'signup' ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
            onClick={() => setMode('signup')}
            disabled={loading}
          >
            Sign Up
          </button>
        </div>

        <h2 className="text-xl font-semibold text-gray-900 text-center mb-1">
          {mode === 'login' ? 'Welcome back' : 'Create your account'}
        </h2>
        <p className="text-sm text-gray-500 text-center mb-6">
          {mode === 'login' ? 'Enter your credentials to continue' : 'It takes less than a minute'}
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full border rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="Enter username"
              required
              autoComplete="username"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full border rounded-lg px-3 py-2 pr-10 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Minimum 6 characters"
                required
                minLength={6}
                autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-xs text-gray-500 hover:text-gray-700"
                aria-label="Toggle password visibility"
              >
                {showPassword ? 'Hide' : 'Show'}
              </button>
            </div>
          </div>
          {mode === 'signup' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Confirm Password</label>
              <input
                type={showPassword ? 'text' : 'password'}
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                className="w-full border rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Re-enter password"
                required
                minLength={6}
                autoComplete="new-password"
              />
              {confirm && confirm !== password && (
                <p className="text-xs text-red-600 mt-1">Passwords do not match</p>
              )}
            </div>
          )}

          {error && (
            <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg p-2">{error}</div>
          )}

          <button
            type="submit"
            className="w-full bg-blue-600 hover:bg-blue-700 transition-colors text-white py-2 rounded-lg disabled:opacity-60"
            disabled={loading || !canSubmit()}
          >
            {loading ? 'Please wait...' : (mode === 'login' ? 'Login' : 'Create account')}
          </button>
        </form>
      </div>
    </div>
  );
};

export default AuthPage;



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
    <div className="min-h-screen quantum-lab flex items-center justify-center p-4">
      <div className="w-full max-w-md glass-card material-thick backdrop-blur-3xl">
        <div className="flex justify-center mb-8 p-1 bg-gray-100/50 rounded-xl backdrop-blur-sm">
          <button
            className={`flex-1 py-2 rounded-lg text-sm font-semibold transition-all duration-300 ${mode === 'login'
              ? 'bg-white text-black shadow-sm scale-[1.02]'
              : 'text-gray-500 hover:text-gray-900'
              }`}
            onClick={() => setMode('login')}
            disabled={loading}
          >
            Login
          </button>
          <button
            className={`flex-1 py-2 rounded-lg text-sm font-semibold transition-all duration-300 ${mode === 'signup'
              ? 'bg-white text-black shadow-sm scale-[1.02]'
              : 'text-gray-500 hover:text-gray-900'
              }`}
            onClick={() => setMode('signup')}
            disabled={loading}
          >
            Sign Up
          </button>
        </div>

        <div className="text-center mb-8">
          <h2 className="text-2xl font-bold text-[var(--text-primary)] tracking-tight">
            {mode === 'login' ? 'Welcome Back' : 'Create Account'}
          </h2>
          <p className="text-gray-500 mt-2 text-sm">
            {mode === 'login'
              ? 'Enter your credentials to access the secure quantum network.'
              : 'Join the quantum-secured network in seconds.'}
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5 ml-1">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-gray-50/50 border border-gray-200/60 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-[var(--system-blue)] focus:border-transparent transition-all"
              placeholder="Enter username"
              required
              autoComplete="username"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5 ml-1">Password</label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-gray-50/50 border border-gray-200/60 rounded-xl px-4 py-3 pr-12 focus:outline-none focus:ring-2 focus:ring-[var(--system-blue)] focus:border-transparent transition-all"
                placeholder="••••••"
                required
                minLength={6}
                autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-xs font-medium text-[var(--system-blue)] hover:text-blue-700 transition-colors"
              >
                {showPassword ? 'Hide' : 'Show'}
              </button>
            </div>
          </div>
          {mode === 'signup' && (
            <div>
              <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5 ml-1">Confirm Password</label>
              <input
                type={showPassword ? 'text' : 'password'}
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                className="w-full bg-gray-50/50 border border-gray-200/60 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-[var(--system-blue)] focus:border-transparent transition-all"
                placeholder="••••••"
                required
                minLength={6}
                autoComplete="new-password"
              />
              {confirm && confirm !== password && (
                <p className="text-xs text-red-500 mt-2 ml-1">Passwords do not match</p>
              )}
            </div>
          )}

          {error && (
            <div className="text-sm text-red-600 bg-red-50/80 backdrop-blur-md border border-red-200 rounded-xl p-3 flex items-center justify-center">
              {error}
            </div>
          )}

          <button
            type="submit"
            className="w-full bg-[var(--system-blue)] hover:bg-blue-600 text-white font-semibold py-3.5 rounded-xl shadow-lg shadow-blue-500/20 active:scale-[0.98] transition-all disabled:opacity-70 disabled:active:scale-100 mt-2"
            disabled={loading || !canSubmit()}
          >
            {loading ? 'Processing...' : (mode === 'login' ? 'Sign In' : 'Create Account')}
          </button>
        </form>
      </div>
    </div>
  );
};

export default AuthPage;



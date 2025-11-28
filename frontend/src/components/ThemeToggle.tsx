import React from 'react';
import { Moon, Sun } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';

interface ThemeToggleProps {
  compact?: boolean;
}

const ThemeToggle: React.FC<ThemeToggleProps> = ({ compact }) => {
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === 'dark';

  return (
    <button
      onClick={toggleTheme}
      className={`theme-toggle ${compact ? 'theme-toggle-compact' : ''}`}
      aria-label="Toggle color theme"
    >
      <div className={`theme-toggle-icon ${isDark ? 'theme-toggle-icon--dark' : 'theme-toggle-icon--light'}`}>
        {isDark ? <Moon size={18} /> : <Sun size={18} />}
      </div>
      {!compact && (
        <span className="theme-toggle-label">
          {isDark ? 'Dark' : 'Light'}
        </span>
      )}
    </button>
  );
};

export default ThemeToggle;


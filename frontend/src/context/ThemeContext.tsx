import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';

type ThemeMode = 'light' | 'dark';

interface ThemeContextValue {
  theme: ThemeMode;
  toggleTheme: () => void;
  setTheme: (mode: ThemeMode) => void;
}

const storageKey = 'bb84_theme_preference';

const ThemeContext = createContext<ThemeContextValue>({
  theme: 'dark',
  toggleTheme: () => {},
  setTheme: () => {}
});

const getSystemPreference = (): ThemeMode => {
  if (typeof window === 'undefined') return 'dark';
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
};

const getStoredPreference = (): ThemeMode | null => {
  if (typeof window === 'undefined') return null;
  const stored = window.localStorage.getItem(storageKey);
  return stored === 'dark' || stored === 'light' ? stored : null;
};

export const ThemeProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
  const [theme, setTheme] = useState<ThemeMode>(() => getStoredPreference() ?? getSystemPreference());

  useEffect(() => {
    if (typeof document === 'undefined') return;
    document.documentElement.setAttribute('data-theme', theme);
    document.documentElement.style.colorScheme = theme;
    window.localStorage.setItem(storageKey, theme);
  }, [theme]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const listener = (event: MediaQueryListEvent) => {
      const stored = getStoredPreference();
      if (!stored) {
        setTheme(event.matches ? 'dark' : 'light');
      }
    };
    const matcher = window.matchMedia('(prefers-color-scheme: dark)');
    matcher.addEventListener('change', listener);
    return () => matcher.removeEventListener('change', listener);
  }, []);

  const value = useMemo(() => ({
    theme,
    toggleTheme: () => setTheme(prev => (prev === 'dark' ? 'light' : 'dark')),
    setTheme
  }), [theme]);

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = () => useContext(ThemeContext);
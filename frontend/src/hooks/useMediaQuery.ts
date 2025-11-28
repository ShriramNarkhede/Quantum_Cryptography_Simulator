import { useEffect, useState } from 'react';

const canUseDOM = () => typeof window !== 'undefined' && typeof window.matchMedia !== 'undefined';

export const useMediaQuery = (query: string): boolean => {
  const getMatch = () => {
    if (!canUseDOM()) return false;
    return window.matchMedia(query).matches;
  };

  const [matches, setMatches] = useState<boolean>(getMatch);

  useEffect(() => {
    if (!canUseDOM()) return;
    const mediaQueryList = window.matchMedia(query);
    const listener = (event: MediaQueryListEvent) => setMatches(event.matches);
    mediaQueryList.addEventListener('change', listener);
    setMatches(mediaQueryList.matches);
    return () => mediaQueryList.removeEventListener('change', listener);
  }, [query]);

  return matches;
};



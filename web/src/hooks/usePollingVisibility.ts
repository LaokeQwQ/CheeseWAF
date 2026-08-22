import { useEffect, useState } from 'react';

function getDocumentVisible(): boolean {
  return typeof document === 'undefined' ? true : !document.hidden;
}

/** True while the tab is visible (not document.hidden). */
export function usePageVisibility(): boolean {
  const [visible, setVisible] = useState(getDocumentVisible);

  useEffect(() => {
    if (typeof document === 'undefined') {
      return undefined;
    }
    const update = () => setVisible(getDocumentVisible());
    document.addEventListener('visibilitychange', update);
    return () => document.removeEventListener('visibilitychange', update);
  }, []);

  return visible;
}

/**
 * Returns the desired refetchInterval only while the tab is visible; hidden
 * tabs pause polling (false). This pairs with the global
 * `refetchIntervalInBackground: false` to avoid burning requests in background.
 */
export function usePollingVisibility(refetchInterval: number | false): number | false {
  const visible = usePageVisibility();
  return visible ? refetchInterval : false;
}

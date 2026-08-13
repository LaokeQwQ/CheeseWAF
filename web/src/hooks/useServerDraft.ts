import { useCallback, useEffect, useRef, useState } from 'react';

/**
 * Keeps a local draft of server data without overwriting unsaved edits on refetch.
 * First successful server payload hydrates the draft; subsequent refetches are ignored while dirty.
 * Call markClean() after a successful save so the next server payload can re-hydrate.
 */
export function useServerDraft<T>(server: T | undefined | null) {
  const [draft, setDraftState] = useState<T | undefined>(undefined);
  const dirtyRef = useRef(false);
  const hydratedRef = useRef(false);
  const revisionRef = useRef(0);

  useEffect(() => {
    if (server === undefined || server === null) {
      return;
    }
    if (!hydratedRef.current || !dirtyRef.current) {
      setDraftState(server);
      hydratedRef.current = true;
      dirtyRef.current = false;
    }
  }, [server]);

  const setDraft = useCallback((next: T | undefined | ((prev: T | undefined) => T | undefined)) => {
    dirtyRef.current = true;
    revisionRef.current += 1;
    setDraftState((prev) => (typeof next === 'function' ? (next as (p: T | undefined) => T | undefined)(prev) : next));
  }, []);

  const markClean = useCallback((next?: T, expectedRevision?: number) => {
    if (expectedRevision !== undefined && revisionRef.current !== expectedRevision) {
      return false;
    }
    dirtyRef.current = false;
    if (next !== undefined) {
      setDraftState(next);
      hydratedRef.current = true;
    }
    return true;
  }, []);

  const resetFromServer = useCallback((next: T) => {
    dirtyRef.current = false;
    hydratedRef.current = true;
    revisionRef.current += 1;
    setDraftState(next);
  }, []);

  return {
    draft,
    setDraft,
    markClean,
    resetFromServer,
    isDirty: () => dirtyRef.current,
    isHydrated: () => hydratedRef.current,
    getRevision: () => revisionRef.current,
  };
}

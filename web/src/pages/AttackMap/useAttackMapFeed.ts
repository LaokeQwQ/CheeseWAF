import { useQuery } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import { fetchAttackMapAggregate } from '../../api/client';
import { usePollingVisibility } from '../../hooks/usePollingVisibility';
import type { AttackMapAggregate, AttackMapAggregateResponse, LogEntry } from '../../types/api';
import { mergeAttackMapAggregates, mergeAttackMapFeed, nextAttackMapCursor, type AttackMapCursor } from './attackMapFeed';

type AttackMapQueryResult = {
  baseCursor: AttackMapCursor | null;
  response: AttackMapAggregateResponse;
};

export function useAttackMapFeed(queryKey: string, refreshMs: number | false) {
  const cursorRef = useRef<AttackMapCursor | null>(null);
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [aggregates, setAggregates] = useState<AttackMapAggregate[]>([]);
  const [initialized, setInitialized] = useState(false);
  const refetchInterval = usePollingVisibility(refreshMs);
  const query = useQuery<AttackMapQueryResult>({
    queryKey: [queryKey],
    queryFn: async () => {
      const baseCursor = cursorRef.current;
      const response = await fetchAttackMapAggregate({
        limit: baseCursor ? 250 : 1000,
        after: baseCursor?.time,
        after_id: baseCursor?.id,
      });
      return { baseCursor, response };
    },
    refetchInterval,
    refetchOnMount: 'always',
    retry: false,
  });

  useEffect(() => {
    if (!query.data) {
      return;
    }
    const { baseCursor, response } = query.data;
    const currentCursor = cursorRef.current;
    if (!currentCursor) {
      if (baseCursor) {
        return;
      }
      setEntries(mergeAttackMapFeed([], response));
      setAggregates(mergeAttackMapAggregates([], response));
      cursorRef.current = nextAttackMapCursor(null, response);
      setInitialized(true);
      return;
    }
    if (!sameCursor(baseCursor, currentCursor)) {
      return;
    }
    const nextCursor = nextAttackMapCursor(currentCursor, response);
    if (sameCursor(nextCursor, currentCursor)) {
      setInitialized(true);
      return;
    }
    setEntries((current) => mergeAttackMapFeed(current, response));
    setAggregates((current) => mergeAttackMapAggregates(current, response));
    cursorRef.current = nextCursor;
    setInitialized(true);
  }, [query.data]);

  return {
    ...query,
    data: query.data?.response,
    isLoading: !initialized && (query.isLoading || query.isFetching),
    entries,
    aggregates,
  };
}

function sameCursor(left: AttackMapCursor | null, right: AttackMapCursor | null) {
  return left?.time === right?.time && left?.id === right?.id;
}

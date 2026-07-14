import { QueryClient } from '@tanstack/react-query';

/** Shared React Query client — used by App provider, auth 401 handling, and logout. */
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      refetchIntervalInBackground: false,
      staleTime: 30_000,
      gcTime: 10 * 60_000,
    },
  },
});

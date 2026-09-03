import { useCallback, useEffect, useRef, useState } from "react";

interface ApiState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
}

/**
 * Fetches once on mount, optionally polls via `pollMs`, and re-fetches when
 * `refetch()` runs. The fetcher itself is read from a ref, so an inline closure
 * that changes identity on every render does NOT cause an effect re-run /
 * refetch storm; callers that need a state-dependent fetcher simply call
 * `refetch()` when their input changes.
 */
export function useApi<T>(fetcher: () => Promise<T>, pollMs?: number): ApiState<T> {
  const fetcherRef = useRef(fetcher);
  const dataRef = useRef<T | null>(null);
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    fetcherRef.current = fetcher;
  });
  useEffect(() => {
    dataRef.current = data;
  }, [data]);

  const refetch = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    let active = true;
    const run = async () => {
      // Avoid flickering an existing dataset when merely refreshing.
      if (dataRef.current === null) setLoading(true);
      try {
        const result = await fetcherRef.current();
        if (active) {
          setData(result);
          setError(null);
        }
      } catch (e) {
        if (active) setError(e instanceof Error ? e.message : "Request failed");
      } finally {
        if (active) setLoading(false);
      }
    };
    run();
    if (pollMs) {
      const id = setInterval(run, pollMs);
      return () => {
        active = false;
        clearInterval(id);
      };
    }
    return () => {
      active = false;
    };
  }, [pollMs, tick]);

  return { data, loading, error, refetch };
}
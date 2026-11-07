import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { loadDataset, type IndexedDataset } from './loader';

type State =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; data: IndexedDataset };

const Ctx = createContext<State>({ status: 'loading' });

export function DatasetProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<State>({ status: 'loading' });
  useEffect(() => {
    let cancelled = false;
    loadDataset()
      .then((data) => {
        if (!cancelled) setState({ status: 'ready', data });
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setState({ status: 'error', message: err instanceof Error ? err.message : String(err) });
      });
    return () => {
      cancelled = true;
    };
  }, []);
  return <Ctx.Provider value={state}>{children}</Ctx.Provider>;
}

export function useDatasetState(): State {
  return useContext(Ctx);
}

/** Används i vyer som renderas först när data är laddad. */
export function useDataset(): IndexedDataset {
  const s = useContext(Ctx);
  if (s.status !== 'ready') throw new Error('useDataset anropades innan datasetet var laddat');
  return s.data;
}

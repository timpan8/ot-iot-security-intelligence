import { useMemo } from 'react';
import { useSearchParams } from 'react-router';
import { parseFilters, serializeFilters, type CatalogFilters } from '@/lib/filters';

/** Filterläge som speglas i URL:ens query-sträng (under hash-routen). */
export function useCatalogFilters(): [CatalogFilters, (next: CatalogFilters) => void] {
  const [params, setParams] = useSearchParams();
  const filters = useMemo(() => parseFilters(params), [params]);
  const set = (next: CatalogFilters) => setParams(serializeFilters(next), { replace: true });
  return [filters, set];
}

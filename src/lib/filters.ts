import type { IndexedDataset, CatalogEntry } from '@/data/loader';
import { isProduct } from '@/data/loader';

export type EntryKind = 'all' | 'product_family' | 'protocol_service';
export type SortKey = 'name' | 'vendor' | 'category' | 'verification' | 'action';

export interface CatalogFilters {
  q: string;
  vendor: string[];
  category: string[];
  kind: EntryKind;
  cve: string;
  riskType: string;
  verification: string[];
  kev: 'any' | 'yes' | 'no';
  fix: string[]; // fix.available-värden
  flags: string[];
  action: string[];
  sort: SortKey;
  dir: 'asc' | 'desc';
}

export const DEFAULT_FILTERS: CatalogFilters = {
  q: '',
  vendor: [],
  category: [],
  kind: 'all',
  cve: '',
  riskType: '',
  verification: [],
  kev: 'any',
  fix: [],
  flags: [],
  action: [],
  sort: 'name',
  dir: 'asc',
};

const LIST_KEYS = ['vendor', 'category', 'verification', 'fix', 'flags', 'action'] as const;

export function parseFilters(params: URLSearchParams): CatalogFilters {
  const f: CatalogFilters = {
    ...DEFAULT_FILTERS,
    vendor: [],
    category: [],
    verification: [],
    fix: [],
    flags: [],
    action: [],
  };
  f.q = params.get('q') ?? '';
  f.cve = params.get('cve') ?? '';
  f.riskType = params.get('risk') ?? '';
  const kind = params.get('kind');
  if (kind === 'product_family' || kind === 'protocol_service') f.kind = kind;
  const kev = params.get('kev');
  if (kev === 'yes' || kev === 'no') f.kev = kev;
  for (const k of LIST_KEYS) {
    const v = params.get(k);
    f[k] = v
      ? v
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean)
      : [];
  }
  const sort = params.get('sort');
  if (
    sort === 'name' ||
    sort === 'vendor' ||
    sort === 'category' ||
    sort === 'verification' ||
    sort === 'action'
  )
    f.sort = sort;
  if (params.get('dir') === 'desc') f.dir = 'desc';
  return f;
}

export function serializeFilters(f: CatalogFilters): URLSearchParams {
  const p = new URLSearchParams();
  if (f.q) p.set('q', f.q);
  if (f.cve) p.set('cve', f.cve);
  if (f.riskType) p.set('risk', f.riskType);
  if (f.kind !== 'all') p.set('kind', f.kind);
  if (f.kev !== 'any') p.set('kev', f.kev);
  for (const k of LIST_KEYS) if (f[k].length) p.set(k, f[k].join(','));
  if (f.sort !== 'name') p.set('sort', f.sort);
  if (f.dir !== 'asc') p.set('dir', f.dir);
  return p;
}

export function countActiveFilters(f: CatalogFilters): number {
  let n = 0;
  if (f.q) n++;
  if (f.cve) n++;
  if (f.riskType) n++;
  if (f.kind !== 'all') n++;
  if (f.kev !== 'any') n++;
  for (const k of LIST_KEYS) if (f[k].length) n++;
  return n;
}

export interface EntryDerived {
  vendorName: string | null;
  cveIds: string[];
  kevListed: boolean;
  fixValues: string[];
}

export function deriveEntry(d: IndexedDataset, e: CatalogEntry): EntryDerived {
  const matches = isProduct(e) ? (d.matchesByProduct.get(e.id) ?? []) : [];
  const vulns = matches
    .map((m) => (m.vulnerability_id ? d.vulnerabilityById.get(m.vulnerability_id) : undefined))
    .filter((v): v is NonNullable<typeof v> => Boolean(v));
  return {
    vendorName: isProduct(e) ? (d.vendorById.get(e.vendor_id)?.name ?? null) : null,
    cveIds: [...new Set(vulns.map((v) => v.cve_id))],
    kevListed: vulns.some((v) => v.kev.listed),
    fixValues: [...new Set(matches.map((m) => m.fix.available))],
  };
}

export function applyFilters(
  d: IndexedDataset,
  entries: CatalogEntry[],
  f: CatalogFilters,
  searchHits: Set<string> | null,
): CatalogEntry[] {
  const cveNeedle = f.cve.trim().toUpperCase();
  const riskNeedle = f.riskType.trim().toLowerCase();
  const out = entries.filter((e) => {
    if (searchHits && !searchHits.has(e.id)) return false;
    if (f.kind !== 'all' && e.kind !== f.kind) return false;
    if (f.category.length && !f.category.includes(e.category)) return false;
    const der = deriveEntry(d, e);
    if (f.vendor.length) {
      if (!isProduct(e) || !f.vendor.includes(e.vendor_id)) return false;
    }
    if (cveNeedle && !der.cveIds.some((c) => c.includes(cveNeedle))) return false;
    if (riskNeedle) {
      const hay =
        `${e.risk_summary.type_text ?? ''} ${e.risk_summary.explanation_text ?? ''}`.toLowerCase();
      if (!hay.includes(riskNeedle)) return false;
    }
    if (f.verification.length && !f.verification.includes(e.verification_status)) return false;
    if (f.kev === 'yes' && !der.kevListed) return false;
    if (f.kev === 'no' && der.kevListed) return false;
    if (f.fix.length && !der.fixValues.some((v) => f.fix.includes(v))) return false;
    if (f.flags.length && !e.data_quality_flags.some((fl) => f.flags.includes(fl))) return false;
    if (f.action.length && !f.action.includes(e.risk.recommended_action)) return false;
    return true;
  });
  const verOrder = [
    'verified_primary',
    'corroborated_secondary',
    'disputed',
    'needs_review',
    'unknown',
  ];
  const cmp = (a: CatalogEntry, b: CatalogEntry): number => {
    switch (f.sort) {
      case 'vendor':
        return (deriveEntry(d, a).vendorName ?? '').localeCompare(
          deriveEntry(d, b).vendorName ?? '',
          'sv',
        );
      case 'category':
        return a.category.localeCompare(b.category, 'sv');
      case 'verification':
        return verOrder.indexOf(a.verification_status) - verOrder.indexOf(b.verification_status);
      case 'action':
        return a.risk.recommended_action.localeCompare(b.risk.recommended_action);
      default:
        return a.name.localeCompare(b.name, 'sv');
    }
  };
  out.sort((a, b) => {
    const c = cmp(a, b) || a.name.localeCompare(b.name, 'sv');
    return f.dir === 'desc' ? -c : c;
  });
  return out;
}

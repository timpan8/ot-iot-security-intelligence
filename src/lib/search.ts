import MiniSearch from 'minisearch';
import type { IndexedDataset, CatalogEntry } from '@/data/loader';
import { isProduct } from '@/data/loader';

export interface SearchDoc {
  id: string;
  name: string;
  aliases: string;
  vendor: string;
  category: string;
  function_text: string;
  risk: string;
  cves: string;
  register_id: string;
  account: string;
  scope: string;
}

export function buildSearchDocs(d: IndexedDataset): SearchDoc[] {
  return d.entries.map((e) => {
    const vendor = isProduct(e) ? (d.vendorById.get(e.vendor_id)?.name ?? '') : '';
    const cves = (isProduct(e) ? (d.matchesByProduct.get(e.id) ?? []) : [])
      .map((m) => (m.vulnerability_id ? d.vulnerabilityById.get(m.vulnerability_id)?.cve_id : null))
      .filter((x): x is string => Boolean(x))
      .join(' ');
    return {
      id: e.id,
      name: e.name,
      aliases: e.aliases.join(' '),
      vendor,
      category: e.category,
      function_text: e.function_text,
      risk: [e.risk_summary.type_text, e.risk_summary.explanation_text].filter(Boolean).join(' '),
      cves,
      register_id: e.register?.register_id ?? '',
      account: e.credentials?.account_name ?? '',
      scope: e.register?.scope_alias_text ?? '',
    };
  });
}

export function buildSearchIndex(docs: SearchDoc[]): MiniSearch<SearchDoc> {
  const ms = new MiniSearch<SearchDoc>({
    fields: [
      'name',
      'aliases',
      'vendor',
      'category',
      'function_text',
      'risk',
      'cves',
      'register_id',
      'account',
      'scope',
    ],
    storeFields: ['id'],
    searchOptions: {
      boost: { name: 4, register_id: 4, vendor: 3, aliases: 3, cves: 3, scope: 2, category: 2 },
      prefix: true,
      fuzzy: 0.15,
      combineWith: 'AND',
    },
  });
  ms.addAll(docs);
  return ms;
}

export function searchIds(index: MiniSearch<SearchDoc>, query: string): Set<string> | null {
  const q = query.trim();
  if (q.length === 0) return null;
  return new Set(index.search(q).map((r) => String(r.id)));
}

export function entryVendorName(d: IndexedDataset, e: CatalogEntry): string | null {
  return isProduct(e) ? (d.vendorById.get(e.vendor_id)?.name ?? null) : null;
}

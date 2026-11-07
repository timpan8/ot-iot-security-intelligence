import { z } from 'zod';
import {
  Advisory,
  Claim,
  Control,
  DATA_FILES,
  Dataset,
  Manifest,
  Observation,
  ProductFamily,
  ProductVulnerabilityMatch,
  ProtocolService,
  Source,
  Vendor,
  Vulnerability,
} from '@schemas/index';
import type {
  Advisory as TAdvisory,
  Claim as TClaim,
  Control as TControl,
  Dataset as TDataset,
  Observation as TObservation,
  ProductFamily as TProductFamily,
  ProductVulnerabilityMatch as TMatch,
  ProtocolService as TProtocolService,
  Source as TSource,
  Vendor as TVendor,
  Vulnerability as TVulnerability,
} from '@schemas/index';

export type CatalogEntry = TProductFamily | TProtocolService;

export interface IndexedDataset extends TDataset {
  vendorById: Map<string, TVendor>;
  productById: Map<string, TProductFamily>;
  protocolById: Map<string, TProtocolService>;
  entryById: Map<string, CatalogEntry>;
  vulnerabilityById: Map<string, TVulnerability>;
  vulnerabilityByCve: Map<string, TVulnerability>;
  advisoryById: Map<string, TAdvisory>;
  matchById: Map<string, TMatch>;
  matchesByProduct: Map<string, TMatch[]>;
  matchesByVulnerability: Map<string, TMatch[]>;
  matchesByAdvisory: Map<string, TMatch[]>;
  controlById: Map<string, TControl>;
  sourceById: Map<string, TSource>;
  observationById: Map<string, TObservation>;
  claimsByEntity: Map<string, TClaim[]>;
  entries: CatalogEntry[];
}

export function dataBase(): string {
  const env = import.meta.env.VITE_DATA_BASE;
  if (env && env.length > 0) return env.endsWith('/') ? env : `${env}/`;
  return `${import.meta.env.BASE_URL}data/`;
}

async function loadFile<T>(file: string, schema: z.ZodType<T>, fetcher: typeof fetch): Promise<T> {
  const url = `${dataBase()}${file}`;
  const res = await fetcher(url, { headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`Kunde inte hämta ${file} (HTTP ${res.status})`);
  const json: unknown = await res.json();
  const parsed = schema.safeParse(json);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .slice(0, 5)
      .map((i) => `${i.path.join('.')}: ${i.message}`)
      .join('; ');
    throw new Error(`Ogiltig data i ${file}: ${issues}`);
  }
  return parsed.data;
}

export async function loadDataset(fetcher: typeof fetch = fetch): Promise<IndexedDataset> {
  const [
    manifest,
    vendors,
    product_families,
    protocol_services,
    vulnerabilities,
    advisories,
    matches,
    controls,
    sources,
    observations,
    claims,
  ] = await Promise.all([
    loadFile(DATA_FILES.manifest, Manifest, fetcher),
    loadFile(DATA_FILES.vendors, z.array(Vendor), fetcher),
    loadFile(DATA_FILES.product_families, z.array(ProductFamily), fetcher),
    loadFile(DATA_FILES.protocol_services, z.array(ProtocolService), fetcher),
    loadFile(DATA_FILES.vulnerabilities, z.array(Vulnerability), fetcher),
    loadFile(DATA_FILES.advisories, z.array(Advisory), fetcher),
    loadFile(DATA_FILES.matches, z.array(ProductVulnerabilityMatch), fetcher),
    loadFile(DATA_FILES.controls, z.array(Control), fetcher),
    loadFile(DATA_FILES.sources, z.array(Source), fetcher),
    loadFile(DATA_FILES.observations, z.array(Observation), fetcher),
    loadFile(DATA_FILES.claims, z.array(Claim), fetcher),
  ]);
  const dataset: TDataset = Dataset.parse({
    manifest,
    vendors,
    product_families,
    protocol_services,
    vulnerabilities,
    advisories,
    matches,
    controls,
    sources,
    observations,
    claims,
  });
  return indexDataset(dataset);
}

function groupBy<T>(items: T[], key: (t: T) => string | null): Map<string, T[]> {
  const m = new Map<string, T[]>();
  for (const it of items) {
    const k = key(it);
    if (k === null) continue;
    const arr = m.get(k) ?? [];
    arr.push(it);
    m.set(k, arr);
  }
  return m;
}

export function indexDataset(d: TDataset): IndexedDataset {
  const byId = <T extends { id: string }>(arr: T[]) => new Map(arr.map((x) => [x.id, x] as const));
  const entries: CatalogEntry[] = [...d.product_families, ...d.protocol_services].sort((a, b) =>
    a.name.localeCompare(b.name, 'sv'),
  );
  return {
    ...d,
    vendorById: byId(d.vendors),
    productById: byId(d.product_families),
    protocolById: byId(d.protocol_services),
    entryById: byId(entries),
    vulnerabilityById: byId(d.vulnerabilities),
    vulnerabilityByCve: new Map(d.vulnerabilities.map((v) => [v.cve_id, v] as const)),
    advisoryById: byId(d.advisories),
    matchById: byId(d.matches),
    matchesByProduct: groupBy(d.matches, (m) => m.product_family_id),
    matchesByVulnerability: groupBy(d.matches, (m) => m.vulnerability_id),
    matchesByAdvisory: groupBy(d.matches, (m) => m.advisory_id),
    controlById: byId(d.controls),
    sourceById: byId(d.sources),
    observationById: byId(d.observations),
    claimsByEntity: groupBy(d.claims, (c) => c.entity_id),
    entries,
  };
}

export function isProduct(e: CatalogEntry): e is TProductFamily {
  return e.kind === 'product_family';
}

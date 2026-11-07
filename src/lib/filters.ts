import type { IndexedDataset, CatalogEntry } from '@/data/loader';
import { isProduct } from '@/data/loader';
import type {
  InitialPasswordType,
  MaterialTypeCode,
  PublicPocStatus,
  RegisterOrigin,
} from '@schemas/index';

export type EntryKind = 'all' | 'product_family' | 'protocol_service';
export type OriginFilter = 'all' | RegisterOrigin;
export type PocFilter = 'any' | PublicPocStatus;
export type DocGapFilter = 'any' | 'verified' | 'unverified';
export type ViewMode = 'table' | 'fields' | 'cards';
const POC_VALUES: PublicPocStatus[] = [
  'poc_reported',
  'none_reported_at_assessment',
  'unknown_missing',
  'active_reported',
];
export type SortKey = 'name' | 'vendor' | 'category' | 'verification' | 'action' | 'severity';
const SORT_KEYS: SortKey[] = ['name', 'vendor', 'category', 'verification', 'action', 'severity'];

/** Snabbfilter: "visa endast poster med …" */
export const HAS_KEYS = ['cve', 'kev', 'poc', 'account', 'defaultpw'] as const;
export type HasKey = (typeof HAS_KEYS)[number];

/** Lösenordstyper som i sig signalerar en svaghet som kräver åtgärd (inte bara okänt). */
export const WEAK_PWD: ReadonlySet<InitialPasswordType> = new Set<InitialPasswordType>([
  'shared_default_documented',
  'hardcoded_in_affected_version',
  'predictable_builtin_mechanism',
  'default_exists_type_unknown',
]);

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
  // Registerimport (125-postregistret)
  origin: OriginFilter;
  poc: PocFilter;
  material: string[]; // material_type_code
  pwdType: string[]; // initial_password_type
  docgap: DocGapFilter;
  regstatus: string[]; // register.source_status_text
  has: string[]; // HasKey
  sort: SortKey;
  dir: 'asc' | 'desc';
  /** Presentation, inte ett filter – räknas inte som aktivt filter. */
  view: ViewMode;
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
  origin: 'all',
  poc: 'any',
  material: [],
  pwdType: [],
  docgap: 'any',
  regstatus: [],
  has: [],
  sort: 'name',
  dir: 'asc',
  view: 'table',
};

const LIST_KEYS = [
  'vendor',
  'category',
  'verification',
  'fix',
  'flags',
  'action',
  'material',
  'pwdType',
  'regstatus',
  'has',
] as const;

export function parseFilters(params: URLSearchParams): CatalogFilters {
  const f: CatalogFilters = {
    ...DEFAULT_FILTERS,
    vendor: [],
    category: [],
    verification: [],
    fix: [],
    flags: [],
    action: [],
    material: [],
    pwdType: [],
    regstatus: [],
    has: [],
  };
  f.q = params.get('q') ?? '';
  const origin = params.get('origin');
  if (origin === 'original' || origin === 'new') f.origin = origin;
  const poc = params.get('poc');
  if (poc && (POC_VALUES as string[]).includes(poc)) f.poc = poc as PublicPocStatus;
  const docgap = params.get('docgap');
  if (docgap === 'verified' || docgap === 'unverified') f.docgap = docgap;
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
  f.has = f.has.filter((h) => (HAS_KEYS as readonly string[]).includes(h));
  const sort = params.get('sort');
  if (sort && (SORT_KEYS as string[]).includes(sort)) f.sort = sort as SortKey;
  if (params.get('dir') === 'desc') f.dir = 'desc';
  const view = params.get('view');
  if (view === 'cards' || view === 'fields') f.view = view;
  return f;
}

export function serializeFilters(f: CatalogFilters): URLSearchParams {
  const p = new URLSearchParams();
  if (f.q) p.set('q', f.q);
  if (f.cve) p.set('cve', f.cve);
  if (f.riskType) p.set('risk', f.riskType);
  if (f.kind !== 'all') p.set('kind', f.kind);
  if (f.kev !== 'any') p.set('kev', f.kev);
  if (f.origin !== 'all') p.set('origin', f.origin);
  if (f.poc !== 'any') p.set('poc', f.poc);
  if (f.docgap !== 'any') p.set('docgap', f.docgap);
  for (const k of LIST_KEYS) if (f[k].length) p.set(k, f[k].join(','));
  if (f.sort !== 'name') p.set('sort', f.sort);
  if (f.dir !== 'asc') p.set('dir', f.dir);
  if (f.view !== 'table') p.set('view', f.view);
  return p;
}

export function countActiveFilters(f: CatalogFilters): number {
  let n = 0;
  if (f.q) n++;
  if (f.cve) n++;
  if (f.riskType) n++;
  if (f.kind !== 'all') n++;
  if (f.kev !== 'any') n++;
  if (f.origin !== 'all') n++;
  if (f.poc !== 'any') n++;
  if (f.docgap !== 'any') n++;
  for (const k of LIST_KEYS) if (f[k].length) n++;
  return n;
}

export interface EntryDerived {
  vendorName: string | null;
  cveIds: string[];
  kevListed: boolean;
  fixValues: string[];
  /** Registerimport */
  origin: RegisterOrigin | null;
  pocStatuses: PublicPocStatus[];
  materialCodes: MaterialTypeCode[];
  pwdType: InitialPasswordType | null;
  accountName: string | null;
  setupVerified: boolean | null; // null = ingen setupdokumentation registrerad
  sourceStatus: string | null;
  /** Högsta CVSS-basvärde bland kopplade CVE (null = inget värde). */
  maxCvss: number | null;
  kevCount: number;
  /** Antal unika PoC-/hotunderlagslänkar (evidens, inte exploateringssteg). */
  pocLinkCount: number;
  weakPwd: boolean;
}

export function deriveEntry(d: IndexedDataset, e: CatalogEntry): EntryDerived {
  const matches = isProduct(e) ? (d.matchesByProduct.get(e.id) ?? []) : [];
  const vulns = matches
    .map((m) => (m.vulnerability_id ? d.vulnerabilityById.get(m.vulnerability_id) : undefined))
    .filter((v): v is NonNullable<typeof v> => Boolean(v));
  const ti = vulns.map((v) => v.threat_intel).filter((t): t is NonNullable<typeof t> => Boolean(t));
  const uniqVulns = [...new Map(vulns.map((v) => [v.cve_id, v])).values()];
  let maxCvss: number | null = null;
  for (const v of uniqVulns)
    for (const c of v.cvss)
      maxCvss = maxCvss === null ? c.base_score : Math.max(maxCvss, c.base_score);
  const pwdType = e.credentials?.initial_password_type ?? null;
  return {
    vendorName: isProduct(e) ? (d.vendorById.get(e.vendor_id)?.name ?? null) : null,
    cveIds: [...new Set(vulns.map((v) => v.cve_id))],
    kevListed: vulns.some((v) => v.kev.listed),
    fixValues: [...new Set(matches.map((m) => m.fix.available))],
    origin: e.register?.origin ?? null,
    pocStatuses: [...new Set(ti.map((t) => t.public_poc_status))],
    materialCodes: [...new Set(ti.map((t) => t.material_type_code))],
    pwdType,
    accountName: e.credentials?.account_name ?? null,
    setupVerified: e.setup_documentation ? e.setup_documentation.is_verified_setup_manual : null,
    sourceStatus: e.register?.source_status_text ?? null,
    maxCvss,
    kevCount: uniqVulns.filter((v) => v.kev.listed).length,
    pocLinkCount: new Set(ti.map((t) => t.poc_url).filter(Boolean)).size,
    weakPwd: pwdType ? WEAK_PWD.has(pwdType) : false,
  };
}

/** Sammanfattar PoC-signalerna för en post: starkaste signal först. Aldrig ett påstående om exploaterbarhet. */
export function strongestPoc(statuses: PublicPocStatus[]): PublicPocStatus | null {
  for (const s of POC_VALUES.slice().reverse()) if (statuses.includes(s)) return s;
  return null;
}

export function applyFilters(
  d: IndexedDataset,
  entries: CatalogEntry[],
  f: CatalogFilters,
  searchHits: Set<string> | null,
): CatalogEntry[] {
  const cveNeedle = f.cve.trim().toUpperCase();
  const riskNeedle = f.riskType.trim().toLowerCase();
  const cache = new Map<string, EntryDerived>();
  const derive = (e: CatalogEntry): EntryDerived => {
    let v = cache.get(e.id);
    if (!v) cache.set(e.id, (v = deriveEntry(d, e)));
    return v;
  };
  const out = entries.filter((e) => {
    if (searchHits && !searchHits.has(e.id)) return false;
    if (f.kind !== 'all' && e.kind !== f.kind) return false;
    if (f.category.length && !f.category.includes(e.category)) return false;
    const der = derive(e);
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
    if (f.origin !== 'all' && der.origin !== f.origin) return false;
    if (f.poc !== 'any' && !der.pocStatuses.includes(f.poc)) return false;
    if (f.material.length && !der.materialCodes.some((m) => f.material.includes(m))) return false;
    if (f.pwdType.length && (!der.pwdType || !f.pwdType.includes(der.pwdType))) return false;
    if (f.docgap === 'verified' && der.setupVerified !== true) return false;
    if (f.docgap === 'unverified' && der.setupVerified !== false) return false;
    if (f.regstatus.length && (!der.sourceStatus || !f.regstatus.includes(der.sourceStatus)))
      return false;
    if (f.has.includes('cve') && der.cveIds.length === 0) return false;
    if (f.has.includes('kev') && der.kevCount === 0) return false;
    if (f.has.includes('poc') && der.pocLinkCount === 0) return false;
    if (f.has.includes('account') && !der.accountName) return false;
    if (f.has.includes('defaultpw') && !der.weakPwd) return false;
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
        return (derive(a).vendorName ?? '').localeCompare(derive(b).vendorName ?? '', 'sv');
      case 'category':
        return a.category.localeCompare(b.category, 'sv');
      case 'verification':
        return verOrder.indexOf(a.verification_status) - verOrder.indexOf(b.verification_status);
      case 'action':
        return a.risk.recommended_action.localeCompare(b.risk.recommended_action);
      case 'severity': {
        // Allvarligast först i stigande ordning: KEV, sedan högsta CVSS
        const da = derive(a);
        const db = derive(b);
        return db.kevCount - da.kevCount || (db.maxCvss ?? -1) - (da.maxCvss ?? -1);
      }
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

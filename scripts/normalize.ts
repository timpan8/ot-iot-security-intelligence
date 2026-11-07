/**
 * Steg B3 – Normalisering: raw (workbook.json) + curated + enrichment-cache → public/data/*.json
 *
 * Principer:
 *  - Alla 66 poster bevaras med originalvärden och spårbarhet (provenance per cell).
 *  - Inga fabricerade uppgifter: allt som inte stöds av källa blir unknown/needs_review.
 *  - Protokoll får aldrig CVE-matchningar.
 *  - CVE-intervall expanderas bara om varje ID finns verifierat i NVD-cachen.
 *  - Exponering är alltid 'unknown' i publik katalog.
 */
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, statSync } from 'node:fs';
import {
  DATA_FILES,
  SCHEMA_VERSION,
  type Advisory,
  type Claim,
  type Control,
  type DataQualityFlag,
  Dataset,
  type FactorLevel,
  type LinkCheck,
  type Manifest,
  type Observation,
  type ProductFamily,
  type ProductVulnerabilityMatch,
  type ProtocolService,
  type RecommendedAction,
  type RiskAssessment,
  type Source,
  type Vendor,
  type VerificationStatus,
  type Vulnerability,
} from '../schemas/index';
import { CURATED_FILES, loadCuratedArray, loadCuratedRecord } from './lib/curated';
import {
  addRegisterSources,
  buildLinkChecks,
  buildRegisterAdvisories,
  credentialsFor,
  extractUrls,
  g,
  isHttps,
  loadCsafIndex,
  loadRegister,
  normalizeUrl as regNormalizeUrl,
  registerInfoFor,
  reviewFindingsFor,
  setupDocFor,
  threatIntelFor,
  verifyRelationAgainstCsaf,
  type RegisterData,
} from './normalize-register';
import type { RawRecord } from './import-register';
import { nowIso, p, readJson, writeJson } from './lib/fs';
import type { FieldKey, WorkbookJson, WorkbookRecord } from './import-xlsx';

/* ------------------------------------------------------------------ */
/* Typer för kuraterade filer (löst typade – valideras i validate.ts)  */
/* ------------------------------------------------------------------ */

type CuratedMatch = Omit<ProductVulnerabilityMatch, 'vulnerability_id'> & { cve_id: string };
type CuratedClaim = {
  id: string;
  field: string;
  text: string;
  status: VerificationStatus;
  source_ids: string[];
  conflict_note?: string | null;
};
type RowOverride = {
  id: string;
  vendor_id?: string;
  aliases?: string[];
  lifecycle?: {
    status: ProductFamily['lifecycle']['status'];
    eol_date: string | null;
    eol_status: VerificationStatus;
    note: string | null;
  };
  ot_role?: string;
  ot_consequence?: string;
  protocol_service_ids?: string[];
  doc_level?: ProductFamily['documentation'][number]['level'];
  doc_product_specific?: boolean;
  ot_impact?: { level: FactorLevel; basis: string };
  control_ids?: string[];
  claims?: CuratedClaim[];
  unexpanded_cve_ranges?: ProductFamily['unexpanded_cve_ranges'];
  // protokoll
  typical_use?: string;
  default_ports?: ProtocolService['default_ports'];
  authentication?: ProtocolService['authentication'];
  encryption?: ProtocolService['encryption'];
  security_notes?: string;
  allowed_zones?: string;
};
type VulnOverride = {
  summary_sv?: string;
  advisory_ids?: string[];
  verification_status?: VerificationStatus;
  exploitation_evidence?: Vulnerability['exploitation_evidence'];
  review?: Vulnerability['review'];
};

/* ------------------------------------------------------------------ */
/* Hjälpare                                                            */
/* ------------------------------------------------------------------ */

const HEADER_COLUMNS: Record<FieldKey, string> = {
  category: 'A',
  name: 'B',
  function: 'C',
  shodan_query: 'D',
  risk_type: 'E',
  risk_explanation: 'F',
  cve_bulletin: 'G',
  affected_firmware: 'H',
  fix: 'I',
  patch_level: 'J',
  defensive_control: 'K',
  documentation_url: 'L',
  documentation_level: 'M',
  security_source_url: 'N',
  priority_if_exposed: 'O',
};

const GENERIC_CONTROL_PREFIX = 'Ingen publik direktadministration';
const DISCOVERY_CAVEAT =
  'Sökord är heuristik för egen/auktoriserad inventering (komplettera med net:DITT-EGET-IP-INTERVALL). Träffar är inte enhetsbevis och kan vara falska; portträffar identifierar protokollmöjlighet, inte specifik produkt. Plattformen utför inga sökningar.';

const STATUS_RANK: Record<VerificationStatus, number> = {
  verified_primary: 4,
  corroborated_secondary: 3,
  needs_review: 2,
  disputed: 1,
  unknown: 0,
};
function minStatus(statuses: VerificationStatus[]): VerificationStatus {
  if (statuses.length === 0) return 'unknown';
  return statuses.reduce((a, b) => (STATUS_RANK[b] < STATUS_RANK[a] ? b : a));
}

function normalizeUrl(u: string): string {
  return u.trim().replace(/\/+$/, '').toLowerCase();
}
function shortHash(s: string): string {
  return createHash('sha256').update(s).digest('hex').slice(0, 8);
}
function hostOf(u: string): string {
  try {
    return new URL(u).hostname.toLowerCase();
  } catch {
    return 'unknown-host';
  }
}
function toIsoDateTime(nvd: string | undefined | null): string | null {
  if (!nvd) return null;
  // NVD API 2.0 anger tidsstämplar utan zon; dokumenterat som UTC.
  return /Z$|[+-]\d{2}:\d{2}$/.test(nvd) ? nvd : `${nvd}Z`;
}
/** Tidsstämpel = cachefilens mtime (när data faktiskt hämtades), inte byggtid. */
function fileMtimeIso(path: string): string {
  return statSync(path).mtime.toISOString();
}
function cveToId(cve: string): string {
  return `cve-${cve.toLowerCase().replace(/^cve-/, '')}`;
}
function uniq<T>(arr: T[]): T[] {
  return [...new Set(arr)];
}

function hostMatchesDomain(host: string, domain: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  const d = domain.toLowerCase().replace(/\.$/, '');
  return h === d || h.endsWith(`.${d}`);
}

/* ------------------------------------------------------------------ */
/* Källor                                                              */
/* ------------------------------------------------------------------ */

function classifySourceByHost(host: string): { type: Source['source_type']; publisher: string } {
  if (hostMatchesDomain(host, 'csrc.nist.gov') || hostMatchesDomain(host, 'nist.gov'))
    return { type: 'primary_standard', publisher: 'NIST' };
  if (hostMatchesDomain(host, 'cisa.gov')) return { type: 'primary_government', publisher: 'CISA' };
  if (hostMatchesDomain(host, 'armis.com'))
    return { type: 'secondary_research', publisher: 'Armis' };
  if (hostMatchesDomain(host, 'opcfoundation.org'))
    return { type: 'primary_standard', publisher: 'OPC Foundation' };
  if (hostMatchesDomain(host, 'learn.microsoft.com'))
    return { type: 'primary_vendor', publisher: 'Microsoft' };
  if (hostMatchesDomain(host, 'cert-portal.siemens.com'))
    return { type: 'primary_vendor', publisher: 'Siemens ProductCERT' };
  return { type: 'primary_vendor', publisher: host.replace(/^www\./, '') };
}

/* ------------------------------------------------------------------ */
/* Huvudflöde                                                          */
/* ------------------------------------------------------------------ */

export function buildDataset(): Dataset {
  const wb = readJson<WorkbookJson>(p('sources', 'raw', 'workbook.json'));
  const vendors = loadCuratedArray<Vendor>(...CURATED_FILES.vendors);
  const curatedSources = loadCuratedArray<Source>(...CURATED_FILES.sources);
  const advisoriesIn = loadCuratedArray<Advisory>(...CURATED_FILES.advisories);
  const matchesIn = loadCuratedArray<CuratedMatch>(...CURATED_FILES.matches);
  const controls = loadCuratedArray<Control>(...CURATED_FILES.controls);
  const observations = loadCuratedArray<Observation>(...CURATED_FILES.observations);
  const overrides = loadCuratedRecord<RowOverride>(...CURATED_FILES.overrides);
  const vulnOverrides = loadCuratedRecord<VulnOverride>(...CURATED_FILES.vulnerability_overrides);

  /* --- Källor: kuraterade + auto från arbetsboken (dedupe på URL) --- */
  const sourcesByUrl = new Map<string, Source>();
  const sources: Source[] = [];
  for (const s of curatedSources) {
    sourcesByUrl.set(normalizeUrl(s.url), s);
    sources.push(s);
  }
  const workbookSourceId = 'src-workbook';
  const rowSources = new Map<number, { doc: Source | null; sec: Source | null }>();
  for (const r of wb.records) {
    const entry: { doc: Source | null; sec: Source | null } = { doc: null, sec: null };
    for (const [key, field] of [
      ['doc', 'documentation_url'],
      ['sec', 'security_source_url'],
    ] as const) {
      const url = r.fields[field];
      if (!url) continue;
      const norm = normalizeUrl(url);
      let s = sourcesByUrl.get(norm);
      if (!s) {
        const host = hostOf(url);
        const cls = classifySourceByHost(host);
        s = {
          id: `src-wb-${host.replace(/[^a-z0-9.]/g, '-')}-${shortHash(norm)}`,
          url: url.trim(),
          title:
            key === 'doc'
              ? `${r.fields.documentation_level ?? 'Dokumentation'} – ${r.fields.name}`
              : `Säkerhetskälla (arbetsboken) – ${r.fields.name}`,
          publisher: cls.publisher,
          source_type: cls.type,
          is_primary: cls.type.startsWith('primary'),
          published_at: null,
          last_checked_at: null,
          last_verified_at: null,
          availability: 'unchecked',
          http_status: null,
          supports_claims: [],
          access_note: null,
          notes: `Länk från arbetsboken, rad ${r.row}, kolumn ${key === 'doc' ? 'L' : 'N'}.`,
          document_sha256: null,
          fetched_at: null,
          final_url: null,
          interpretation_text: null,
          register_source_key: null,
        };
        sourcesByUrl.set(norm, s);
        sources.push(s);
      }
      s.supports_claims.push({
        entity_id: overrides[String(r.row)]?.id ?? `row-${r.row}`,
        field: key === 'doc' ? 'documentation' : 'risk_summary.cve_text',
        note: `Arbetsboken rad ${r.row}, kolumn ${key === 'doc' ? 'L' : 'N'}`,
      });
      entry[key] = s;
    }
    rowSources.set(r.row, entry);
  }
  /* --- Registerimport (125-postregistret): källor, länkkontroll, CSAF-index --- */
  const reg = loadRegister();
  const regUrlToSource = reg
    ? addRegisterSources(reg, sources, sourcesByUrl)
    : new Map<string, string>();
  const linkChecks: LinkCheck[] = reg ? buildLinkChecks(reg, sourcesByUrl) : [];
  const csafIndex = loadCsafIndex();
  const categoryProfiles = loadCuratedRecord<{
    group: string;
    ot_impact: FactorLevel;
    basis: string;
  }>('category_profiles.json', 'categories');
  const regVendors = loadCuratedRecord<{ vendor_id: string }>('register_vendors.json', 'rows');
  const projectIdFor = (rid: string): string | null => reg?.idMap[rid] ?? null;
  const registerIdFor = new Map<string, string>(
    reg ? Object.entries(reg.idMap).map(([rid, pid]) => [pid, rid]) : [],
  );
  const sourceIds = new Set(sources.map((s) => s.id));

  /* --- Sårbarheter från NVD-cache + overrides + EPSS + KEV --- */
  const nvdDir = p('sources', 'enrichment', 'nvd');
  const epssRaw = existsSync(p('sources', 'enrichment', 'epss.json'))
    ? readJson<{ data?: { cve: string; epss: string; percentile: string; date: string }[] }>(
        p('sources', 'enrichment', 'epss.json'),
      )
    : { data: [] };
  const kevRaw = existsSync(p('sources', 'enrichment', 'kev.json'))
    ? readJson<{
        catalogVersion?: string;
        fetched_at?: string;
        checked_cve_ids?: string[];
        vulnerabilities?: {
          cveID: string;
          dateAdded: string;
          dueDate: string;
          knownRansomwareCampaignUse: string;
          vulnerabilityName: string;
        }[];
      }>(p('sources', 'enrichment', 'kev.json'))
    : {};
  const epssByCve = new Map((epssRaw.data ?? []).map((d) => [d.cve, d]));
  const kevByCve = new Map((kevRaw.vulnerabilities ?? []).map((v) => [v.cveID, v]));
  const kevChecked = new Set(kevRaw.checked_cve_ids ?? []);

  const registerCves = reg
    ? uniq(reg.sheets.vulnerabilities.records.map((r) => r.fields.cve_id!))
    : [];
  const registerVulnRowByCve = new Map<string, RawRecord>();
  if (reg)
    for (const r of reg.sheets.vulnerabilities.records)
      if (!registerVulnRowByCve.has(r.fields.cve_id!))
        registerVulnRowByCve.set(r.fields.cve_id!, r);
  const neededCves = uniq([
    ...matchesIn.map((m) => m.cve_id),
    ...Object.keys(vulnOverrides),
    ...registerCves,
  ]).sort();

  const vulnerabilities: Vulnerability[] = [];
  const vulnIds = new Set<string>();
  for (const cve of neededCves) {
    const file = p(nvdDir, `${cve}.json`);
    const regRow = registerVulnRowByCve.get(cve);
    if (!existsSync(file)) {
      if (!regRow) {
        throw new Error(
          `NVD-cache saknas för ${cve} (${file}). Kör data:enrich eller ta bort referensen.`,
        );
      }
      // Fallback: arbetsboksuppgift utan NVD-post – markeras needs_review
      const rf = regRow.fields;
      const score =
        rf.cvss_base_score !== null &&
        rf.cvss_base_score !== undefined &&
        !Number.isNaN(Number(rf.cvss_base_score))
          ? Number(rf.cvss_base_score)
          : null;
      const ver =
        rf.cvss_version === '4.0'
          ? '4.0'
          : rf.cvss_version === '3.0'
            ? '3.0'
            : rf.cvss_version === '2.0'
              ? '2.0'
              : '3.1';
      const srcUrl = extractUrls(rf.source_url).find(isHttps);
      const srcId = srcUrl ? regUrlToSource.get(regNormalizeUrl(srcUrl)) : undefined;
      const fallback: Vulnerability = {
        id: cveToId(cve),
        cve_id: cve,
        cve_status: 'published',
        nvd_status: 'unknown',
        summary: rf.cwe_text ?? '(NVD-post ej hämtad)',
        summary_sv: null,
        cwe_ids: uniq([...(rf.cwe_text ?? '').matchAll(/CWE-\d+/g)].map((m) => m[0])),
        cvss:
          score !== null && rf.cvss_vector
            ? [
                {
                  version: ver,
                  vector: rf.cvss_vector,
                  base_score: score,
                  base_severity: null,
                  source: 'register (CISA CSAF/CNA via arbetsbok)',
                  type: 'Secondary',
                },
              ]
            : [],
        epss: null,
        kev: {
          listed: rf.kev === 'Ja',
          date_added: rf.kev === 'Ja' ? (rf.kev_date_added ?? null) : null,
          due_date: null,
          known_ransomware_use: null,
          vulnerability_name: null,
          catalog_version: null,
          checked_at: null,
        },
        exploitation_evidence: [],
        cna: null,
        published_at: null,
        last_modified_at: null,
        references: [],
        advisory_ids: [],
        source_ids: srcId ? [srcId] : [],
        verification_status: 'needs_review',
        threat_intel: reg ? threatIntelFor(cve, reg, regUrlToSource, projectIdFor) : null,
        register_cvss: {
          version: rf.cvss_version ?? 'okänd',
          base_score: score,
          vector: rf.cvss_vector ?? null,
          cwe_text: rf.cwe_text ?? null,
        },
        enrichment: { nvd_fetched_at: null, epss_fetched_at: null, kev_checked_at: null },
        review: {
          reviewed_at: '2026-11-07',
          reviewer: 'registerimport',
          notes: [
            'NVD-post ej hämtad i projektet; CVSS/CWE kommer från registrets Sårbarheter-blad.',
          ],
          history: [],
        },
      };
      vulnerabilities.push(fallback);
      vulnIds.add(fallback.id);
      continue;
    }
    const raw = readJson<{
      vulnerabilities?: {
        cve: {
          id: string;
          sourceIdentifier?: string;
          published?: string;
          lastModified?: string;
          vulnStatus?: string;
          descriptions?: { lang: string; value: string }[];
          metrics?: Record<
            string,
            {
              source: string;
              type: 'Primary' | 'Secondary';
              cvssData: {
                version: string;
                vectorString: string;
                baseScore: number;
                baseSeverity?: string;
              };
              baseSeverity?: string;
            }[]
          >;
          weaknesses?: { description: { lang: string; value: string }[] }[];
          references?: { url: string; tags?: string[] }[];
          cisaExploitAdd?: string;
        };
      }[];
    }>(file);
    const rec = raw.vulnerabilities?.[0]?.cve;
    if (!rec || rec.id !== cve)
      throw new Error(`NVD-cache för ${cve} saknar post eller har fel ID.`);
    const nvdSrcId = `src-nvd-${cve.toLowerCase()}`;
    if (!sourceIds.has(nvdSrcId)) {
      const fetched = fileMtimeIso(file).slice(0, 10);
      const nvdSrc: Source = {
        id: nvdSrcId,
        url: `https://nvd.nist.gov/vuln/detail/${cve}`,
        title: `NVD: ${cve}`,
        publisher: `NIST NVD (CNA: ${rec.sourceIdentifier ?? 'okänd'})`,
        source_type: 'database',
        is_primary: true,
        published_at: rec.published ? rec.published.slice(0, 10) : null,
        last_checked_at: fetched,
        last_verified_at: fetched,
        availability: 'ok',
        http_status: 200,
        supports_claims: [
          { entity_id: cveToId(cve), field: '*', note: 'Hämtad via NVD CVE API 2.0 (data:enrich)' },
        ],
        access_note: null,
        notes: `NVD-status ${rec.vulnStatus ?? 'okänd'}; lastModified ${rec.lastModified ?? 'okänt'}.`,
        document_sha256: null,
        fetched_at: fetched,
        final_url: null,
        interpretation_text: null,
        register_source_key: null,
      };
      sources.push(nvdSrc);
      sourcesByUrl.set(normalizeUrl(nvdSrc.url), nvdSrc);
      sourceIds.add(nvdSrcId);
    }
    const ov = vulnOverrides[cve] ?? {};
    const cvss: Vulnerability['cvss'] = [];
    for (const [key, list] of Object.entries(rec.metrics ?? {})) {
      const version =
        key === 'cvssMetricV40'
          ? '4.0'
          : key === 'cvssMetricV31'
            ? '3.1'
            : key === 'cvssMetricV30'
              ? '3.0'
              : key === 'cvssMetricV2'
                ? '2.0'
                : null;
      if (!version) continue; // t.ex. ssvcV203 – ej CVSS
      for (const m of list) {
        if (!m.cvssData) continue;
        const sev = (m.cvssData.baseSeverity ??
          m.baseSeverity ??
          null) as Vulnerability['cvss'][number]['base_severity'];
        cvss.push({
          version,
          vector: m.cvssData.vectorString,
          base_score: m.cvssData.baseScore,
          base_severity: sev,
          source: m.source,
          type: m.type,
        });
      }
    }
    const nvdStatusRaw = rec.vulnStatus ?? 'unknown';
    const nvdStatus = (
      [
        'Received',
        'Awaiting Analysis',
        'Undergoing Analysis',
        'Analyzed',
        'Modified',
        'Deferred',
        'Rejected',
      ].includes(nvdStatusRaw)
        ? nvdStatusRaw
        : 'unknown'
    ) as Vulnerability['nvd_status'];
    const epss = epssByCve.get(cve);
    const kev = kevByCve.get(cve);
    const desc =
      rec.descriptions
        ?.find((d) => d.lang === 'en')
        ?.value?.replace(/\s+/g, ' ')
        .trim() ?? '(beskrivning saknas)';
    const v: Vulnerability = {
      id: cveToId(cve),
      cve_id: cve,
      cve_status: nvdStatus === 'Rejected' ? 'rejected' : 'published',
      nvd_status: nvdStatus,
      summary: desc,
      summary_sv: ov.summary_sv ?? null,
      cwe_ids: uniq((rec.weaknesses ?? []).flatMap((w) => w.description.map((d) => d.value))),
      cvss,
      epss: epss
        ? {
            score: Number(epss.epss),
            percentile: Number(epss.percentile),
            date: epss.date,
            fetched_at: fileMtimeIso(p('sources', 'enrichment', 'epss.json')),
          }
        : null,
      kev: {
        listed: Boolean(kev),
        date_added: kev?.dateAdded ?? null,
        due_date: kev?.dueDate ?? null,
        known_ransomware_use:
          (kev?.knownRansomwareCampaignUse as 'Known' | 'Unknown' | undefined) ?? null,
        vulnerability_name: kev?.vulnerabilityName ?? null,
        catalog_version: kevRaw.catalogVersion ?? null,
        checked_at: kevChecked.has(cve) ? (kevRaw.fetched_at ?? null) : null,
      },
      exploitation_evidence: ov.exploitation_evidence ?? [],
      cna: rec.sourceIdentifier ?? null,
      published_at: toIsoDateTime(rec.published),
      last_modified_at: toIsoDateTime(rec.lastModified),
      references: uniq((rec.references ?? []).map((r) => r.url))
        .filter((u) => u.startsWith('https://'))
        .map((u) => ({
          url: u,
          tags: uniq(
            (rec.references ?? []).filter((r) => r.url === u).flatMap((r) => r.tags ?? []),
          ),
        })),
      advisory_ids: ov.advisory_ids ?? [],
      source_ids: [
        `src-nvd-${cve.toLowerCase()}`,
        ...(kev ? ['src-cisa-kev'] : []),
        ...(epss ? ['src-first-epss'] : []),
      ].filter((id) => sourceIds.has(id)),
      verification_status: ov.verification_status ?? (regRow ? 'verified_primary' : 'needs_review'),
      threat_intel: reg ? threatIntelFor(cve, reg, regUrlToSource, projectIdFor) : null,
      register_cvss: regRow
        ? {
            version: regRow.fields.cvss_version ?? 'okänd',
            base_score: Number.isNaN(Number(regRow.fields.cvss_base_score))
              ? null
              : Number(regRow.fields.cvss_base_score),
            vector: regRow.fields.cvss_vector ?? null,
            cwe_text: regRow.fields.cwe_text ?? null,
          }
        : null,
      enrichment: {
        nvd_fetched_at: fileMtimeIso(file),
        epss_fetched_at: epss ? fileMtimeIso(p('sources', 'enrichment', 'epss.json')) : null,
        kev_checked_at: kevRaw.fetched_at ?? null,
      },
      review: ov.review ?? { reviewed_at: null, reviewer: null, notes: [], history: [] },
    };
    vulnerabilities.push(v);
    vulnIds.add(v.id);
  }

  /* --- Bulletiner --- */
  const advisories: Advisory[] = advisoriesIn.map((a) => ({
    ...a,
    history: a.history ?? [],
    source_ids: a.source_ids ?? [],
    review: a.review ?? { reviewed_at: null, reviewer: null, notes: [], history: [] },
  }));
  if (reg)
    advisories.push(
      ...buildRegisterAdvisories(
        reg,
        csafIndex,
        regUrlToSource,
        new Set(advisories.map((a) => a.id)),
      ),
    );
  const advisoryIds = new Set(advisories.map((a) => a.id));
  const advisoryIdByKey = new Map(advisories.map((a) => [a.advisory_id.toUpperCase(), a.id]));

  /* --- Matchningar --- */
  const matches: ProductVulnerabilityMatch[] = matchesIn.map((m) => {
    const { cve_id, ...rest } = m;
    const vulnerability_id = cveToId(cve_id);
    if (!vulnIds.has(vulnerability_id))
      throw new Error(`Match ${m.id} refererar okänd CVE ${cve_id}`);
    if (rest.advisory_id && !advisoryIds.has(rest.advisory_id))
      throw new Error(`Match ${m.id} refererar okänd bulletin ${rest.advisory_id}`);
    return { ...rest, vulnerability_id };
  });
  // Registerrelationer (Sårbarheter-bladet): befintliga kuraterade matchningar vinner och annoteras
  const registerMatchStats = {
    annotated: 0,
    created: 0,
    verified_primary: 0,
    corroborated: 0,
    needs_review: 0,
  };
  if (reg) {
    const byKey = new Map(matches.map((m) => [`${m.product_family_id}|${m.vulnerability_id}`, m]));
    for (const r of reg.sheets.vulnerabilities.records) {
      const f = r.fields;
      const pid = projectIdFor(g(f, 'register_id')!);
      if (!pid || !pid.startsWith('pf-')) continue; // protokoll får aldrig CVE-matchningar
      const vid = cveToId(g(f, 'cve_id')!);
      const regRow = reg.byRegisterId.get(g(f, 'register_id')!);
      const bulletin =
        regRow && /^ICSM?A-/i.test(g(regRow.fields, 'origin_reference') ?? '')
          ? g(regRow.fields, 'origin_reference')
          : (/icsm?a-[0-9-]+/i.exec(g(f, 'source_url') ?? '')?.[0]?.toUpperCase() ?? null);
      const verdict = verifyRelationAgainstCsaf(
        bulletin,
        g(f, 'cve_id')!,
        g(regRow?.fields, 'name') ?? '',
        g(f, 'affected_source_text'),
        csafIndex,
      );
      const srcUrl = extractUrls(g(f, 'source_url')).find(isHttps);
      const srcId = srcUrl ? regUrlToSource.get(regNormalizeUrl(srcUrl)) : undefined;
      const key = `${pid}|${vid}`;
      const existing = byKey.get(key);
      if (existing) {
        existing.register_relation = true;
        existing.affected_source_text = g(f, 'affected_source_text');
        existing.fixed_source_text = g(f, 'fixed_source_text');
        existing.product_link_limitation_text = g(f, 'product_link_limitation');
        existing.cwe_text = g(f, 'cwe_text');
        existing.register_verification_note = verdict.note;
        if (srcId && !existing.source_ids.includes(srcId)) existing.source_ids.push(srcId);
        registerMatchStats.annotated++;
        continue;
      }
      const advId = bulletin ? (advisoryIdByKey.get(bulletin.toUpperCase()) ?? null) : null;
      const m: ProductVulnerabilityMatch = {
        id: `match-reg-${g(f, 'register_id')!.toLowerCase()}-${g(f, 'cve_id')!.toLowerCase()}`,
        product_family_id: pid,
        vulnerability_id: vid,
        advisory_id: advId,
        component: null,
        affected_versions_text: g(f, 'affected_source_text') ?? 'Se källans produktstatus',
        version_rule: {
          type: 'source_text',
          version: null,
          version_end: null,
          text: g(f, 'affected_source_text') ?? 'versionsgräns enligt källtext',
        },
        status: 'affected',
        attack_prerequisites: null,
        attack_vector: 'unknown',
        authentication_required: 'unknown',
        user_interaction: 'unknown',
        fix: {
          available: verdict.fix_available,
          version: null,
          text: [
            g(f, 'fixed_source_text'),
            verdict.fix_text ? `CSAF remediations – ${verdict.fix_text}` : null,
          ]
            .filter(Boolean)
            .join(' · '),
          status: verdict.fix_available === 'unknown' ? 'needs_review' : 'verified_primary',
          source_ids: srcId ? [srcId] : [],
        },
        mitigation_control_ids: [],
        mitigation_text: null,
        evidence: `Registrets Sårbarheter-blad (rad ${r.row}): ${g(f, 'product_link_limitation') ?? 'CISA produktstatus'}. ${verdict.note}`,
        source_ids: srcId ? [srcId] : ['src-register-workbook'],
        verification_status: verdict.status,
        review: {
          reviewed_at: '2026-11-07',
          reviewer: 'registerimport',
          notes: ['Importerad relation; installerad enhet ej bedömd.'],
          history: [],
        },
        register_relation: true,
        affected_source_text: g(f, 'affected_source_text'),
        fixed_source_text: g(f, 'fixed_source_text'),
        product_link_limitation_text: g(f, 'product_link_limitation'),
        cwe_text: g(f, 'cwe_text'),
        register_verification_note: verdict.note,
      };
      matches.push(m);
      byKey.set(key, m);
      registerMatchStats.created++;
      if (verdict.status === 'verified_primary') registerMatchStats.verified_primary++;
      else if (verdict.status === 'corroborated_secondary') registerMatchStats.corroborated++;
      else registerMatchStats.needs_review++;
    }
    // bulletin-ID:n → vulnerabilities.advisory_ids
    for (const v of vulnerabilities) {
      const rr = registerVulnRowByCve.get(v.cve_id);
      const regRow = rr ? reg.byRegisterId.get(rr.fields.register_id!) : undefined;
      const bulletin =
        regRow && /^ICSM?A-/i.test(g(regRow.fields, 'origin_reference') ?? '')
          ? g(regRow.fields, 'origin_reference')!
          : null;
      const advId = bulletin ? advisoryIdByKey.get(bulletin.toUpperCase()) : undefined;
      if (advId && !v.advisory_ids.includes(advId)) v.advisory_ids.push(advId);
    }
  }

  /* --- Katalogposter --- */
  const claims: Claim[] = [];
  const productFamilies: ProductFamily[] = [];
  const protocolServices: ProtocolService[] = [];

  const attachRegister = (entity: ProductFamily | ProtocolService) => {
    if (!reg) return;
    const rid = registerIdFor.get(entity.id);
    const rr = rid ? reg.byRegisterId.get(rid) : undefined;
    if (!rid || !rr) return;
    entity.register = registerInfoFor(reg, rr);
    entity.credentials = credentialsFor(reg.setupByRegisterId.get(rid), rr, regUrlToSource);
    entity.setup_documentation = setupDocFor(reg.setupByRegisterId.get(rid), rr, regUrlToSource);
    entity.review_findings = reviewFindingsFor(reg.reviewByRegisterId.get(rid), regUrlToSource);
    const scopeAlias = g(rr.fields, 'scope_alias');
    if (scopeAlias && scopeAlias !== entity.name && !entity.aliases.includes(scopeAlias))
      entity.aliases.push(scopeAlias);
    const flags = new Set(entity.data_quality_flags);
    if (entity.setup_documentation?.exact_manual_missing) flags.add('setup_manual_unverified');
    if (
      entity.kind === 'product_family' &&
      /^ej verifierat/i.test(entity.credentials.account_name_text ?? '')
    )
      flags.add('account_name_unverified');
    if (entity.credentials.initial_password_type === 'unknown_unverified')
      flags.add('initial_password_type_unknown');
    if (reg.conflicts.some((c) => c.register_id === rid)) flags.add('register_conflict');
    // Radgranskningens "Öppen – lokal inventering återstår" gäller alla poster och visas i registersektionen,
    // den sätter inte needs_human_review (som är reserverad för påståenden som kräver källgranskning).
    entity.data_quality_flags = [...flags];
    // källor
    const extra = [
      entity.credentials.account_source_id,
      entity.credentials.password_status_source_id,
      entity.setup_documentation?.source_id,
      ...entity.review_findings.flatMap((x) => x.source_ids),
    ].filter((x): x is string => Boolean(x));
    entity.source_ids = uniq([...entity.source_ids, 'src-register-workbook', ...extra]);
    // registerkontroller (K-koder) → kontroll-ID
    const kControls = controls
      .filter((c) => c.register_code && entity.register!.control_codes.includes(c.register_code))
      .map((c) => c.id);
    const byId = new Map(controls.map((c) => [c.id, c]));
    entity.control_ids = uniq([...entity.control_ids, ...kControls]).sort(
      (a, b) => byId.get(a)!.order_hint - byId.get(b)!.order_hint,
    );
  };

  for (const r of wb.records) {
    const ov = overrides[String(r.row)];
    if (!ov) throw new Error(`Saknar override/ID för rad ${r.row} (${r.fields.name})`);
    const base = buildCatalogBase(r, ov, wb.data_sheet, rowSources.get(r.row)!, workbookSourceId);
    if (r.fields.category === 'Tjänst') {
      protocolServices.push(buildProtocol(r, ov, base, controls));
    } else {
      const pf = buildProduct(
        r,
        ov,
        base,
        matches,
        vulnerabilities,
        advisories,
        controls,
        observations,
        vulnIds,
      );
      productFamilies.push(pf);
    }
    for (const c of ov.claims ?? []) {
      claims.push({
        id: c.id,
        entity_id: ov.id,
        field: c.field,
        text: c.text,
        status: c.status,
        source_ids: c.source_ids,
        conflict_note: c.conflict_note ?? null,
        reviewed_at: '2026-11-07',
        history: [],
      });
    }
  }
  // Nya poster från registret (origin = Ny)
  if (reg) {
    for (const rr of reg.sheets.register.records) {
      if (g(rr.fields, 'origin') === 'Original') continue;
      const pid = projectIdFor(g(rr.fields, 'register_id')!);
      if (!pid) throw new Error(`register_id_map saknar ${g(rr.fields, 'register_id')}`);
      const isSvc = g(rr.fields, 'category') === 'Tjänst';
      const vendorId = regVendors[g(rr.fields, 'register_id')!]?.vendor_id;
      if (!isSvc && (!vendorId || !vendors.some((v) => v.id === vendorId)))
        throw new Error(
          `register_vendors.json saknar giltig vendor_id för ${rr.fields.register_id}`,
        );
      const f = rr.fields;
      const docUrl = extractUrls(g(f, 'documentation_url')).find(isHttps) ?? null;
      const secUrl = extractUrls(g(f, 'security_source_url')).find(isHttps) ?? null;
      const docSrc = docUrl
        ? (sources.find((s) => s.id === regUrlToSource.get(regNormalizeUrl(docUrl))) ?? null)
        : null;
      const secSrc = secUrl
        ? (sources.find((s) => s.id === regUrlToSource.get(regNormalizeUrl(secUrl))) ?? null)
        : null;
      const synthetic: WorkbookRecord = {
        row: rr.row,
        fields: {
          category: g(f, 'category'),
          name: g(f, 'name'),
          function: g(f, 'scope_alias') ?? g(f, 'name'),
          shodan_query: null,
          risk_type: g(f, 'exposure_risk'),
          risk_explanation: g(f, 'uncertainty'),
          cve_bulletin: g(f, 'cve_selection'),
          affected_firmware: g(f, 'versions_guidance'),
          fix: g(f, 'fix_guidance'),
          patch_level: null,
          defensive_control: g(f, 'risk_controls'),
          documentation_url: docUrl,
          documentation_level: g(f, 'documentation_limitation'),
          security_source_url: secUrl,
          priority_if_exposed: g(f, 'priority'),
        },
      };
      const prof = categoryProfiles[g(f, 'category') ?? ''];
      const ovNew: RowOverride = {
        id: pid,
        vendor_id: vendorId,
        aliases: ((a) => (a && a !== g(f, 'name') ? [a] : []))(g(f, 'scope_alias')),
        doc_level: inferDocLevel(g(f, 'documentation_limitation') ?? ''),
        doc_product_specific:
          Boolean(docUrl) &&
          !/ej verifierad|portal|ingång/i.test(g(f, 'documentation_limitation') ?? ''),
        ot_impact: prof
          ? { level: prof.ot_impact, basis: prof.basis }
          : {
              level: 'unknown',
              basis: `Kategorin "${g(f, 'category')}" saknar profil i category_profiles.json.`,
            },
        control_ids: [],
      };
      const base = buildCatalogBase(
        synthetic,
        ovNew,
        'Register',
        { doc: docSrc, sec: secSrc },
        'src-register-workbook',
      );
      base.original = {
        sheet: 'Register',
        row: rr.row,
        values: Object.fromEntries(
          Object.entries(reg.sheets.register.column_map).map(([header, key]) => [
            header,
            f[key] ?? null,
          ]),
        ),
      };
      base.provenance = Object.entries(reg.sheets.register.column_map)
        .filter(([, key]) => g(f, key) !== null)
        .map(([header, key]) => ({
          sheet: 'Register',
          row: rr.row,
          column: columnLetterForKey(reg, key),
          header,
        }));
      base.discovery_heuristic = {
        query: null,
        caveat: DISCOVERY_CAVEAT,
        purpose: 'authorized_inventory_only',
      };
      base.data_quality_flags = base.data_quality_flags.filter((x) => x !== 'generic_control_text');
      if (isSvc) protocolServices.push(buildProtocol(synthetic, ovNew, base, controls));
      else
        productFamilies.push(
          buildProduct(
            synthetic,
            ovNew,
            base,
            matches,
            vulnerabilities,
            advisories,
            controls,
            observations,
            vulnIds,
          ),
        );
    }
    for (const e of [...productFamilies, ...protocolServices]) attachRegister(e);
    // Risk omräknas efter att registerdata (hotunderlag) kopplats
    for (const pf of productFamilies) {
      const my = matches.filter((m) => m.product_family_id === pf.id);
      const myV = my
        .map((m) => vulnerabilities.find((v) => v.id === m.vulnerability_id))
        .filter((v): v is Vulnerability => Boolean(v));
      pf.match_ids = my.map((m) => m.id);
      pf.advisory_ids = uniq([
        ...pf.advisory_ids,
        ...my.map((m) => m.advisory_id).filter((x): x is string => Boolean(x)),
      ]);
      pf.source_ids = uniq([...pf.source_ids, ...my.flatMap((m) => m.source_ids)]);
      if (my.length > 0)
        pf.data_quality_flags = pf.data_quality_flags.filter((x) => x !== 'missing_cve_reference');
      if (
        my.some(
          (m) =>
            m.verification_status === 'verified_primary' ||
            m.verification_status === 'corroborated_secondary',
        )
      )
        pf.data_quality_flags = pf.data_quality_flags.filter((x) => x !== 'missing_primary_source');
      if (my.some((m) => m.version_rule.type === 'source_text'))
        pf.data_quality_flags = uniq([...pf.data_quality_flags, 'unknown_version_boundary']);
      const ovRisk = overrides[String(pf.original.row)];
      const prof = categoryProfiles[pf.category];
      pf.risk = assessRisk(
        pf,
        my,
        myV,
        ovRisk && ovRisk.id === pf.id
          ? ovRisk
          : {
              id: pf.id,
              ot_impact: prof ? { level: prof.ot_impact, basis: prof.basis } : undefined,
            },
      );
      if (my.length > 0) pf.verification_status = minStatus(my.map((m) => m.verification_status));
    }
    // Konflikter → claims
    for (const c of reg.conflicts) {
      const pid = projectIdFor(c.register_id);
      if (!pid) continue;
      claims.push({
        id: `claim-register-conflict-${c.register_id.toLowerCase()}-${c.type.replace(/_/g, '-')}`,
        entity_id: pid,
        field: c.type === 'cve_set_difference' ? 'match_ids' : 'name',
        text:
          c.type === 'cve_set_difference'
            ? `Registret och projektets kuraterade matchningar skiljer sig: endast i registret ${(c.only_in_register as string[]).join(', ') || '–'}; endast i projektet ${(c.only_in_project as string[]).join(', ') || '–'}. Projektets manuella bedömning behålls; registrets relationer har lagts till separat.`
            : `Namnavvikelse: projekt "${c.project_name}" vs register "${c.register_name}".`,
        status: 'disputed',
        source_ids: ['src-register-workbook', 'src-workbook'],
        conflict_note: String(c.resolution ?? 'Kräver manuell granskning.'),
        reviewed_at: '2026-11-07',
        history: [],
      });
    }
  }

  // Auto-claims: overifierade fixversioner per match
  for (const m of matches) {
    if (m.id.startsWith('match-reg-')) continue; // registerrelationer: fixtext visas direkt på matchningen
    if (m.fix.status === 'needs_review' || m.fix.status === 'unknown') {
      claims.push({
        id: `claim-${m.id}-fix`,
        entity_id: m.product_family_id,
        field: `matches.${m.id}.fix`,
        text: m.fix.text ?? 'Fixuppgift saknas.',
        status: m.fix.status,
        source_ids: m.fix.source_ids,
        conflict_note: null,
        reviewed_at: m.review.reviewed_at,
        history: [],
      });
    }
  }
  // Koppla claim_ids till poster
  for (const pf of productFamilies)
    pf.claim_ids = claims.filter((c) => c.entity_id === pf.id).map((c) => c.id);
  for (const svc of protocolServices)
    svc.claim_ids = claims.filter((c) => c.entity_id === svc.id).map((c) => c.id);

  /* --- Manifest --- */
  const categories = uniq([
    ...productFamilies.map((x) => x.category),
    ...protocolServices.map((x) => x.category),
  ]);
  const manifest: Manifest = {
    dataset_tier: 'public',
    schema_version: SCHEMA_VERSION,
    generated_at: nowIso(),
    workbook: {
      filename: wb.filename,
      sha256: wb.sha256,
      sheets: wb.sheets.map((s) => s.name),
      data_sheet: wb.data_sheet,
      header_row: wb.header_row,
      data_rows: wb.records.length,
    },
    counts: {
      total_entries: productFamilies.length + protocolServices.length,
      product_families: productFamilies.length,
      protocol_services: protocolServices.length,
      categories: categories.length,
      vendors: vendors.length,
      vulnerabilities: vulnerabilities.length,
      advisories: advisories.length,
      matches: matches.length,
      controls: controls.length,
      sources: sources.length,
      observations: observations.length,
      claims: claims.length,
      entries_with_cve_reference: wb.records.filter((r) => r.fields.cve_bulletin).length,
      entries_with_security_source_url: wb.records.filter((r) => r.fields.security_source_url)
        .length,
      kev_listed_vulnerabilities: vulnerabilities.filter((v) => v.kev.listed).length,
      register_entries: reg ? reg.sheets.register.records.length : 0,
      register_original: reg
        ? reg.sheets.register.records.filter((r) => r.fields.origin === 'Original').length
        : 0,
      register_new: reg
        ? reg.sheets.register.records.filter((r) => r.fields.origin !== 'Original').length
        : 0,
      register_cve_unique: registerCves.length,
      register_relations: reg ? reg.sheets.vulnerabilities.records.length : 0,
      link_checks: linkChecks.length,
      threat_intel: vulnerabilities.filter((v) => v.threat_intel).length,
    },
    imports: reg
      ? [
          {
            file: reg.report.file,
            sha256: reg.report.sha256,
            imported_at: reg.report.imported_at,
            import_version: reg.report.import_version,
            sheets: reg.report.sheets,
            counts: {
              ...(reg.report.counts as Record<
                string,
                number | string | string[] | Record<string, number>
              >),
              register_matches_annotated: registerMatchStats.annotated,
              register_matches_created: registerMatchStats.created,
              register_matches_verified_primary: registerMatchStats.verified_primary,
              register_matches_corroborated: registerMatchStats.corroborated,
              register_matches_needs_review: registerMatchStats.needs_review,
            },
          },
        ]
      : [],
    files: { ...DATA_FILES },
    notes: [
      'Publik produkt- och hotkunskapsbas. Innehåller inga anläggningsunika uppgifter.',
      'Frånvaro av CVE-referens är inte bevis för frånvaro av sårbarheter.',
      '"P1 vid publik åtkomst" i arbetsboken är en villkorlig inventeringssignal, inte en verifierad exponering.',
    ],
  };

  // Zod-parse fyller defaults (t.ex. register_relation=false) så att publika filer är kompletta
  return Dataset.parse({
    manifest,
    vendors,
    product_families: productFamilies,
    protocol_services: protocolServices,
    vulnerabilities,
    advisories,
    matches,
    controls,
    sources,
    observations,
    claims,
    link_checks: linkChecks,
  });
}

function columnLetterForKey(reg: RegisterData, key: string): string {
  const headers = reg.sheets.register.headers;
  const header = Object.entries(reg.sheets.register.column_map).find(([, k]) => k === key)?.[0];
  const idx = header ? headers.indexOf(header) : -1;
  if (idx < 0) return 'A';
  let n = idx + 1;
  let s = '';
  while (n > 0) {
    const rem = (n - 1) % 26;
    s = String.fromCharCode(65 + rem) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

/* ------------------------------------------------------------------ */
/* Byggare                                                             */
/* ------------------------------------------------------------------ */

type CatalogBase = Omit<
  ProductFamily,
  | 'id'
  | 'kind'
  | 'vendor_id'
  | 'hardware_revisions'
  | 'lifecycle'
  | 'ot_role'
  | 'ot_consequence'
  | 'secure_configuration_notes'
  | 'unexpanded_cve_ranges'
  | 'protocol_service_ids'
>;

function buildCatalogBase(
  r: WorkbookRecord,
  ov: RowOverride,
  sheet: string,
  rowSrc: { doc: Source | null; sec: Source | null },
  workbookSourceId: string,
): CatalogBase {
  const f = r.fields;
  const provenance = (Object.keys(HEADER_COLUMNS) as FieldKey[])
    .filter((k) => f[k] !== null)
    .map((k) => ({ sheet, row: r.row, column: HEADER_COLUMNS[k], header: headerFor(k) }));
  const original = {
    sheet,
    row: r.row,
    values: Object.fromEntries(
      (Object.keys(HEADER_COLUMNS) as FieldKey[]).map((k) => [headerFor(k), f[k]]),
    ),
  };
  const documentation: CatalogBase['documentation'] = rowSrc.doc
    ? [
        {
          url: rowSrc.doc.url,
          level: ov.doc_level ?? inferDocLevel(f.documentation_level ?? ''),
          level_text: f.documentation_level ?? '(saknas)',
          product_specific:
            ov.doc_product_specific ??
            !/branschguide|ej exakt|ej verifierad|ej säkerställd|ej alla/i.test(
              f.documentation_level ?? '',
            ),
          source_id: rowSrc.doc.id,
        },
      ]
    : [];
  const flags: DataQualityFlag[] = [];
  if (f.defensive_control?.startsWith(GENERIC_CONTROL_PREFIX)) flags.push('generic_control_text');
  if ((ov.doc_level ?? inferDocLevel(f.documentation_level ?? '')) === 'industry_guide')
    flags.push('industry_guide_only');
  if (f.priority_if_exposed) flags.push('conditional_priority_only');
  if (!f.patch_level || /uppgift saknas/i.test(f.patch_level)) flags.push('patch_level_unknown');

  return {
    name: f.name!,
    aliases: ov.aliases ?? [],
    category: f.category ?? 'Okänd',
    function_text: f.function!,
    description: null,
    documentation,
    discovery_heuristic: {
      query: f.shodan_query,
      caveat: DISCOVERY_CAVEAT,
      purpose: 'authorized_inventory_only',
    },
    risk_summary: {
      type_text: f.risk_type,
      explanation_text: f.risk_explanation,
      cve_text: f.cve_bulletin,
      affected_firmware_text: f.affected_firmware,
      fix_text: f.fix,
      patch_level_text: f.patch_level,
      control_text: f.defensive_control,
      legacy_priority_text: f.priority_if_exposed,
    },
    control_ids: [],
    advisory_ids: [],
    match_ids: [],
    observation_ids: [],
    claim_ids: [],
    risk: placeholderRisk(),
    data_quality_flags: flags,
    provenance,
    original,
    verification_status: 'needs_review',
    register: null,
    credentials: null,
    setup_documentation: null,
    review_findings: [],
    source_ids: uniq(
      [workbookSourceId, rowSrc.doc?.id, rowSrc.sec?.id].filter((x): x is string => Boolean(x)),
    ),
    review: {
      reviewed_at: '2026-11-07',
      reviewer: 'projektgranskning',
      notes: [],
      history: [
        {
          date: '2026-11-07',
          status: null,
          summary: 'Migrerad från arbetsboken (2026-11-07) med bevarade originalfält.',
        },
      ],
    },
  };
}

function headerFor(k: FieldKey): string {
  const map: Record<FieldKey, string> = {
    category: 'Kategori',
    name: 'System / produktfamilj',
    function: 'Funktion',
    shodan_query: 'Shodan-sökord (komplettera med net:...)',
    risk_type: 'Sårbarhetstyp / klass',
    risk_explanation: 'Vad risktypen innebär (ej exploitinstruktion)',
    cve_bulletin: 'CVE / bulletin (urval)',
    affected_firmware: 'Berörd firmware / modell',
    fix: 'Fix / senaste offentlig uppgift',
    patch_level: 'Patchningsgrad / urval',
    defensive_control: 'Rekommenderad defensiv kontroll',
    documentation_url: 'Konfigurationsdokumentation (URL)',
    documentation_level: 'Dokumentnivå / begränsning',
    security_source_url: 'Källa till CVE/säkerhetsuppgift (URL)',
    priority_if_exposed: 'Prio vid publik exponering',
  };
  return map[k];
}

function inferDocLevel(text: string): ProductFamily['documentation'][number]['level'] {
  const t = text.toLowerCase();
  if (t.includes('branschguide') || t.includes('branschstandard')) return 'industry_guide';
  if (t.includes('hardening')) return 'hardening_guide';
  if (t.includes('bulletin')) return 'bulletin_portal';
  if (t.includes('manual')) return 'product_manual';
  if (t.includes('support') || t.includes('dokumentsök') || t.includes('nedladdningar'))
    return 'vendor_support';
  if (t.includes('security') || t.includes('säkerhet') || t.includes('cyber'))
    return 'security_guidance';
  if (t.includes('opc foundation') || t.includes('standard')) return 'standard';
  return 'other';
}

const CATEGORY_DEFAULT_CONTROLS: Partial<Record<string, string[]>> = {
  PLC: ['ctl-protect-engineering-access'],
  'PLC/HMI': ['ctl-protect-engineering-access'],
  DCS: ['ctl-protect-engineering-access'],
  RTU: ['ctl-protect-engineering-access'],
  NAS: ['ctl-backup-restore'],
  Passer: ['ctl-least-privilege-accounts'],
  Kamera: ['ctl-change-default-credentials'],
  Gateway: ['ctl-monitor-remote-service', 'ctl-disable-unused-services'],
  Kyla: ['ctl-https-strict-mode'],
  BMS: ['ctl-least-privilege-accounts'],
  SCADA: ['ctl-least-privilege-accounts', 'ctl-backup-restore'],
  HMI: ['ctl-https-strict-mode'],
  OPC: ['ctl-secure-protocol-features'],
  Energi: ['ctl-cloud-not-inbound'],
  Ventilation: ['ctl-cloud-not-inbound'],
  IoT: ['ctl-cloud-not-inbound'],
  Kraft: ['ctl-least-privilege-accounts'],
  Tjänst: ['ctl-protocol-firewall-allowlist'],
};
const UNIVERSAL_CONTROLS = [
  'ctl-asset-version-verification',
  'ctl-no-public-admin',
  'ctl-network-segmentation',
  'ctl-secure-remote-access',
  'ctl-logging-monitoring',
  'ctl-vendor-hardening-guide',
];

function controlIdsFor(
  r: WorkbookRecord,
  ov: RowOverride,
  controls: Control[],
  matchControls: string[],
): string[] {
  const t = (r.fields.defensive_control ?? '').toLowerCase();
  const fromText: string[] = [];
  if (/uppdatera|firmware|fw/.test(t)) fromText.push('ctl-vendor-firmware-update');
  if (/lösenord|konton|unika konton|servicekonton|roll/.test(t))
    fromText.push('ctl-least-privilege-accounts');
  if (/standardlösenord|byt/.test(t)) fromText.push('ctl-change-default-credentials');
  if (/https|tls|strict mode/.test(t)) fromText.push('ctl-https-strict-mode');
  if (/inaktivera|stäng/.test(t)) fromText.push('ctl-disable-unused-services');
  if (/eol|avveckla|utbyte/.test(t)) fromText.push('ctl-eol-replacement');
  if (/cip security|secure ads|signering|kryptering/.test(t))
    fromText.push('ctl-secure-protocol-features');
  if (/fjärrservice|fjärrtjänst/.test(t)) fromText.push('ctl-monitor-remote-service');
  if (/backup/.test(t)) fromText.push('ctl-backup-restore');
  const all = uniq([
    ...UNIVERSAL_CONTROLS,
    ...(CATEGORY_DEFAULT_CONTROLS[r.fields.category ?? ''] ?? []),
    ...fromText,
    ...(ov.control_ids ?? []),
    ...matchControls,
  ]);
  const byId = new Map(controls.map((c) => [c.id, c]));
  for (const id of all) if (!byId.has(id)) throw new Error(`Rad ${r.row}: okänd kontroll ${id}`);
  return all.sort((a, b) => byId.get(a)!.order_hint - byId.get(b)!.order_hint);
}

function placeholderRisk(): RiskAssessment {
  const u = { level: 'unknown' as const, basis: 'ej beräknad', source_ids: [] };
  return {
    threat: u,
    severity: u,
    relevance: u,
    exposure: { level: 'unknown', basis: 'ej beräknad', source_ids: [] },
    ot_impact: u,
    mitigation_feasibility: u,
    data_quality: u,
    recommended_action: 'monitor',
    rationale: 'ej beräknad',
    method_version: 'risk-method-1.0',
  };
}

function buildProduct(
  r: WorkbookRecord,
  ov: RowOverride,
  base: CatalogBase,
  matches: ProductVulnerabilityMatch[],
  vulns: Vulnerability[],
  advisories: Advisory[],
  controls: Control[],
  observations: Observation[],
  vulnIds: Set<string>,
): ProductFamily {
  const myMatches = matches.filter((m) => m.product_family_id === ov.id);
  const vulnById = new Map(vulns.map((v) => [v.id, v]));
  const myVulns = myMatches
    .map((m) => (m.vulnerability_id ? vulnById.get(m.vulnerability_id) : undefined))
    .filter((v): v is Vulnerability => Boolean(v));
  const advisoryIds = uniq([
    ...myMatches.map((m) => m.advisory_id).filter((x): x is string => Boolean(x)),
    ...(r.row === 47 || r.row === 12 ? ['adv-siemens-ssa-568427'] : []),
  ]).filter((id) => advisories.some((a) => a.id === id));
  const matchControls = uniq(myMatches.flatMap((m) => m.mitigation_control_ids));
  const controlIds = controlIdsFor(r, ov, controls, matchControls);
  const observationIds = observations.filter((o) => o.subject_ids.includes(ov.id)).map((o) => o.id);
  const ranges = (ov.unexpanded_cve_ranges ?? []).map((rg) => {
    const allVerified =
      rg.verified_ids.length > 0 && rg.verified_ids.every((id) => vulnIds.has(id));
    return { ...rg, expanded: rg.expanded && allVerified };
  });
  // Intervall i CVE-texten utan override → oexpanderat
  const rangeInText = /CVE-\d{4}-\d+[–-]\d+/.exec(r.fields.cve_bulletin ?? '');
  if (rangeInText && ranges.length === 0) {
    const [, start, endSuffix] = /(CVE-\d{4}-\d+)[–-](\d+)/.exec(rangeInText[0]) ?? [];
    if (start && endSuffix)
      ranges.push({
        text: rangeInText[0],
        start,
        end: `${start.slice(0, start.lastIndexOf('-') + 1)}${endSuffix}`,
        expanded: false,
        verified_ids: [],
        note: 'Intervall ur arbetsboken – inte expanderat eftersom ID:n inte verifierats.',
      });
  }

  const flags = [...base.data_quality_flags];
  if (myMatches.length === 0) flags.push('missing_cve_reference');
  const affectedMatches = myMatches.filter(
    (m) => m.status === 'affected' || m.status === 'under_investigation',
  );
  if (affectedMatches.some((m) => m.version_rule.type === 'unknown'))
    flags.push('unknown_version_boundary');
  if (myMatches.length === 0 && r.fields.cve_bulletin && !r.fields.affected_firmware)
    flags.push('unknown_version_boundary');
  if (
    myMatches.some((m) => m.fix.status === 'needs_review' || m.fix.status === 'unknown') ||
    /senast|tidigare verifiering/i.test(r.fields.fix ?? '')
  )
    flags.push('unverified_fix_version');
  if (
    /senast angiven|tidigare verifiering/i.test(r.fields.fix ?? '') ||
    advisoryIds.some((id) => advisories.find((a) => a.id === id)?.status === 'interim')
  )
    flags.push('possibly_outdated');
  if (ranges.some((x) => !x.expanded)) flags.push('unexpanded_cve_range');
  const myClaims = ov.claims ?? [];
  if (
    myMatches.some((m) => m.verification_status === 'needs_review') ||
    myClaims.some((c) => c.status === 'needs_review' || c.status === 'disputed') ||
    ov.lifecycle?.eol_status === 'needs_review'
  )
    flags.push('needs_human_review');
  if (myClaims.some((c) => c.status === 'disputed')) flags.push('conflicting_sources');
  const hasPrimary =
    myMatches.some((m) => m.verification_status === 'verified_primary') ||
    Boolean(r.fields.security_source_url);
  if (!hasPrimary) flags.push('missing_primary_source');

  const vstatus: VerificationStatus =
    myMatches.length > 0
      ? minStatus(myMatches.map((m) => m.verification_status))
      : base.documentation[0]?.product_specific
        ? 'corroborated_secondary'
        : 'needs_review';

  const lifecycle: ProductFamily['lifecycle'] = ov.lifecycle
    ? {
        status: ov.lifecycle.status,
        eol_date: {
          value: ov.lifecycle.eol_date,
          status: ov.lifecycle.eol_status,
          source_ids: ['src-workbook'],
          reviewed_at: '2026-11-07',
          note: ov.lifecycle.note,
        },
        note: ov.lifecycle.note,
      }
    : {
        status: 'unknown',
        eol_date: { value: null, status: 'unknown', source_ids: [], reviewed_at: null, note: null },
        note: null,
      };

  const pf: ProductFamily = {
    id: ov.id,
    kind: 'product_family',
    vendor_id: ov.vendor_id!,
    ...base,
    control_ids: controlIds,
    advisory_ids: advisoryIds,
    match_ids: myMatches.map((m) => m.id),
    observation_ids: observationIds,
    data_quality_flags: uniq(flags),
    verification_status: vstatus,
    source_ids: uniq([...base.source_ids, ...myMatches.flatMap((m) => m.source_ids)]),
    hardware_revisions: [],
    lifecycle,
    ot_role: ov.ot_role ?? null,
    ot_consequence: ov.ot_consequence ?? null,
    secure_configuration_notes: r.fields.defensive_control ? [r.fields.defensive_control] : [],
    unexpanded_cve_ranges: ranges,
    protocol_service_ids: ov.protocol_service_ids ?? [],
  };
  pf.risk = assessRisk(pf, myMatches, myVulns, ov);
  return pf;
}

function buildProtocol(
  r: WorkbookRecord,
  ov: RowOverride,
  base: CatalogBase,
  controls: Control[],
): ProtocolService {
  const controlIds = controlIdsFor(r, ov, controls, []);
  const flags = [...base.data_quality_flags, 'missing_primary_source' as DataQualityFlag];
  const svc: ProtocolService = {
    id: ov.id,
    kind: 'protocol_service',
    ...base,
    category: 'Tjänst',
    control_ids: controlIds,
    data_quality_flags: uniq(flags),
    verification_status: 'corroborated_secondary',
    typical_use: ov.typical_use ?? r.fields.function!,
    default_ports: ov.default_ports ?? [],
    authentication: ov.authentication ?? 'unknown',
    encryption: ov.encryption ?? 'unknown',
    security_notes: ov.security_notes ?? null,
    allowed_zones: ov.allowed_zones ?? null,
    match_ids: [],
    source_ids: uniq([
      ...base.source_ids,
      ...(ov.default_ports ?? []).flatMap((pp) => pp.source_ids),
    ]),
  };
  svc.risk = assessRisk(svc, [], [], ov);
  return svc;
}

/* ------------------------------------------------------------------ */
/* Riskmetod 1.0 (se docs/RISK_METHOD.md)                              */
/* ------------------------------------------------------------------ */

const CATEGORY_OT_IMPACT: Record<string, { level: FactorLevel; basis: string }> = {
  Kyla: { level: 'high', basis: 'Kylkedja/livsmedelssäkerhet och larm.' },
  PLC: { level: 'high', basis: 'Direkt processtyrning.' },
  'PLC/HMI': { level: 'high', basis: 'Direkt processtyrning med operatörsgränssnitt.' },
  DCS: { level: 'high', basis: 'Anläggningsomfattande processtyrning.' },
  RTU: { level: 'high', basis: 'Fjärrstyrning av el-/vatteninfrastruktur.' },
  SCADA: { level: 'high', basis: 'Operatörskommandon och övervakning.' },
  Passer: { level: 'high', basis: 'Fysisk åtkomstkontroll.' },
  Kraft: { level: 'high', basis: 'Strömförsörjning.' },
  Gateway: { level: 'high', basis: 'Nätgräns mot OT.' },
  BMS: { level: 'high', basis: 'Central byggnadsstyrning.' },
  OPC: { level: 'high', basis: 'Nav mellan PLC och IT.' },
  HMI: { level: 'medium', basis: 'HMI med möjlig skrivåtkomst.' },
  Energi: { level: 'medium', basis: 'Lokal energiproduktion/värme.' },
  Ventilation: { level: 'medium', basis: 'Inomhusklimat.' },
  Kamera: { level: 'medium', basis: 'Övervakning/integritet, språngbräda.' },
  NAS: { level: 'medium', basis: 'Backup/återställning.' },
  IoT: { level: 'low', basis: 'Hem-/byggnadsautomation med begränsad räckvidd.' },
  Tjänst: { level: 'medium', basis: 'Beror på bakomliggande system.' },
};

function assessRisk(
  entity: ProductFamily | ProtocolService,
  matches: ProductVulnerabilityMatch[],
  vulns: Vulnerability[],
  ov: RowOverride,
): RiskAssessment {
  const affected = matches.filter((m) => m.status === 'affected');
  const investigating = matches.filter((m) => m.status === 'under_investigation');
  const vulnById = new Map(vulns.map((v) => [v.id, v]));
  const affectedVulns = uniq(
    affected
      .map((m) => (m.vulnerability_id ? vulnById.get(m.vulnerability_id) : undefined))
      .filter((v): v is Vulnerability => Boolean(v)),
  );
  const srcAll = uniq(matches.flatMap((m) => m.source_ids));

  // Hot
  const kev = affectedVulns.filter((v) => v.kev.listed);
  const maxEpss = Math.max(0, ...affectedVulns.map((v) => v.epss?.score ?? 0));
  let threat: RiskAssessment['threat'];
  if (kev.length > 0)
    threat = {
      level: 'high',
      basis: `Bekräftat utnyttjande: ${kev.map((v) => v.cve_id).join(', ')} finns i CISA KEV.`,
      source_ids: ['src-cisa-kev'],
    };
  else if (affectedVulns.length > 0)
    threat = {
      level: 'medium',
      basis: `Verifierade CVE-kopplingar utan KEV-notering. Högsta EPSS ${maxEpss.toFixed(3)} (${affectedVulns.find((v) => v.epss)?.epss?.date ?? 'datum saknas'}). EPSS är en sannolikhetsindikator, inte bevis.`,
      source_ids: ['src-first-epss', 'src-cisa-kev'],
    };
  else if (investigating.length > 0)
    threat = {
      level: 'unknown',
      basis: 'CVE-koppling under utredning (komponentsårbarhet, produktmatch ej verifierad).',
      source_ids: srcAll,
    };
  else
    threat = {
      level: 'unknown',
      basis:
        entity.kind === 'protocol_service'
          ? 'Protokoll/tjänst: hotet beror på konfiguration och bakomliggande produkter, inte på egna CVE:er.'
          : 'Inga verifierade CVE-kopplingar i katalogen. Frånvaro av CVE är inte bevis för frånvaro av sårbarheter.',
      source_ids: [],
    };

  // Allvarlighet
  const scores = affectedVulns.flatMap((v) => v.cvss.map((c) => c.base_score));
  const maxScore = scores.length ? Math.max(...scores) : null;
  const severity: RiskAssessment['severity'] =
    maxScore === null
      ? {
          level: 'unknown',
          basis: 'Ingen CVSS tillgänglig (inga bekräftade matchningar).',
          source_ids: [],
        }
      : {
          level: maxScore >= 7 ? 'high' : maxScore >= 4 ? 'medium' : 'low',
          basis: `Högsta CVSS-grundpoäng bland bekräftade matchningar: ${maxScore}. Leverantörs- och NVD-poäng kan skilja sig; se CVE-vyn.`,
          source_ids: uniq(affectedVulns.flatMap((v) => v.source_ids)),
        };

  // Relevans
  let relevance: RiskAssessment['relevance'];
  if (
    affected.some(
      (m) => m.verification_status === 'verified_primary' && m.version_rule.type !== 'unknown',
    )
  )
    relevance = {
      level: 'high',
      basis:
        'Primärkälla anger exakt berörd produkt/komponent och versionsregel. Faktisk installerad version måste ändå fastställas.',
      source_ids: srcAll,
    };
  else if (affected.length > 0)
    relevance = {
      level: 'medium',
      basis: 'Matchning finns men versionsgräns eller primärkälla saknas.',
      source_ids: srcAll,
    };
  else if (investigating.length > 0)
    relevance = {
      level: 'unknown',
      basis: 'Komponent-CVE utan verifierad produktmappning.',
      source_ids: srcAll,
    };
  else
    relevance = {
      level: 'unknown',
      basis: 'Ingen CVE-matchning; versionsuppgift saknas.',
      source_ids: [],
    };

  const exposure: RiskAssessment['exposure'] = {
    level: 'unknown',
    basis:
      'Publik katalog saknar asset-data. Exponering kan bara bedömas per inventerad tillgång i en separat, skyddad modul. "P1 vid publik åtkomst" i arbetsboken är villkorlig.',
    source_ids: [],
  };

  const otImpact: RiskAssessment['ot_impact'] = {
    level: (ov.ot_impact ?? CATEGORY_OT_IMPACT[entity.category] ?? { level: 'unknown' as const })
      .level,
    basis:
      (
        ov.ot_impact ??
        CATEGORY_OT_IMPACT[entity.category] ?? {
          basis: `Ingen kategoriprofil för "${entity.category}".`,
        }
      ).basis + ' Generell bedömning per produkttyp; faktisk konsekvens beror på anläggning.',
    source_ids: [],
  };

  // Genomförbarhet
  const isEol = entity.kind === 'product_family' && entity.lifecycle.status === 'eol';
  let mitigation: RiskAssessment['mitigation_feasibility'];
  if (isEol)
    mitigation = {
      level: 'low',
      basis:
        'Produkten anges som EOL (verifiera): fix förväntas inte; utbyte eller strikt isolering krävs.',
      source_ids: ['src-workbook'],
    };
  else if (
    affected.some(
      (m) =>
        m.fix.available === 'yes' &&
        (m.fix.status === 'verified_primary' || m.fix.status === 'corroborated_secondary'),
    )
  )
    mitigation = {
      level: 'high',
      basis: 'Leverantörsfix finns med belagd version; kräver test och servicefönster.',
      source_ids: uniq(affected.flatMap((m) => m.fix.source_ids)),
    };
  else if (affected.some((m) => m.fix.available === 'no' || m.fix.available === 'none_planned'))
    mitigation = {
      level: 'medium',
      basis: 'Ingen fix tillgänglig; endast kompenserande kontroller (behörighet, segmentering).',
      source_ids: uniq(affected.flatMap((m) => m.fix.source_ids)),
    };
  else if (affected.length > 0)
    mitigation = {
      level: 'medium',
      basis: 'Fixuppgift ej verifierad; kompenserande kontroller tillämpliga.',
      source_ids: uniq(affected.flatMap((m) => m.fix.source_ids)),
    };
  else
    mitigation = {
      level: 'medium',
      basis:
        'Generella härdningsåtgärder (segmentering, ingen publik exponering, skyddad fjärråtkomst) är tillämpliga.',
      source_ids: [],
    };

  // Datakvalitet
  const flags = entity.data_quality_flags;
  const primary = matches.some((m) => m.verification_status === 'verified_primary');
  const dq: RiskAssessment['data_quality'] =
    primary && !flags.includes('needs_human_review')
      ? {
          level: 'high',
          basis: 'Primärkällor verifierade för CVE-matchningar.',
          source_ids: srcAll,
        }
      : primary || entity.documentation.some((d) => d.product_specific)
        ? {
            level: 'medium',
            basis:
              'Delvis primärkällor; vissa uppgifter kräver granskning eller saknar versionsgräns.',
            source_ids: srcAll,
          }
        : {
            level: 'low',
            basis:
              'Endast arbetsbok/branschguide som underlag. Låg datakvalitet betyder inte låg risk – verifiera.',
            source_ids: ['src-workbook'],
          };

  // Rekommenderad åtgärd
  let action: RecommendedAction;
  let rationale: string;
  if (entity.kind === 'protocol_service') {
    action = 'harden_configuration';
    rationale =
      'Protokoll/tjänst: risken styrs av zonering, filtrering och protokollets säkerhetsfunktioner, inte av produkt-CVE.';
  } else if (isEol) {
    action = 'replace_or_isolate_eol';
    rationale =
      'Livscykelrisk: fix uteblir. Planera utbyte; till dess strikt isolering och ingen fjärråtkomst. Verifiera EOL-datum hos tillverkaren.';
  } else if (kev.length > 0) {
    action = 'mitigate_if_exposed';
    rationale =
      'KEV-listad sårbarhet: om enheten finns i er miljö och versionen är berörd ska åtgärd ske omgående oavsett exponering; publik exponering gör det akut.';
  } else if (affected.length > 0 && mitigation.level === 'high') {
    action = 'apply_vendor_fix';
    rationale =
      'Verifierad CVE-matchning med belagd leverantörsfix: fastställ installerad version och planera uppdatering.';
  } else if (affected.length > 0) {
    action = 'mitigate_if_exposed';
    rationale =
      'Verifierad CVE-matchning utan belagd fix: tillämpa kompenserande kontroller och bevaka leverantören.';
  } else if (
    investigating.length > 0 ||
    /versions|modell|beroende|kontrolleras|skiljer/i.test(
      entity.risk_summary.affected_firmware_text ?? entity.risk_summary.explanation_text ?? '',
    )
  ) {
    action = 'verify_model_and_version';
    rationale =
      'Sårbarheter är modell-/versionsberoende enligt underlaget: fastställ exakt modell och firmware innan bedömning.';
  } else {
    action = 'monitor';
    rationale =
      'Inga verifierade CVE-kopplingar i katalogen. Tillämpa generella kontroller och bevaka tillverkarens bulletiner.';
  }

  return {
    threat,
    severity,
    relevance,
    exposure,
    ot_impact: otImpact,
    mitigation_feasibility: mitigation,
    data_quality: dq,
    recommended_action: action,
    rationale,
    method_version: 'risk-method-1.0',
  };
}

/* ------------------------------------------------------------------ */
/* Skrivning                                                           */
/* ------------------------------------------------------------------ */

export function writeDataset(ds: Dataset, outDir = p('public', 'data')): void {
  const files: [keyof typeof DATA_FILES, unknown][] = [
    ['manifest', ds.manifest],
    ['vendors', ds.vendors],
    ['product_families', ds.product_families],
    ['protocol_services', ds.protocol_services],
    ['vulnerabilities', ds.vulnerabilities],
    ['advisories', ds.advisories],
    ['matches', ds.matches],
    ['controls', ds.controls],
    ['sources', ds.sources],
    ['observations', ds.observations],
    ['claims', ds.claims],
    ['link_checks', ds.link_checks],
  ];
  for (const [key, data] of files) writeJson(p(outDir, DATA_FILES[key]), data);
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  try {
    if (!existsSync(p('sources', 'raw', 'workbook.json')))
      throw new Error('sources/raw/workbook.json saknas – kör npm run data:import först.');
    const ds = buildDataset();
    writeDataset(ds);
    const c = ds.manifest.counts;
    console.log(
      `Normalisering OK: ${c.total_entries} poster (${c.product_families} produktfamiljer, ${c.protocol_services} tjänster, ${c.categories} kategorier), ${c.vulnerabilities} CVE, ${c.advisories} bulletiner, ${c.matches} matchningar, ${c.sources} källor, ${c.claims} påståenden. NVD-cache: ${readdirSync(nvdDirForLog()).length} filer.`,
    );
  } catch (err) {
    console.error('Normalisering misslyckades:', err instanceof Error ? err.message : err);
    process.exit(1);
  }
}
function nvdDirForLog() {
  return p('sources', 'enrichment', 'nvd');
}

/**
 * Import 2 – transformationer från sources/raw/register/*.json till datamodellen.
 * Rena funktioner; normalize.ts orkestrerar och bygger katalogposter/risk.
 */
import { existsSync, readdirSync } from 'node:fs';
import type {
  Advisory,
  Credentials,
  InitialPasswordType,
  LinkCheck,
  MaterialTypeCode,
  PublicPocStatus,
  RegisterInfo,
  ReviewFinding,
  SetupDocumentation,
  Source,
  ThreatIntel,
  VerificationStatus,
} from '../schemas/index';
import { p, readJson } from './lib/fs';
import type { RawRecord, RawSheetJson, SheetKey } from './import-register';

export interface RegisterData {
  sheets: Record<SheetKey, RawSheetJson>;
  report: {
    imported_at: string;
    import_version: string;
    file: string;
    sha256: string;
    sheets: string[];
    counts: Record<string, unknown>;
    deviations: string[];
  };
  idMap: Record<string, string>;
  conflicts: { type: string; register_id: string; project_id?: string; [k: string]: unknown }[];
  byRegisterId: Map<string, RawRecord>;
  vulnByRegisterId: Map<string, RawRecord[]>;
  setupByRegisterId: Map<string, RawRecord>;
  reviewByRegisterId: Map<string, RawRecord>;
  threatByCve: Map<string, RawRecord>;
  threatSourceByCve: Map<string, RawRecord>;
}

type Fields = Record<string, string | null> | undefined;
/** Säker fältåtkomst: saknad kolumn eller tom cell ⇒ null. */
export const g = (o: Fields, k: string): string | null => o?.[k] ?? null;

const RAW = p('sources', 'raw', 'register');
const SHEET_KEYS: SheetKey[] = [
  'register',
  'vulnerabilities',
  'review',
  'controls',
  'source_manifest',
  'link_checks',
  'threat_intel',
  'threat_sources',
  'setup_accounts',
];

export function loadRegister(): RegisterData | null {
  if (!existsSync(p(RAW, 'register.json'))) return null;
  const sheets = {} as Record<SheetKey, RawSheetJson>;
  for (const k of SHEET_KEYS) sheets[k] = readJson<RawSheetJson>(p(RAW, `${k}.json`));
  const report = readJson<RegisterData['report']>(p(RAW, 'import-report.json'));
  const conflicts = existsSync(p(RAW, 'conflicts.json'))
    ? readJson<RegisterData['conflicts']>(p(RAW, 'conflicts.json'))
    : [];
  const idMap = readJson<Record<string, string>>(p('sources', 'curated', 'register_id_map.json'));
  const byRegisterId = new Map(
    sheets.register.records.map((r) => [g(r.fields, 'register_id')!, r]),
  );
  const vulnByRegisterId = new Map<string, RawRecord[]>();
  for (const r of sheets.vulnerabilities.records) {
    const k = g(r.fields, 'register_id')!;
    vulnByRegisterId.set(k, [...(vulnByRegisterId.get(k) ?? []), r]);
  }
  const setupByRegisterId = new Map(
    sheets.setup_accounts.records.map((r) => [g(r.fields, 'register_id')!, r]),
  );
  const reviewByRegisterId = new Map(
    sheets.review.records.map((r) => [g(r.fields, 'register_id')!, r]),
  );
  const threatByCve = new Map(sheets.threat_intel.records.map((r) => [g(r.fields, 'cve_id')!, r]));
  const threatSourceByCve = new Map(
    sheets.threat_sources.records.map((r) => [g(r.fields, 'cve_id')!, r]),
  );
  return {
    sheets,
    report,
    idMap,
    conflicts,
    byRegisterId,
    vulnByRegisterId,
    setupByRegisterId,
    reviewByRegisterId,
    threatByCve,
    threatSourceByCve,
  };
}

/* ------------------------------------------------------------------ */
/* Hjälpare                                                            */
/* ------------------------------------------------------------------ */

export const isoDate = (s: string | null | undefined): string | null =>
  s && /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : null;
export const normalizeUrl = (u: string): string => u.trim().replace(/\/+$/, '').toLowerCase();
export const isHttps = (u: string | null | undefined): u is string =>
  Boolean(u && /^https:\/\/\S+$/i.test(u.trim()));
export const extractUrls = (s: string | null | undefined): string[] =>
  s ? [...new Set(s.match(/https?:\/\/[^\s;,)]+/g) ?? [])] : [];
export const slug = (s: string): string =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
const isSha = (s: string | null): s is string => Boolean(s && /^[a-f0-9]{64}$/.test(s));

/** Exakt värdnamn eller sub-domän av en känd domän (ingen substringmatchning). */
export function hostMatchesDomain(host: string, domain: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  const d = domain.toLowerCase().replace(/\.$/, '');
  return h === d || h.endsWith(`.${d}`);
}
/** Värdnamn ur URL, eller null om URL:en inte kan tolkas. */
export function hostnameOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}
const RESEARCH_DOMAINS = [
  'github.com',
  'armis.com',
  'dragos.com',
  'claroty.com',
  'nozominetworks.com',
  'forescout.com',
  'medium.com',
  'exploit-db.com',
];
const DATABASE_DOMAINS = ['cve.org', 'nist.gov', 'mitre.org'];

function shortHash(s: string): string {
  // deterministisk FNV-1a 32-bit – räcker som ID-suffix
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

const NOT_SET =
  /^(ej verifierat|ej tillämpligt.*|skapas (av installatören|vid driftsättning).*|-|–)$/i;

export function accountNameFromText(text: string | null): string | null {
  if (!text) return null;
  const t = text.trim();
  if (NOT_SET.test(t) || /^ej /i.test(t) || /^inget/i.test(t)) return null;
  return t;
}

export function initialPasswordTypeCode(text: string | null): InitialPasswordType {
  const t = (text ?? '').toLowerCase();
  if (t.startsWith('gemensamt standardlösenord')) return 'shared_default_documented';
  if (t.startsWith('standardlösenord förekommer')) return 'default_exists_type_unknown';
  if (t.startsWith('enhetsunikt initiallösenord enligt')) return 'device_unique_documented';
  if (t.startsWith('enhetsunikt initiallösenord vid')) return 'device_unique_normal_delivery';
  if (t.startsWith('modell-/versions-/batchberoende')) return 'model_version_batch_dependent';
  if (t.startsWith('versionsberoende')) return 'version_dependent_shared_or_unique';
  if (t.startsWith('lösenord väljs/skapas')) return 'set_at_commissioning';
  if (t.startsWith('hårdkodade')) return 'hardcoded_in_affected_version';
  if (t.startsWith('förutsägbar')) return 'predictable_builtin_mechanism';
  if (t.startsWith('ej tillämpligt')) return 'not_applicable_implementation';
  return 'unknown_unverified';
}

export function setupDocTypeCode(text: string | null): SetupDocumentation['doc_type'] {
  const t = (text ?? '').toLowerCase();
  if (t.startsWith('direkt instruktion')) return 'direct_manual';
  if (t.startsWith('produktens dokumentportal') || t.startsWith('dokumentportal'))
    return 'doc_portal';
  if (t.startsWith('onlinehandbok')) return 'online_handbook';
  if (t.startsWith('leverantörsingång')) return 'vendor_entry_unverified';
  if (t.startsWith('säkerhetsguide') || t.startsWith('säkerhetsresurser'))
    return 'security_guide_unverified';
  if (t.startsWith('tillverkarens start')) return 'start_guide';
  if (t.startsWith('ej produkt')) return 'not_product';
  if (t.includes('ej verifierad')) return 'unverified';
  return t ? 'other' : 'unverified';
}

export function publicPocStatusCode(text: string | null, ssvcRaw: string | null): PublicPocStatus {
  const t = (text ?? '').toLowerCase();
  if (t.startsWith('offentlig poc') || ssvcRaw === 'poc') return 'poc_reported';
  if (t.includes('aktiv exploatering') || ssvcRaw === 'active') return 'active_reported';
  if (t.startsWith('okänt') || ssvcRaw === 'missing') return 'unknown_missing';
  return 'none_reported_at_assessment';
}

export function materialTypeCode(text: string | null): MaterialTypeCode {
  const t = (text ?? '').toLowerCase();
  if (!t || t.startsWith('ingen direkt poc-länk')) return 'none_verified';
  if (t.startsWith('emulator')) return 'emulator_or_reconstructed_poc';
  if (t.startsWith('forskningsartefakter')) return 'research_artifacts_and_detection';
  if (t.startsWith('publicerad komponentexploit')) return 'component_exploit_published';
  if (t.startsWith('forskarpublicerad komponent')) return 'component_poc_research';
  if (t.startsWith('forskarpublicering')) return 'research_publication_with_code';
  if (t.startsWith('publikt exploitarkiv')) return 'public_exploit_archive';
  if (t.startsWith('officiell rapport om aktiv')) return 'official_active_exploitation_report';
  if (t.startsWith('incidentanalys')) return 'incident_analysis_detection';
  if (t.startsWith('cert-rapport')) return 'cert_report_public_poc';
  return 'other';
}

/* ------------------------------------------------------------------ */
/* Källor, länkkontroll                                                */
/* ------------------------------------------------------------------ */

function classifyManifest(
  fmt: string | null,
  url: string,
): { type: Source['source_type']; publisher: string; isPrimary: boolean } {
  const f = (fmt ?? '').toLowerCase();
  if (f.includes('csaf'))
    return { type: 'primary_government', publisher: 'CISA (CSAF)', isPrimary: true };
  if (f.includes('kev'))
    return { type: 'primary_government', publisher: 'CISA KEV', isPrimary: true };
  if (f.includes('cve'))
    return { type: 'database', publisher: 'CVE Program (CNA + CISA ADP)', isPrimary: true };
  const host = (hostnameOf(url) ?? 'leverantör').replace(/^www\./, '');
  return { type: 'primary_vendor', publisher: host, isPrimary: true };
}

function baseSource(id: string, url: string, title: string): Source {
  return {
    id,
    url: url.trim(),
    title,
    publisher: 'okänd',
    source_type: 'primary_vendor',
    is_primary: true,
    published_at: null,
    last_checked_at: null,
    last_verified_at: null,
    availability: 'unchecked',
    http_status: null,
    supports_claims: [],
    access_note: null,
    notes: null,
    document_sha256: null,
    fetched_at: null,
    final_url: null,
    interpretation_text: null,
    register_source_key: null,
  };
}

/**
 * Lägger till källor från Källmanifest och Hotkällor samt auto-källor för övriga URL:er i
 * Register/Setup/Sårbarheter/Radgranskning/Hotunderlag. Dedupe på normaliserad URL.
 * Returnerar uppslag normaliserad URL → source_id.
 */
export function addRegisterSources(
  reg: RegisterData,
  sources: Source[],
  sourcesByUrl: Map<string, Source>,
): Map<string, string> {
  const byUrl = new Map<string, string>();
  const sourceIds = new Set(sources.map((s) => s.id));
  const add = (s: Source) => {
    if (sourceIds.has(s.id)) return;
    sources.push(s);
    sourceIds.add(s.id);
    sourcesByUrl.set(normalizeUrl(s.url), s);
  };
  const workbookSrc = baseSource(
    'src-register-workbook',
    'https://github.com/timpan8/ot-iot-security-intelligence/blob/main/sources/original/OT_IoT_125_poster_losenordsstatus.xlsx',
    `Utökat OT/IoT-register (${reg.report.file})`,
  );
  workbookSrc.publisher = 'Projektets registerimport';
  workbookSrc.source_type = 'internal_workbook';
  workbookSrc.is_primary = false;
  workbookSrc.published_at = '2026-11-07';
  workbookSrc.last_checked_at = reg.report.imported_at.slice(0, 10);
  workbookSrc.availability = 'ok';
  workbookSrc.document_sha256 = reg.report.sha256;
  workbookSrc.notes = `Arbetsbok med 13 blad; importversion ${reg.report.import_version}. Källa för registerfält, konto-/lösenordsstatus, setupdokument och radgranskning.`;
  add(workbookSrc);

  for (const r of reg.sheets.source_manifest.records) {
    const f = r.fields;
    const url = g(f, 'url');
    if (!isHttps(url)) continue;
    const norm = normalizeUrl(url);
    const key = g(f, 'source_key');
    const sha = g(f, 'document_sha256');
    const existing = sourcesByUrl.get(norm);
    if (existing) {
      existing.document_sha256 = existing.document_sha256 ?? (isSha(sha) ? sha : null);
      existing.fetched_at = existing.fetched_at ?? isoDate(g(f, 'fetched_at'));
      existing.register_source_key = existing.register_source_key ?? key;
      byUrl.set(norm, existing.id);
      continue;
    }
    const cls = classifyManifest(g(f, 'publisher_format'), url);
    const s = baseSource(
      `src-reg-${slug(key ?? `manifest-${r.row}`)}`,
      url,
      `${key ?? 'källa'} – ${g(f, 'publisher_format') ?? 'källa'}`,
    );
    s.publisher = cls.publisher;
    s.source_type = cls.type;
    s.is_primary = cls.isPrimary;
    s.published_at = isoDate(g(f, 'source_date'));
    s.last_checked_at = isoDate(g(f, 'fetched_at'));
    s.notes = g(f, 'verified_text')
      ? `Källmanifest: ${g(f, 'verified_text')}`
      : 'Från registrets källmanifest.';
    s.document_sha256 = isSha(sha) ? sha : null;
    s.fetched_at = isoDate(g(f, 'fetched_at'));
    s.register_source_key = key;
    add(s);
    byUrl.set(norm, s.id);
  }

  for (const r of reg.sheets.threat_sources.records) {
    const f = r.fields;
    const url = g(f, 'url');
    if (!isHttps(url)) continue;
    const norm = normalizeUrl(url);
    if (sourcesByUrl.has(norm)) {
      byUrl.set(norm, sourcesByUrl.get(norm)!.id);
      continue;
    }
    const cve = g(f, 'cve_id') ?? `row-${r.row}`;
    const sha = g(f, 'sha256');
    const s = baseSource(`src-cverecord-${slug(cve)}`, url, `CVE-post ${cve} (CNA + CISA ADP)`);
    s.publisher = 'CVE Program / MITRE (cveawg)';
    s.source_type = 'database';
    s.last_checked_at = isoDate(g(f, 'fetched_at'));
    s.supports_claims = [
      {
        entity_id: `cve-${cve.toLowerCase().replace(/^cve-/, '')}`,
        field: 'threat_intel',
        note: g(f, 'checked_fields'),
      },
    ];
    s.notes = `Hotkällor: ${g(f, 'source_type') ?? ''}; postens uppdateringsdatum ${g(f, 'record_updated_at') ?? 'okänt'}.`;
    s.document_sha256 = isSha(sha) ? sha : null;
    s.fetched_at = isoDate(g(f, 'fetched_at'));
    add(s);
    byUrl.set(norm, s.id);
  }

  // Övriga URL:er (auto-källor)
  const autoUrls: { url: string; title: string; sheet: string; row: number }[] = [];
  const collect = (records: RawRecord[], keys: string[], sheet: string, nameKey: string) => {
    for (const r of records)
      for (const k of keys)
        for (const u of extractUrls(g(r.fields, k)))
          autoUrls.push({
            url: u,
            title: `${g(r.fields, nameKey) ?? sheet} – ${k}`,
            sheet,
            row: r.row,
          });
  };
  collect(
    reg.sheets.register.records,
    [
      'documentation_url',
      'security_source_url',
      'setup_url',
      'password_status_source_url',
      'threat_links',
    ],
    'Register',
    'name',
  );
  collect(
    reg.sheets.setup_accounts.records,
    ['account_source_url', 'setup_url', 'password_status_source_url'],
    'Setup och konton',
    'name',
  );
  collect(reg.sheets.vulnerabilities.records, ['source_url', 'poc_url'], 'Sårbarheter', 'cve_id');
  collect(reg.sheets.review.records, ['source_urls'], 'Radgranskning', 'name');
  collect(
    reg.sheets.threat_intel.records,
    ['poc_url', 'assessment_source_url'],
    'Hotunderlag',
    'cve_id',
  );
  for (const a of autoUrls) {
    if (!isHttps(a.url)) continue;
    const norm = normalizeUrl(a.url);
    if (sourcesByUrl.has(norm)) {
      byUrl.set(norm, sourcesByUrl.get(norm)!.id);
      continue;
    }
    const host = hostnameOf(a.url);
    if (!host) continue;
    const isResearch = RESEARCH_DOMAINS.some((d) => hostMatchesDomain(host, d));
    const s = baseSource(
      `src-reg-url-${host.replace(/[^a-z0-9.]/g, '-')}-${shortHash(norm)}`,
      a.url,
      a.title,
    );
    s.publisher = host.replace(/^www\./, '');
    s.source_type = isResearch
      ? 'secondary_research'
      : hostMatchesDomain(host, 'cisa.gov')
        ? 'primary_government'
        : DATABASE_DOMAINS.some((d) => hostMatchesDomain(host, d))
          ? 'database'
          : 'primary_vendor';
    s.is_primary = !isResearch;
    s.notes = `Länk från registret (${a.sheet}, rad ${a.row}).`;
    add(s);
    byUrl.set(norm, s.id);
  }
  return byUrl;
}

/** Länkkontroll → LinkCheck-poster; uppdaterar Source.availability/http_status/final_url. */
export function buildLinkChecks(reg: RegisterData, sourcesByUrl: Map<string, Source>): LinkCheck[] {
  const out: LinkCheck[] = [];
  for (const r of reg.sheets.link_checks.records) {
    const f = r.fields;
    const url = g(f, 'url');
    if (!url) continue;
    const norm = normalizeUrl(url);
    const src = sourcesByUrl.get(norm);
    const statusText = g(f, 'http_status');
    const code = statusText && /^\d{3}$/.test(statusText) ? Number(statusText) : null;
    const finalUrl = g(f, 'final_url');
    let availability: Source['availability'] = 'unchecked';
    if (code !== null)
      availability =
        code >= 200 && code < 300
          ? finalUrl && normalizeUrl(finalUrl) !== norm
            ? 'redirected'
            : 'ok'
          : code === 403 || code === 429
            ? 'blocked'
            : 'broken';
    else if (statusText) availability = /403|429/.test(statusText) ? 'blocked' : 'broken';
    if (src) {
      src.availability = availability;
      src.http_status =
        code ?? (statusText ? Number((statusText.match(/\d{3}/) ?? [null])[0]) || null : null);
      src.final_url = finalUrl;
      src.interpretation_text = g(f, 'interpretation');
      src.last_checked_at = isoDate(g(f, 'checked_at')) ?? src.last_checked_at;
    }
    const sha = g(f, 'response_sha256');
    out.push({
      id: `lc-${shortHash(norm)}-${r.row}`,
      url: url.trim(),
      http_status_text: statusText,
      final_url: finalUrl,
      response_sha256: isSha(sha) ? sha : null,
      interpretation_text: g(f, 'interpretation'),
      checked_at: isoDate(g(f, 'checked_at')),
      source_ids: src ? [src.id] : [],
      entity_ids: [],
    });
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Per post                                                            */
/* ------------------------------------------------------------------ */

export function registerInfoFor(reg: RegisterData, r: RawRecord): RegisterInfo {
  const f = r.fields;
  const codes = new Set<string>();
  for (const m of (g(f, 'risk_controls') ?? '').matchAll(/K(\d)(?:–K(\d))?/g)) {
    const a = Number(m[1]);
    const b = m[2] ? Number(m[2]) : a;
    for (let i = a; i <= b; i++) codes.add(`K${i}`);
  }
  return {
    register_id: g(f, 'register_id')!,
    origin: g(f, 'origin') === 'Original' ? 'original' : 'new',
    origin_reference: g(f, 'origin_reference'),
    normalization_key: g(f, 'normalization_key'),
    scope_alias_text: g(f, 'scope_alias'),
    source_status_text: g(f, 'source_status'),
    uncertainty_text: g(f, 'uncertainty'),
    exposure_risk_text: g(f, 'exposure_risk'),
    cve_selection_text: g(f, 'cve_selection'),
    kev_text: g(f, 'kev_matched'),
    priority_text: g(f, 'priority'),
    control_codes: [...codes].sort(),
    controls_text: g(f, 'risk_controls'),
    credentials_status_text: g(f, 'credentials_status'),
    change_required_text: g(f, 'change_required'),
    verify_login_text: g(f, 'verify_login'),
    documentation_limitation_text: g(f, 'documentation_limitation'),
    versions_guidance_text: g(f, 'versions_guidance'),
    fix_guidance_text: g(f, 'fix_guidance'),
    source_date_text: g(f, 'source_date'),
    checked_at: isoDate(g(f, 'checked_at')),
    observed_exposure_text: g(f, 'observed_exposure'),
    threat_selection_text: g(f, 'threat_selection'),
    threat_links_text: g(f, 'threat_links'),
    threat_tracking_text: g(f, 'threat_tracking'),
    limitation_text: g(f, 'limitation'),
    threat_checked_at: isoDate(g(f, 'threat_checked_at')),
    import: {
      file: reg.report.file,
      file_sha256: reg.report.sha256,
      import_version: reg.report.import_version,
      sheet: 'Register',
      row: r.row,
    },
  };
}

export function credentialsFor(
  setup: RawRecord | undefined,
  regRow: RawRecord,
  byUrl: Map<string, string>,
): Credentials {
  const s = setup?.fields;
  const f = regRow.fields;
  const typeText = g(s, 'initial_password_type') ?? g(f, 'initial_password_type');
  const code = initialPasswordTypeCode(typeText);
  const accountText = g(s, 'account_name') ?? g(f, 'account_name');
  const accSrc = extractUrls(g(s, 'account_source_url')).find(isHttps);
  const pwdSrc = extractUrls(
    g(s, 'password_status_source_url') ?? g(f, 'password_status_source_url'),
  ).find(isHttps);
  const hasSource = Boolean(accSrc || pwdSrc);
  const vs: VerificationStatus =
    code === 'unknown_unverified'
      ? 'unknown'
      : code === 'not_applicable_implementation'
        ? 'verified_primary'
        : hasSource
          ? 'corroborated_secondary'
          : 'needs_review';
  return {
    account_name: accountNameFromText(accountText),
    account_name_text: accountText,
    account_status_text: g(s, 'account_status'),
    account_scope_text: g(s, 'account_scope'),
    account_source_id: accSrc ? (byUrl.get(normalizeUrl(accSrc)) ?? null) : null,
    initial_password_type: code,
    initial_password_type_text: typeText,
    change_requirement_text:
      g(s, 'initial_account_change') ?? g(f, 'initial_account_change') ?? g(f, 'change_required'),
    commissioning_action_text: g(s, 'commissioning_action'),
    password_status_source_id: pwdSrc ? (byUrl.get(normalizeUrl(pwdSrc)) ?? null) : null,
    verification_status: vs,
    checked_at: isoDate(g(s, 'checked_at') ?? g(f, 'checked_at')),
    note: 'Underlaget innehåller inga lösenordsvärden; endast kontonamn, lösenordstyp och bytekrav.',
  };
}

export function setupDocFor(
  setup: RawRecord | undefined,
  regRow: RawRecord,
  byUrl: Map<string, string>,
): SetupDocumentation | null {
  const s = setup?.fields;
  const url = extractUrls(g(s, 'setup_url') ?? g(regRow.fields, 'setup_url')).find(isHttps) ?? null;
  const typeText = g(s, 'setup_doc_type') ?? g(regRow.fields, 'setup_doc_type');
  if (!url && !typeText) return null;
  const code = setupDocTypeCode(typeText);
  const verificationText = g(s, 'setup_verification');
  const identityVerified = /^dokumentidentitet/i.test(verificationText ?? '');
  const exactManualMissing = /exakt setupmanual saknas/i.test(verificationText ?? '');
  const verified =
    identityVerified &&
    !exactManualMissing &&
    (code === 'direct_manual' || code === 'online_handbook' || code === 'start_guide');
  return {
    url,
    title: g(s, 'setup_title'),
    doc_type: code,
    doc_type_text: typeText,
    scope_text: g(s, 'setup_scope'),
    verification_text: verificationText,
    fetch_status_text: g(s, 'setup_fetch_status'),
    identity_verified: identityVerified,
    exact_manual_missing: exactManualMissing,
    is_verified_setup_manual: verified,
    source_id: url ? (byUrl.get(normalizeUrl(url)) ?? null) : null,
    checked_at: isoDate(g(s, 'checked_at')),
  };
}

export function reviewFindingsFor(
  review: RawRecord | undefined,
  byUrl: Map<string, string>,
): ReviewFinding[] {
  if (!review) return [];
  const f = review.fields;
  return [
    {
      finding: g(f, 'finding'),
      uncertainty: g(f, 'uncertainty'),
      status_text: g(f, 'status'),
      source_ids: extractUrls(g(f, 'source_urls'))
        .filter(isHttps)
        .map((u) => byUrl.get(normalizeUrl(u)))
        .filter((x): x is string => Boolean(x)),
      checked_at: null,
    },
  ];
}

export function threatIntelFor(
  cve: string,
  reg: RegisterData,
  byUrl: Map<string, string>,
  productIdFor: (rid: string) => string | null,
): ThreatIntel | null {
  const t = reg.threatByCve.get(cve);
  if (!t) return null;
  const f = t.fields;
  const ts = reg.threatSourceByCve.get(cve)?.fields;
  const rawText = (g(f, 'ssvc_exploitation_raw') ?? '').toLowerCase();
  const raw = (['none', 'poc', 'active', 'missing'] as const).find((x) => x === rawText) ?? null;
  const pocUrl = extractUrls(g(f, 'poc_url')).find(isHttps) ?? null;
  const assessUrl = extractUrls(g(f, 'assessment_source_url')).find(isHttps);
  const tsUrl0 = g(ts, 'url');
  const tsUrl = isHttps(tsUrl0) ? tsUrl0 : null;
  const rid = g(f, 'register_id');
  const pid = rid ? productIdFor(rid) : null;
  return {
    id: `ti-${slug(cve)}`,
    public_poc_status: publicPocStatusCode(g(f, 'public_poc_status'), raw),
    public_poc_status_text: g(f, 'public_poc_status'),
    cisa_ssvc_exploitation_raw: raw,
    cisa_assessment_date: isoDate(g(f, 'cisa_assessment_date')),
    active_exploitation_status: /kev/i.test(g(f, 'active_exploitation') ?? '')
      ? 'kev_listed'
      : 'not_established',
    active_exploitation_text: g(f, 'active_exploitation'),
    poc_url: pocUrl,
    material_type_code: materialTypeCode(g(f, 'material_type')),
    material_type_text: g(f, 'material_type'),
    source_critical_note: g(f, 'source_critical_note'),
    verification_level_text: g(f, 'verification_level'),
    assessment_source_id: assessUrl ? (byUrl.get(normalizeUrl(assessUrl)) ?? null) : null,
    record_source_id: tsUrl ? (byUrl.get(normalizeUrl(tsUrl)) ?? null) : null,
    subject_product_family_id: pid && pid.startsWith('pf-') ? pid : null,
    checked_at: isoDate(g(f, 'checked_at')),
  };
}

/* ------------------------------------------------------------------ */
/* CSAF-verifiering av registrets relationer                           */
/* ------------------------------------------------------------------ */

interface CsafDoc {
  document: {
    title?: string;
    tracking: {
      id: string;
      status?: string;
      version?: string;
      initial_release_date?: string;
      current_release_date?: string;
    };
  };
  product_tree?: { branches?: CsafBranch[] };
  vulnerabilities?: {
    cve?: string;
    product_status?: Record<string, string[]>;
    remediations?: { category?: string; details?: string; product_ids?: string[] }[];
  }[];
}
interface CsafBranch {
  name?: string;
  category?: string;
  product?: { product_id: string; name?: string };
  branches?: CsafBranch[];
}

export interface CsafIndex {
  byId: Map<string, { doc: CsafDoc; file: string; names: Map<string, string>; cves: Set<string> }>;
}

export function loadCsafIndex(dir = p('sources', 'enrichment', 'csaf')): CsafIndex {
  const byId: CsafIndex['byId'] = new Map();
  if (!existsSync(dir)) return { byId };
  for (const f of readdirSync(dir)) {
    if (!f.endsWith('.json')) continue;
    const doc = readJson<CsafDoc>(p(dir, f));
    const id = doc?.document?.tracking?.id;
    if (!id) continue;
    const names = new Map<string, string>();
    const walk = (b: CsafBranch[], path: string[]) => {
      for (const x of b) {
        const q = [...path, x.name ?? ''];
        if (x.product) names.set(x.product.product_id, q.filter(Boolean).join(' / '));
        if (x.branches) walk(x.branches, q);
      }
    };
    walk(doc.product_tree?.branches ?? [], []);
    const cves = new Set(
      (doc.vulnerabilities ?? []).map((v) => v.cve).filter((x): x is string => Boolean(x)),
    );
    byId.set(id.toUpperCase(), { doc, file: f, names, cves });
  }
  return { byId };
}

const tokens = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .split(' ')
    .filter(
      (t) => t.length >= 3 && !['the', 'and', 'series', 'products', 'family', 'update'].includes(t),
    );

/** Jämför en Sårbarheter-rad mot CSAF: CVE i dokumentet och produktnamn bland known_affected. */
export function verifyRelationAgainstCsaf(
  bulletinId: string | null,
  cve: string,
  productName: string,
  affectedSourceText: string | null,
  csaf: CsafIndex,
): {
  status: VerificationStatus;
  note: string;
  fix_available: 'yes' | 'no' | 'partial' | 'unknown';
  fix_text: string | null;
} {
  if (!bulletinId)
    return {
      status: 'corroborated_secondary',
      note: 'Ingen CSAF-bulletin angiven; källa är CVE-post/leverantör enligt registret.',
      fix_available: 'unknown',
      fix_text: null,
    };
  const entry = csaf.byId.get(bulletinId.toUpperCase());
  if (!entry)
    return {
      status: 'corroborated_secondary',
      note: `CSAF ${bulletinId} ej i cache; registrets källmanifest (SHA-256) är enda belägg.`,
      fix_available: 'unknown',
      fix_text: null,
    };
  const tr = entry.doc.document.tracking;
  if (!entry.cves.has(cve))
    return {
      status: 'needs_review',
      note: `${cve} finns inte i CSAF ${bulletinId} (${tr.current_release_date ?? 'datum okänt'}).`,
      fix_available: 'unknown',
      fix_text: null,
    };
  const vuln = entry.doc.vulnerabilities?.find((v) => v.cve === cve);
  // Fixtillgänglighet enligt CSAF remediations (kategorier: vendor_fix, mitigation, workaround, none_available, no_fix_planned)
  const cats = new Set((vuln?.remediations ?? []).map((r) => r.category ?? ''));
  const fixAvailable: 'yes' | 'no' | 'partial' | 'unknown' = cats.has('vendor_fix')
    ? 'yes'
    : cats.has('none_available') || cats.has('no_fix_planned')
      ? 'no'
      : cats.has('mitigation') || cats.has('workaround')
        ? 'partial'
        : 'unknown';
  const fixText =
    (vuln?.remediations ?? [])
      .map(
        (r) => `${r.category ?? 'remediation'}: ${(r.details ?? '').replace(/\s+/g, ' ').trim()}`,
      )
      .filter((t) => t.length > 0)
      .slice(0, 4)
      .join(' | ') || null;
  const affectedIds = new Set([
    ...(vuln?.product_status?.known_affected ?? []),
    ...(vuln?.product_status?.first_affected ?? []),
    ...(vuln?.product_status?.last_affected ?? []),
  ]);
  const affectedNames = [...affectedIds]
    .map((id) => entry.names.get(id) ?? id)
    .join(' | ')
    .toLowerCase();
  const nameTokens = tokens(productName);
  const hit = nameTokens.some((t) => affectedNames.includes(t));
  const srcTokens = tokens(affectedSourceText ?? '');
  const srcHit =
    srcTokens.length > 0 &&
    srcTokens.filter((t) => affectedNames.includes(t)).length >= Math.min(2, srcTokens.length);
  if (affectedIds.size === 0)
    return {
      status: 'corroborated_secondary',
      note: `CSAF ${bulletinId} saknar known_affected för ${cve}; produktstatus kan inte verifieras maskinellt.`,
      fix_available: fixAvailable,
      fix_text: fixText,
    };
  if (hit || srcHit)
    return {
      status: 'verified_primary',
      note: `Verifierad mot CSAF ${bulletinId} (v${tr.version ?? '?'}, ${tr.current_release_date?.slice(0, 10) ?? '?'}): ${cve} med ${affectedIds.size} berörda produkt-ID:n.`,
      fix_available: fixAvailable,
      fix_text: fixText,
    };
  return {
    status: 'needs_review',
    note: `${cve} finns i CSAF ${bulletinId} men produktnamnet kunde inte matchas mot known_affected maskinellt.`,
    fix_available: fixAvailable,
    fix_text: fixText,
  };
}

/** Bulletiner ur källmanifestet (CISA CSAF) med data från CSAF-cache när den finns. */
export function buildRegisterAdvisories(
  reg: RegisterData,
  csaf: CsafIndex,
  byUrl: Map<string, string>,
  existingIds: Set<string>,
): Advisory[] {
  const out: Advisory[] = [];
  for (const r of reg.sheets.source_manifest.records) {
    const f = r.fields;
    const key = g(f, 'source_key');
    const url = g(f, 'url');
    if (!/csaf/i.test(g(f, 'publisher_format') ?? '') || !key || !isHttps(url)) continue;
    const id = `adv-cisa-${slug(key)}`;
    if (existingIds.has(id)) continue;
    const entry = csaf.byId.get(key.toUpperCase());
    const tr = entry?.doc.document.tracking;
    const srcId = byUrl.get(normalizeUrl(url));
    out.push({
      id,
      advisory_id: key,
      issuer: 'CISA',
      vendor_id: null,
      title: entry?.doc.document.title ?? `${key} (CISA ICS Advisory)`,
      url: `https://www.cisa.gov/news-events/ics${key.startsWith('ICSMA') ? 'ma' : ''}-advisories/${key.toLowerCase()}`,
      csaf_url: url.trim(),
      published_at:
        isoDate(tr?.initial_release_date?.slice(0, 10) ?? null) ?? isoDate(g(f, 'source_date')),
      updated_at: isoDate(tr?.current_release_date?.slice(0, 10) ?? null),
      status: tr?.status === 'final' ? 'final' : tr?.status === 'interim' ? 'interim' : 'unknown',
      source_type: 'primary_government',
      cve_ids: entry ? [...entry.cves].sort() : [],
      summary: entry
        ? `CSAF-dokument v${tr?.version ?? '?'} läst maskinellt; ${entry.cves.size} CVE, ${entry.names.size} produkt-ID:n i produktträdet.`
        : 'CSAF-dokumentet finns i registrets källmanifest men är inte hämtat i projektet.',
      history: tr?.initial_release_date
        ? [
            {
              date: tr.initial_release_date.slice(0, 10),
              status: 'verified_primary',
              summary: 'Initial release (CSAF).',
            },
          ]
        : [],
      source_ids: srcId ? [srcId] : [],
      verification_status: entry ? 'verified_primary' : 'corroborated_secondary',
      review: {
        reviewed_at: '2026-11-07',
        reviewer: 'registerimport',
        notes: entry ? [] : ['CSAF ej hämtat; kör data:enrich (csaf-register).'],
        history: [],
      },
    });
  }
  return out;
}

/**
 * Import 2 – rubrikbaserad, idempotent import av det utökade OT/IoT-registret
 * (OT_IoT_125_poster_losenordsstatus.xlsx).
 *
 *   npx tsx scripts/import-register.ts --file sources/original/OT_IoT_125_poster_losenordsstatus.xlsx
 *
 * Skriver sources/raw/register/<blad>.json (verbatim rader med radnummer), import-report.json
 * och conflicts.json. Kolumner identifieras via rubriktext, aldrig via kolumnbokstav.
 * Cellinnehåll behandlas som data (inga formler/makron körs; xlsx-läsaren läser cachade värden).
 * Idempotens: utdata är deterministiskt; register_id_map.json får bara nya nycklar.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { basename } from 'node:path';
import { readXlsx, columnIndexToLetter, type XlsxSheet } from './lib/xlsx';
import { nowIso, p, readJson, writeJson } from './lib/fs';
import { CURATED_FILES, loadCuratedArray, loadCuratedRecord } from './lib/curated';

export const IMPORT_VERSION = 'register-import-1.0.0';
export const DEFAULT_FILE = p('sources', 'original', 'OT_IoT_125_poster_losenordsstatus.xlsx');
export const RAW_DIR = p('sources', 'raw', 'register');

/** Rubrik → maskinläsbar nyckel per blad. Rubriker matchas exakt (trimmade). */
export const SHEETS = {
  register: {
    sheet: 'Register',
    required: true,
    columns: {
      ID: 'register_id',
      Ursprung: 'origin',
      Kategori: 'category',
      'System / produktfamilj': 'name',
      'Omfattning / alias': 'scope_alias',
      Källstatus: 'source_status',
      'Osäkerhet / kvarstående granskning': 'uncertainty',
      'Risk vid internetexponering': 'exposure_risk',
      'CVE – verifierat urval': 'cve_selection',
      'KEV – matchade CVE': 'kev_matched',
      'Prioritet vid konstaterad exponering': 'priority',
      Riskkontroller: 'risk_controls',
      'Fabriksinställda inloggningsuppgifter – status': 'credentials_status',
      'Byte av standarduppgifter krävs': 'change_required',
      'Så verifieras inloggningsskydd': 'verify_login',
      'Officiell dokumentationslänk': 'documentation_url',
      'Dokumentets begränsning': 'documentation_limitation',
      'Berörda versioner – vägledning': 'versions_guidance',
      'Åtgärd / fix – vägledning': 'fix_guidance',
      'CVE / säkerhetskälla': 'security_source_url',
      Källdatum: 'source_date',
      Kontrolldatum: 'checked_at',
      'Observerad internetexponering': 'observed_exposure',
      'Originalrad / bulletin': 'origin_reference',
      Normaliseringsnyckel: 'normalization_key',
      'PoC / aktiv exploatering – urval': 'threat_selection',
      'PoC / hotunderlag – länkar': 'threat_links',
      'Spårning av hotunderlag': 'threat_tracking',
      Begränsning: 'limitation',
      'Hotstatus kontrollerad': 'threat_checked_at',
      'Standardkonto / kontonamn – utan lösenord': 'account_name',
      'Setup / installationsinstruktion – länk': 'setup_url',
      'Setupdokument – typ': 'setup_doc_type',
      'Initial-/fabrikslösenord – typ (utan värden)': 'initial_password_type',
      'Byte / initial kontokonfiguration': 'initial_account_change',
      'Officiell källa för lösenordsstatus': 'password_status_source_url',
    },
  },
  vulnerabilities: {
    sheet: 'Sårbarheter',
    required: true,
    columns: {
      'Produkt-ID': 'register_id',
      CVE: 'cve_id',
      'CWE / riskklass': 'cwe_text',
      'Known affected / CNA affected – exakt källtext': 'affected_source_text',
      'Fixed – exakt produktmatris / osäkerhet': 'fixed_source_text',
      'CVSS-version': 'cvss_version',
      'CVSS baspoäng': 'cvss_base_score',
      'CVSS-vektor': 'cvss_vector',
      'CISA KEV': 'kev',
      'KEV dateAdded': 'kev_date_added',
      'Produktkoppling / begränsning': 'product_link_limitation',
      Källa: 'source_url',
      Källdatum: 'source_date',
      Kontrolldatum: 'checked_at',
      'Offentlig PoC – källstatus': 'public_poc_status',
      'PoC / hotunderlag – länk': 'poc_url',
      Materialtyp: 'material_type',
      'Källkritisk bedömning': 'source_critical_note',
      'CISA bedömningsdatum': 'cisa_assessment_date',
    },
  },
  review: {
    sheet: 'Radgranskning',
    required: true,
    columns: {
      'Produkt-ID': 'register_id',
      Produktfamilj: 'name',
      Granskningsfynd: 'finding',
      Osäkerhet: 'uncertainty',
      Åtgärdsstatus: 'status',
      Källa: 'source_urls',
    },
  },
  controls: {
    sheet: 'Riskkontroller',
    required: true,
    columns: {
      'Kontroll-ID': 'code',
      Kontroll: 'name',
      Åtgärd: 'action',
      Verifieringsmetod: 'verification_method',
    },
  },
  source_manifest: {
    sheet: 'Källmanifest',
    required: true,
    columns: {
      'Käll-ID': 'source_key',
      'Utgivare / format': 'publisher_format',
      URL: 'url',
      'SHA-256 av hämtat dokument': 'document_sha256',
      Källdatum: 'source_date',
      Hämtningsdatum: 'fetched_at',
      'Vad som verifierats': 'verified_text',
    },
  },
  link_checks: {
    sheet: 'Länkkontroll',
    required: true,
    columns: {
      URL: 'url',
      'HTTP-status / fel': 'http_status',
      'Slutlig URL': 'final_url',
      'SHA-256 av svar upp till 10 MB': 'response_sha256',
      Tolkning: 'interpretation',
      Kontrolldatum: 'checked_at',
    },
  },
  threat_intel: {
    sheet: 'Hotunderlag',
    required: true,
    columns: {
      CVE: 'cve_id',
      'Produkt-ID': 'register_id',
      Produktfamilj: 'name',
      'Offentlig PoC – källstatus': 'public_poc_status',
      'CISA SSVC Exploitation – råvärde': 'ssvc_exploitation_raw',
      'CISA bedömningsdatum': 'cisa_assessment_date',
      'Aktiv exploatering – status': 'active_exploitation',
      'PoC / hotunderlag – länk': 'poc_url',
      Materialtyp: 'material_type',
      'Källkritisk bedömning / produktgräns': 'source_critical_note',
      Verifieringsnivå: 'verification_level',
      'Officiell bedömningskälla': 'assessment_source_url',
      Kontrolldatum: 'checked_at',
    },
  },
  threat_sources: {
    sheet: 'Hotkällor',
    required: true,
    columns: {
      CVE: 'cve_id',
      Källtyp: 'source_type',
      URL: 'url',
      'SHA-256': 'sha256',
      'Källpostens uppdateringsdatum': 'record_updated_at',
      Hämtningsdatum: 'fetched_at',
      'Kontrollerade fält': 'checked_fields',
    },
  },
  setup_accounts: {
    sheet: 'Setup och konton',
    required: true,
    columns: {
      'Produkt-ID': 'register_id',
      Produktfamilj: 'name',
      'Standardkonto / kontonamn – utan lösenord': 'account_name',
      Kontostatus: 'account_status',
      'Kontokällans modell-/versionsgräns': 'account_scope',
      'Officiell källa för konto/initial användare': 'account_source_url',
      'Setup / installation – länk': 'setup_url',
      'Dokument / instruktion': 'setup_title',
      Dokumenttyp: 'setup_doc_type',
      'Manualens omfattning / läsanvisning': 'setup_scope',
      Verifieringsstatus: 'setup_verification',
      'Direkt hämtning – status': 'setup_fetch_status',
      'Kontroll / åtgärd vid driftsättning': 'commissioning_action',
      Kontrolldatum: 'checked_at',
      'Initial-/fabrikslösenord – typ (utan värden)': 'initial_password_type',
      'Byte / initial kontokonfiguration': 'initial_account_change',
      'Officiell källa för lösenordsstatus': 'password_status_source_url',
    },
  },
} as const;

export type SheetKey = keyof typeof SHEETS;
export interface RawRecord {
  row: number;
  fields: Record<string, string | null>;
  extra: Record<string, string | null>;
}
export interface RawSheetJson {
  sheet: string;
  import_version: string;
  file: string;
  file_sha256: string;
  header_row: number;
  headers: string[];
  column_map: Record<string, string>; // header -> key
  missing_headers: string[];
  extra_headers: string[];
  records: RawRecord[];
}

const PRESERVED_SHEETS = ['66 system och tjänster', 'Läs först', 'Sammanställning'];

function normalizeValue(cell: { value: string | null; type: string } | undefined): string | null {
  if (!cell || cell.value === null) return null;
  if (cell.type === 'd') return cell.value.slice(0, 10); // datum → YYYY-MM-DD
  const v = String(cell.value).trim();
  return v === '' ? null : v;
}

function readSheet(ws: XlsxSheet, columns: Record<string, string>): RawSheetJson {
  const headerCells = ws.rows.get(1);
  const headers: string[] = [];
  const headerByCol = new Map<string, string>();
  for (let i = 1; i <= ws.maxColumn; i++) {
    const col = columnIndexToLetter(i);
    const h = normalizeValue(headerCells?.get(col));
    if (h) {
      headers.push(h);
      headerByCol.set(col, h);
    }
  }
  const expected = Object.keys(columns);
  const missing = expected.filter((h) => !headers.includes(h));
  const extra = headers.filter((h) => !expected.includes(h));
  if (missing.length > 0) {
    throw new Error(`Bladet "${ws.name}" saknar rubriker: ${missing.join(' | ')}`);
  }
  const records: RawRecord[] = [];
  for (const [rowNum, cells] of [...ws.rows.entries()].sort((a, b) => a[0] - b[0])) {
    if (rowNum === 1) continue;
    const fields: Record<string, string | null> = {};
    const extraVals: Record<string, string | null> = {};
    let any = false;
    for (const [col, header] of headerByCol) {
      const v = normalizeValue(cells.get(col));
      if (v !== null) any = true;
      const key = columns[header];
      if (key) fields[key] = v;
      else extraVals[header] = v;
    }
    if (!any) continue;
    // alla kända nycklar ska finnas (null om tom)
    for (const key of Object.values(columns)) if (!(key in fields)) fields[key] = null;
    records.push({ row: rowNum, fields, extra: extraVals });
  }
  return {
    sheet: ws.name,
    import_version: IMPORT_VERSION,
    file: '',
    file_sha256: '',
    header_row: 1,
    headers,
    column_map: columns,
    missing_headers: missing,
    extra_headers: extra,
    records,
  };
}

export const CVE_RE = /CVE-\d{4}-\d{4,}/g;

export function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/[åä]/g, 'a')
    .replace(/ö/g, 'o')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/-{2,}/g, '-');
}

export interface ImportResult {
  sheets: Record<SheetKey, RawSheetJson>;
  report: Record<string, unknown>;
  conflicts: unknown[];
  idMap: Record<string, string>;
  reviewReport: {
    row: number;
    label: string;
    value: string | null;
    guidance_label: string | null;
    guidance_text: string | null;
  }[];
}

export function importRegister(file: string = DEFAULT_FILE): ImportResult {
  const wb = readXlsx(file);
  const sha256 = createHash('sha256').update(readFileSync(file)).digest('hex');
  const byName = new Map(wb.sheets.map((s) => [s.name, s]));
  const sheetNames = wb.sheets.map((s) => s.name);
  const deviations: string[] = [];

  const sheets = {} as Record<SheetKey, RawSheetJson>;
  for (const [key, def] of Object.entries(SHEETS) as [SheetKey, (typeof SHEETS)[SheetKey]][]) {
    const ws = byName.get(def.sheet);
    if (!ws) throw new Error(`Obligatoriskt blad saknas: ${def.sheet}`);
    const parsed = readSheet(ws, def.columns as Record<string, string>);
    parsed.file = basename(file);
    parsed.file_sha256 = sha256;
    if (parsed.extra_headers.length)
      deviations.push(`${def.sheet}: extra rubriker ${parsed.extra_headers.join(' | ')}`);
    sheets[key] = parsed;
  }
  for (const name of PRESERVED_SHEETS) {
    if (!byName.has(name)) deviations.push(`Bevarat originalblad saknas: ${name}`);
  }
  // Granskningsrapport: nyckel/värde-blad (A = etikett, B = tal/status, D/E = läsanvisning). Importeras som kontrolltal.
  const gr = byName.get('Granskningsrapport');
  const reviewReport: {
    row: number;
    label: string;
    value: string | null;
    guidance_label: string | null;
    guidance_text: string | null;
  }[] = [];
  if (gr) {
    for (const [rowNum, cells] of [...gr.rows.entries()].sort((a, b) => a[0] - b[0])) {
      const label = normalizeValue(cells.get('A'));
      if (!label) continue;
      reviewReport.push({
        row: rowNum,
        label,
        value: normalizeValue(cells.get('B')),
        guidance_label: normalizeValue(cells.get('D')),
        guidance_text: normalizeValue(cells.get('E')),
      });
    }
    if (reviewReport.every((r) => r.value === null))
      deviations.push('Granskningsrapport: inga värden i kolumn B.');
  } else deviations.push('Bladet Granskningsrapport saknas.');

  const reg = sheets.register.records;
  const vul = sheets.vulnerabilities.records;
  const ids = reg.map((r) => r.fields.register_id!);
  const dupIds = ids.filter((id, i) => ids.indexOf(id) !== i);
  if (dupIds.length) throw new Error(`Dubblerade register-ID: ${[...new Set(dupIds)].join(', ')}`);
  const products = reg.filter((r) => r.fields.category !== 'Tjänst');
  const services = reg.filter((r) => r.fields.category === 'Tjänst');
  const origin = countBy(reg, (r) => r.fields.origin ?? '(saknas)');
  const uniqueCves = new Set(vul.map((r) => r.fields.cve_id!));
  const badCves = [...uniqueCves].filter((c) => !/^CVE-\d{4}-\d{4,}$/.test(c));
  const relKeys = vul.map((r) => `${r.fields.register_id}|${r.fields.cve_id}`);
  const dupRel = relKeys.filter((k, i) => relKeys.indexOf(k) !== i);
  const unknownPid = vul
    .filter((r) => !ids.includes(r.fields.register_id!))
    .map((r) => r.fields.register_id);
  const kevRows = vul.filter((r) => r.fields.kev === 'Ja');
  const truncated = reg
    .filter((r) => /ytterligare \d+/.test(r.fields.cve_selection ?? ''))
    .map((r) => r.fields.register_id);
  const dateMixed = reg.filter(
    (r) => r.fields.source_date && !/^\d{4}-\d{2}-\d{2}$/.test(r.fields.source_date),
  ).length;
  if (dateMixed)
    deviations.push(
      `Register: ${dateMixed} rader har Källdatum som fritext i stället för datum (bevaras verbatim).`,
    );
  if (truncated.length)
    deviations.push(
      `Register: CVE-urvalet är trunkerat ("ytterligare N") för ${truncated.length} poster – relationerna hämtas från Sårbarheter.`,
    );
  const multiProductCves = [...countBy(vul, (r) => r.fields.cve_id!).entries()]
    .filter(([, n]) => n > 1)
    .map(([c]) => c);
  const tiPairs = new Set(
    sheets.threat_intel.records.map((r) => `${r.fields.register_id}|${r.fields.cve_id}`),
  );
  const tiUnmatched = sheets.threat_intel.records.filter(
    (r) => !relKeys.includes(`${r.fields.register_id}|${r.fields.cve_id}`),
  ).length;
  if (tiUnmatched)
    deviations.push(
      `Hotunderlag: ${tiUnmatched} rader avser CVE som i Sårbarheter är kopplade till fler produkter; hotunderlaget kopplas per CVE, inte per produkt.`,
    );
  void tiPairs;

  // Jämför arbetsbokens egna kontrolltal (Granskningsrapport) med beräknade tal
  const reported = (label: string): number | null => {
    const r = reviewReport.find((x) => x.label === label);
    return r && r.value !== null && /^\d+$/.test(r.value) ? Number(r.value) : null;
  };
  const controlTotals: Record<string, { reported: number | null; computed: number }> = {
    Originalposter: { reported: reported('Originalposter'), computed: origin.get('Original') ?? 0 },
    'Original: produkter': {
      reported: reported('Original: produkter'),
      computed: reg.filter((r) => r.fields.origin === 'Original' && r.fields.category !== 'Tjänst')
        .length,
    },
    'Original: protokoll/tjänster': {
      reported: reported('Original: protokoll/tjänster'),
      computed: reg.filter((r) => r.fields.origin === 'Original' && r.fields.category === 'Tjänst')
        .length,
    },
    'Nya produktfamiljer': {
      reported: reported('Nya produktfamiljer'),
      computed: origin.get('Ny') ?? 0,
    },
    'Totalt i Register': { reported: reported('Totalt i Register'), computed: reg.length },
    'Unika CVE i verifierat urval': {
      reported: reported('Unika CVE i verifierat urval'),
      computed: uniqueCves.size,
    },
    'CVE-/produktrelationer': {
      reported: reported('CVE-/produktrelationer'),
      computed: vul.length,
    },
    'Unika CVE med KEV-träff': {
      reported: reported('Unika CVE med KEV-träff'),
      computed: new Set(kevRows.map((r) => r.fields.cve_id)).size,
    },
    'Kontrollerade CVE': {
      reported: reported('Kontrollerade CVE'),
      computed: sheets.threat_intel.records.length,
    },
    'Poster i dokumentöversikten': {
      reported: reported('Poster i dokumentöversikten'),
      computed: sheets.setup_accounts.records.length,
    },
  };
  for (const [label, t] of Object.entries(controlTotals)) {
    if (t.reported !== null && t.reported !== t.computed)
      deviations.push(
        `Granskningsrapport: "${label}" anger ${t.reported} men beräknat värde är ${t.computed}.`,
      );
  }

  /* --- ID-mappning (idempotent) --- */
  const idMapPath = p('sources', 'curated', 'register_id_map.json');
  const existingMap: Record<string, string> = existsSync(idMapPath) ? readJson(idMapPath) : {};
  const idMap: Record<string, string> = { ...existingMap };
  const existingPf = loadPublicOrCurated('product_families.json');
  const existingSvc = loadPublicOrCurated('protocol_services.json');
  const existingByRow = new Map<number, { id: string; name: string; aliases: string[] }>();
  for (const e of [...existingPf, ...existingSvc])
    existingByRow.set(e.original.row, { id: e.id, name: e.name, aliases: e.aliases ?? [] });
  const vendorMap = loadCuratedRecord<{ vendor_id: string }>('register_vendors.json', 'rows');
  const usedIds = new Set(Object.values(idMap));
  let created = 0;
  let unchanged = 0;
  for (const r of reg) {
    const rid = r.fields.register_id!;
    if (idMap[rid]) {
      unchanged++;
      continue;
    }
    const m = /^Original rad (\d+)$/.exec(r.fields.origin_reference ?? '');
    let pid: string | null = null;
    if (m) {
      const ex = existingByRow.get(Number(m[1]));
      if (ex) pid = ex.id;
    }
    if (!pid) {
      const isSvc = r.fields.category === 'Tjänst';
      const vendorSlug = vendorMap[rid]?.vendor_id?.replace(/^vendor-/, '');
      const nameSlug = slugify(r.fields.name ?? rid);
      let base = `${isSvc ? 'svc' : 'pf'}-${vendorSlug && !nameSlug.startsWith(vendorSlug) ? `${vendorSlug}-` : ''}${nameSlug}`;
      if (!/^[a-z0-9]+(?:-[a-z0-9.]+)*$/.test(base))
        base = `${isSvc ? 'svc' : 'pf'}-${slugify(rid)}`;
      let candidate = base;
      let n = 2;
      while (usedIds.has(candidate)) candidate = `${base}-${n++}`;
      pid = candidate;
    }
    idMap[rid] = pid;
    usedIds.add(pid);
    created++;
  }

  /* --- Konflikter mot befintliga projektuppgifter (rapporteras, skrivs inte över) --- */
  const conflicts: unknown[] = [];
  const curatedMatches = loadCuratedArray<{ product_family_id: string; cve_id: string }>(
    ...CURATED_FILES.matches,
  );
  for (const r of reg) {
    const m = /^Original rad (\d+)$/.exec(r.fields.origin_reference ?? '');
    if (!m) continue;
    const ex = existingByRow.get(Number(m[1]));
    if (!ex) {
      conflicts.push({
        type: 'missing_original_row',
        register_id: r.fields.register_id,
        row: Number(m[1]),
        detail: 'Originalraden finns inte i projektets katalog.',
      });
      continue;
    }
    if (ex.name !== r.fields.name)
      conflicts.push({
        type: 'name_mismatch',
        register_id: r.fields.register_id,
        project_id: ex.id,
        project_name: ex.name,
        register_name: r.fields.name,
      });
    const regCves = new Set(
      vul.filter((v) => v.fields.register_id === r.fields.register_id).map((v) => v.fields.cve_id!),
    );
    const projCves = new Set(
      curatedMatches.filter((cm) => cm.product_family_id === ex.id).map((cm) => cm.cve_id),
    );
    const onlyReg = [...regCves].filter((c) => !projCves.has(c));
    const onlyProj = [...projCves].filter((c) => !regCves.has(c));
    if (onlyReg.length || onlyProj.length) {
      conflicts.push({
        type: 'cve_set_difference',
        register_id: r.fields.register_id,
        project_id: ex.id,
        only_in_register: onlyReg.sort(),
        only_in_project: onlyProj.sort(),
        resolution:
          'Projektets kuraterade matchningar behålls; registrets relationer läggs till som register_relation. Granska manuellt.',
      });
    }
  }

  const report = {
    imported_at: nowIso(),
    import_version: IMPORT_VERSION,
    file: basename(file),
    sha256,
    sheets: sheetNames,
    preserved_original_sheets: PRESERVED_SHEETS.filter((n) => byName.has(n)),
    counts: {
      register_entries: reg.length,
      register_products: products.length,
      register_services: services.length,
      register_origin: Object.fromEntries(origin),
      categories: new Set(reg.map((r) => r.fields.category)).size,
      vulnerability_relations: vul.length,
      unique_cves: uniqueCves.size,
      products_with_cves: new Set(vul.map((r) => r.fields.register_id)).size,
      cves_in_multiple_products: multiProductCves.length,
      kev_rows: kevRows.length,
      kev_cves: kevRows.map((r) => r.fields.cve_id),
      review_rows: sheets.review.records.length,
      controls: sheets.controls.records.length,
      source_manifest: sheets.source_manifest.records.length,
      link_checks: sheets.link_checks.records.length,
      threat_intel: sheets.threat_intel.records.length,
      threat_sources: sheets.threat_sources.records.length,
      setup_accounts: sheets.setup_accounts.records.length,
    },
    id_map: { created, unchanged, total: Object.keys(idMap).length, conflicted: conflicts.length },
    integrity: {
      bad_cve_ids: badCves,
      duplicate_relations: [...new Set(dupRel)],
      unknown_product_ids_in_vulnerabilities: [...new Set(unknownPid)],
    },
    workbook_control_totals: controlTotals,
    deviations,
    password_values_present: false,
    password_values_note:
      'Arbetsboken innehåller inga lösenordsvärden – endast kontonamn, lösenordstyp och bytekrav ("utan värden").',
  };

  return { sheets, report, conflicts, idMap, reviewReport };
}

function countBy<T>(arr: T[], f: (x: T) => string): Map<string, number> {
  const m = new Map<string, number>();
  for (const x of arr) m.set(f(x), (m.get(f(x)) ?? 0) + 1);
  return m;
}

function loadPublicOrCurated(
  file: string,
): { id: string; name: string; aliases?: string[]; original: { row: number } }[] {
  const pub = p('public', 'data', file);
  if (existsSync(pub)) return readJson(pub);
  // Fallback: härled ur overrides + workbook.json (första import)
  const ov = loadCuratedRecord<{ id: string; aliases?: string[] }>(...CURATED_FILES.overrides);
  const wbPath = p('sources', 'raw', 'workbook.json');
  if (!existsSync(wbPath)) return [];
  const wb = readJson<{
    records: { row: number; fields: { name: string | null; category: string | null } }[];
  }>(wbPath);
  const isSvc = file.startsWith('protocol');
  return wb.records
    .filter((r) => (r.fields.category === 'Tjänst') === isSvc)
    .map((r) => ({
      id: ov[String(r.row)]?.id ?? `row-${r.row}`,
      name: r.fields.name ?? '',
      aliases: ov[String(r.row)]?.aliases ?? [],
      original: { row: r.row },
    }));
}

export function writeImport(result: ImportResult): void {
  for (const [key, data] of Object.entries(result.sheets))
    writeJson(p(RAW_DIR, `${key}.json`), data);
  writeJson(p(RAW_DIR, 'import-report.json'), result.report);
  writeJson(p(RAW_DIR, 'review_report.json'), result.reviewReport);
  writeJson(p(RAW_DIR, 'conflicts.json'), result.conflicts);
  const idMapPath = p('sources', 'curated', 'register_id_map.json');
  const sorted = Object.fromEntries(
    Object.entries(result.idMap).sort(([a], [b]) => a.localeCompare(b)),
  );
  const current = existsSync(idMapPath) ? JSON.stringify(readJson(idMapPath)) : '';
  if (JSON.stringify(sorted) !== current) writeJson(idMapPath, sorted);
  // Städa bort filer från tidigare import som inte längre produceras
  for (const f of readdirSync(RAW_DIR)) {
    if (!f.endsWith('.json')) continue;
    const key = f.replace(/\.json$/, '');
    if (!(key in result.sheets) && !['import-report', 'conflicts', 'review_report'].includes(key)) {
      // lämna okända filer orörda men notera
      console.warn(`Varning: okänd fil i ${RAW_DIR}: ${f}`);
    }
  }
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  const fileArg =
    process.argv.find((a) => a.startsWith('--file='))?.slice(7) ??
    (process.argv.includes('--file')
      ? process.argv[process.argv.indexOf('--file') + 1]
      : undefined);
  const file = fileArg ? p(fileArg) : DEFAULT_FILE;
  try {
    const res = importRegister(file);
    writeImport(res);
    const c = res.report.counts as Record<string, unknown>;
    const idm = res.report.id_map as Record<string, number>;
    console.log(
      `Registerimport OK: ${c.register_entries} poster (${c.register_products} produkter, ${c.register_services} tjänster), ${c.unique_cves} unika CVE i ${c.vulnerability_relations} relationer, KEV ${c.kev_rows}. ID-mappning: ${idm.created} nya, ${idm.unchanged} oförändrade, ${idm.conflicted} konfliktposter. Avvikelser: ${(res.report.deviations as string[]).length}.`,
    );
    for (const d of res.report.deviations as string[]) console.log('  avvikelse:', d);
  } catch (err) {
    console.error('Registerimport misslyckades:', err instanceof Error ? err.message : err);
    process.exit(1);
  }
}

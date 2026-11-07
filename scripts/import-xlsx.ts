/**
 * Steg B1 – Reproducerbar import av arbetsboken.
 *
 * Läser ALLA blad och celler i den bifogade .xlsx-filen och skriver:
 *   sources/raw/workbook.json       – varje cell verbatim med blad/rad/kolumn
 *   sources/raw/import-report.json  – fält, null-värden, dubbletter, kategorier, antaganden
 *
 * Skriptet fallerar om antalet dataposter inte är 66 eller om rubrikerna avviker,
 * så att en ändrad arbetsbok aldrig tyst ger en annan katalog.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { readXlsx, columnIndexToLetter, type XlsxSheet } from './lib/xlsx';
import { p, writeJson, nowIso } from './lib/fs';

export const WORKBOOK_FILENAME = 'OT_IoT_sarbarhetsoversikt_66_system_2026-11-07.xlsx';
export const WORKBOOK_PATH = p('sources', 'original', WORKBOOK_FILENAME);
export const DATA_SHEET = '66 system och tjänster';

/** Förväntade rubriker (kolumn A–O) – avvikelse stoppar importen. */
export const EXPECTED_HEADERS = [
  'Kategori',
  'System / produktfamilj',
  'Funktion',
  'Shodan-sökord (komplettera med net:...)',
  'Sårbarhetstyp / klass',
  'Vad risktypen innebär (ej exploitinstruktion)',
  'CVE / bulletin (urval)',
  'Berörd firmware / modell',
  'Fix / senaste offentlig uppgift',
  'Patchningsgrad / urval',
  'Rekommenderad defensiv kontroll',
  'Konfigurationsdokumentation (URL)',
  'Dokumentnivå / begränsning',
  'Källa till CVE/säkerhetsuppgift (URL)',
  'Prio vid publik exponering',
] as const;

/** Maskinläsbara fältnamn i samma ordning som kolumnerna. */
export const FIELD_KEYS = [
  'category',
  'name',
  'function',
  'shodan_query',
  'risk_type',
  'risk_explanation',
  'cve_bulletin',
  'affected_firmware',
  'fix',
  'patch_level',
  'defensive_control',
  'documentation_url',
  'documentation_level',
  'security_source_url',
  'priority_if_exposed',
] as const;
export type FieldKey = (typeof FIELD_KEYS)[number];

export const EXPECTED_ROW_COUNT = 66;

export interface RawCell {
  column: string;
  header: string | null;
  value: string | null;
}
export interface RawRow {
  row: number;
  cells: RawCell[];
}
export interface RawSheet {
  name: string;
  row_count: number;
  column_count: number;
  rows: RawRow[];
}
export interface WorkbookJson {
  imported_at: string;
  filename: string;
  sha256: string;
  sheets: RawSheet[];
  data_sheet: string;
  header_row: number;
  headers: string[];
  field_keys: readonly string[];
  records: WorkbookRecord[];
}
export interface ImportReport {
  imported_at: string;
  filename: string;
  sha256: string;
  sheets: { name: string; rows: number; columns: number }[];
  data_sheet: string;
  header_row: number;
  headers: string[];
  field_keys: readonly string[];
  counts: {
    total: number;
    product_families: number;
    protocol_services: number;
    categories: number;
    with_cve_bulletin: number;
    with_security_source_url: number;
    with_documentation_url: number;
  };
  null_counts: Record<string, number>;
  categories: Record<string, number>;
  duplicate_names: { name: string; rows: number[] }[];
  distinct_priority_values: [string, number][];
  distinct_patch_level_values: [string, number][];
  generic_control_text_rows: number[];
  industry_guide_documentation_rows: number[];
  assumptions: string[];
}
export interface WorkbookRecord {
  row: number;
  fields: Record<FieldKey, string | null>;
}

export function sha256File(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

export async function importWorkbook(path: string = WORKBOOK_PATH): Promise<{
  workbook: WorkbookJson;
  report: ImportReport;
}> {
  const wb = readXlsx(path);

  const sheets: RawSheet[] = [];
  const sheetByName = new Map<string, XlsxSheet>();
  for (const ws of wb.sheets) {
    sheetByName.set(ws.name, ws);
    const headerRow = ws.rows.get(1);
    const rows: RawRow[] = [];
    for (const [rowNumber, cells] of [...ws.rows.entries()].sort((a, b) => a[0] - b[0])) {
      const rawCells: RawCell[] = [];
      for (const cell of [...cells.values()].sort((a, b) => a.column.localeCompare(b.column))) {
        if (cell.value === null) continue;
        const header =
          ws.name === DATA_SHEET && rowNumber > 1
            ? (headerRow?.get(cell.column)?.value ?? null)
            : null;
        rawCells.push({ column: cell.column, header, value: cell.value });
      }
      if (rawCells.length > 0) rows.push({ row: rowNumber, cells: rawCells });
    }
    sheets.push({ name: ws.name, row_count: ws.maxRow, column_count: ws.maxColumn, rows });
  }

  const data = sheetByName.get(DATA_SHEET);
  if (!data) throw new Error(`Bladet "${DATA_SHEET}" saknas i arbetsboken.`);

  const headerCells = data.rows.get(1);
  const headers: string[] = [];
  for (let i = 1; i <= data.maxColumn; i++) {
    const v = headerCells?.get(columnIndexToLetter(i))?.value;
    if (v) headers.push(v);
  }
  const headerMismatch = EXPECTED_HEADERS.filter((h, i) => headers[i] !== h);
  if (headerMismatch.length > 0 || headers.length !== EXPECTED_HEADERS.length) {
    throw new Error(
      `Rubrikerna avviker från förväntat. Fick: ${JSON.stringify(headers)}; saknade/avvikande: ${JSON.stringify(headerMismatch)}`,
    );
  }

  const records: WorkbookRecord[] = [];
  for (const [rowNumber, cells] of [...data.rows.entries()].sort((a, b) => a[0] - b[0])) {
    if (rowNumber === 1) continue;
    const fields = {} as Record<FieldKey, string | null>;
    FIELD_KEYS.forEach((key, i) => {
      fields[key] = cells.get(columnIndexToLetter(i + 1))?.value ?? null;
    });
    if (Object.values(fields).every((v) => v === null)) continue;
    records.push({ row: rowNumber, fields });
  }

  if (records.length !== EXPECTED_ROW_COUNT) {
    throw new Error(`Förväntade ${EXPECTED_ROW_COUNT} dataposter, fann ${records.length}.`);
  }

  // Rapport
  const nullCounts: Record<string, number> = {};
  for (const key of FIELD_KEYS)
    nullCounts[key] = records.filter((r) => r.fields[key] === null).length;
  const categories: Record<string, number> = {};
  for (const r of records) {
    const c = r.fields.category ?? '(saknas)';
    categories[c] = (categories[c] ?? 0) + 1;
  }
  const nameCounts = new Map<string, number[]>();
  for (const r of records) {
    const n = (r.fields.name ?? '').toLowerCase();
    nameCounts.set(n, [...(nameCounts.get(n) ?? []), r.row]);
  }
  const duplicates = [...nameCounts.entries()].filter(([, rows]) => rows.length > 1);
  const distinct = (key: FieldKey) =>
    Object.entries(
      records.reduce<Record<string, number>>((acc, r) => {
        const v = r.fields[key] ?? '(saknas)';
        acc[v] = (acc[v] ?? 0) + 1;
        return acc;
      }, {}),
    ).sort((a, b) => b[1] - a[1]);

  const services = records.filter((r) => r.fields.category === 'Tjänst').length;
  const sha256 = sha256File(path);

  const report: ImportReport = {
    imported_at: nowIso(),
    filename: WORKBOOK_FILENAME,
    sha256,
    sheets: sheets.map((s) => ({ name: s.name, rows: s.rows.length, columns: s.column_count })),
    data_sheet: DATA_SHEET,
    header_row: 1,
    headers,
    field_keys: FIELD_KEYS,
    counts: {
      total: records.length,
      product_families: records.length - services,
      protocol_services: services,
      categories: Object.keys(categories).length,
      with_cve_bulletin: records.length - nullCounts.cve_bulletin!,
      with_security_source_url: records.length - nullCounts.security_source_url!,
      with_documentation_url: records.length - nullCounts.documentation_url!,
    },
    null_counts: nullCounts,
    categories,
    duplicate_names: duplicates.map(([name, rows]) => ({ name, rows })),
    distinct_priority_values: distinct('priority_if_exposed'),
    distinct_patch_level_values: distinct('patch_level'),
    generic_control_text_rows: records
      .filter((r) => r.fields.defensive_control?.startsWith('Ingen publik direktadministration'))
      .map((r) => r.row),
    industry_guide_documentation_rows: records
      .filter((r) => {
        const url = r.fields.documentation_url;
        if (!url) return false;
        try {
          const host = new URL(url).hostname.toLowerCase();
          return host === 'csrc.nist.gov' || host.endsWith('.csrc.nist.gov');
        } catch {
          return false;
        }
      })
      .map((r) => r.row),
    assumptions: [
      'Rad 1 är rubrikrad; rad 2–67 är dataposter. Tomma rader ignoreras.',
      'Kategorin "Tjänst" klassificeras som protokoll/tjänst; alla övriga som produktfamilj.',
      'Cellvärden bevaras verbatim (trimmas ej, förutom att tomma strängar blir null).',
      'URL:er i kolumn L och N är klartext i arbetsboken (inga hyperlänkobjekt).',
      'Kolumn O ("Prio vid publik exponering") tolkas som villkorlig inventeringssignal, inte risknivå.',
      'Fältet "CVE / bulletin (urval)" kan innehålla bulletin-ID (ej CVE) och oexpanderade intervall; dessa expanderas inte här.',
    ],
  };

  const workbook: WorkbookJson = {
    imported_at: report.imported_at,
    filename: WORKBOOK_FILENAME,
    sha256,
    sheets,
    data_sheet: DATA_SHEET,
    header_row: 1,
    headers,
    field_keys: FIELD_KEYS,
    records,
  };
  return { workbook, report };
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  importWorkbook()
    .then(({ workbook, report }) => {
      writeJson(p('sources', 'raw', 'workbook.json'), workbook);
      writeJson(p('sources', 'raw', 'import-report.json'), report);
      console.log(
        `Import OK: ${report.counts.total} poster (${report.counts.product_families} produktfamiljer, ${report.counts.protocol_services} tjänster, ${report.counts.categories} kategorier). sha256=${workbook.sha256}`,
      );
    })
    .catch((err) => {
      console.error('Import misslyckades:', err instanceof Error ? err.message : err);
      process.exit(1);
    });
}

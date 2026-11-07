import { FORBIDDEN_PUBLIC_KEYS } from '@schemas/index';
import type { Manifest } from '@schemas/index';
import type { IndexedDataset, CatalogEntry } from '@/data/loader';
import { isProduct } from '@/data/loader';
import type { CatalogFilters } from './filters';
import { serializeFilters, deriveEntry } from './filters';

export interface ExportRow {
  id: string;
  kind: string;
  name: string;
  vendor: string | null;
  category: string;
  function_text: string;
  risk_type: string | null;
  risk_explanation: string | null;
  cve_ids: string;
  kev_listed: boolean;
  advisory_ids: string;
  affected_versions: string;
  fix_status: string;
  recommended_action: string;
  verification_status: string;
  data_quality_flags: string;
  documentation_urls: string;
  source_urls: string;
  excel_row: number;
  // Registerimport
  register_id: string | null;
  origin: string | null;
  register_source_status: string | null;
  register_priority_if_exposed: string | null;
  observed_exposure: string | null;
  account_name: string | null;
  initial_password_type: string | null;
  initial_password_type_text: string | null;
  change_requirement: string | null;
  setup_url: string | null;
  setup_doc_type: string | null;
  setup_manual_verified: boolean | null;
  poc_statuses: string;
  material_types: string;
  review_status: string | null;
}

export interface ExportBundle {
  metadata: {
    exported_at: string;
    dataset_generated_at: string;
    workbook_sha256: string;
    workbook_filename: string;
    schema_version: string;
    dataset_tier: 'public';
    filter: Record<string, string>;
    count: number;
    disclaimer: string;
  };
  rows: ExportRow[];
}

export const EXPORT_DISCLAIMER =
  'Publik produkt- och hotkunskapsbas. Innehåller inga anläggningsunika uppgifter. Frånvaro av CVE är inte bevis för frånvaro av sårbarheter; exponering är aldrig bekräftad i denna export.';

export function buildExportRows(d: IndexedDataset, entries: CatalogEntry[]): ExportRow[] {
  return entries.map((e) => {
    const der = deriveEntry(d, e);
    const matches = isProduct(e) ? (d.matchesByProduct.get(e.id) ?? []) : [];
    const sourceUrls = e.source_ids
      .map((id) => d.sourceById.get(id)?.url)
      .filter((u): u is string => Boolean(u));
    return {
      id: e.id,
      kind: e.kind,
      name: e.name,
      vendor: der.vendorName,
      category: e.category,
      function_text: e.function_text,
      risk_type: e.risk_summary.type_text,
      risk_explanation: e.risk_summary.explanation_text,
      cve_ids: der.cveIds.join('; '),
      kev_listed: der.kevListed,
      advisory_ids: e.advisory_ids
        .map((id) => d.advisoryById.get(id)?.advisory_id ?? id)
        .join('; '),
      affected_versions: matches
        .map(
          (m) =>
            `${m.component ? m.component + ': ' : ''}${m.affected_versions_text} [${m.status}]`,
        )
        .join(' | '),
      fix_status: [...new Set(matches.map((m) => m.fix.available))].join('; '),
      recommended_action: e.risk.recommended_action,
      verification_status: e.verification_status,
      data_quality_flags: e.data_quality_flags.join('; '),
      documentation_urls: e.documentation.map((x) => x.url).join(' '),
      source_urls: sourceUrls.join(' '),
      excel_row: e.original.row,
      register_id: e.register?.register_id ?? null,
      origin: der.origin,
      register_source_status: e.register?.source_status_text ?? null,
      register_priority_if_exposed: e.register?.priority_text ?? null,
      observed_exposure: e.register?.observed_exposure_text ?? null,
      account_name: e.credentials?.account_name ?? null,
      initial_password_type: e.credentials?.initial_password_type ?? null,
      initial_password_type_text: e.credentials?.initial_password_type_text ?? null,
      change_requirement: e.credentials?.change_requirement_text ?? null,
      setup_url: e.setup_documentation?.url ?? null,
      setup_doc_type: e.setup_documentation?.doc_type ?? null,
      setup_manual_verified: e.setup_documentation?.is_verified_setup_manual ?? null,
      poc_statuses: der.pocStatuses.join('; '),
      material_types: der.materialCodes.join('; '),
      review_status: e.review_findings[0]?.status_text ?? null,
    };
  });
}

/** Rad i kontosammanställningen (/konton). Inga lösenordsvärden finns i modellen. */
export interface AccountExportRow {
  id: string;
  kind: string;
  name: string;
  register_id: string | null;
  vendor: string | null;
  category: string;
  account_name: string | null;
  account_name_text: string | null;
  account_status: string | null;
  account_scope: string | null;
  initial_password_type: string;
  initial_password_type_text: string | null;
  change_requirement: string | null;
  commissioning_action: string | null;
  verification_status: string;
  account_source_url: string | null;
  password_status_source_url: string | null;
}

export function buildAccountRows(d: IndexedDataset, entries: CatalogEntry[]): AccountExportRow[] {
  return entries
    .filter((e) => e.credentials)
    .map((e) => {
      const c = e.credentials!;
      return {
        id: e.id,
        kind: e.kind,
        name: e.name,
        register_id: e.register?.register_id ?? null,
        vendor: isProduct(e) ? (d.vendorById.get(e.vendor_id)?.name ?? null) : null,
        category: e.category,
        account_name: c.account_name,
        account_name_text: c.account_name_text,
        account_status: c.account_status_text,
        account_scope: c.account_scope_text,
        initial_password_type: c.initial_password_type,
        initial_password_type_text: c.initial_password_type_text,
        change_requirement: c.change_requirement_text,
        commissioning_action: c.commissioning_action_text,
        verification_status: c.verification_status,
        account_source_url: c.account_source_id
          ? (d.sourceById.get(c.account_source_id)?.url ?? null)
          : null,
        password_status_source_url: c.password_status_source_id
          ? (d.sourceById.get(c.password_status_source_id)?.url ?? null)
          : null,
      };
    });
}

export interface AccountExportBundle {
  metadata: ExportBundle['metadata'] & { note: string };
  rows: AccountExportRow[];
}

export function buildAccountBundle(
  d: IndexedDataset,
  entries: CatalogEntry[],
  filter: Record<string, string>,
  now: Date = new Date(),
): AccountExportBundle {
  const m: Manifest = d.manifest;
  const rows = buildAccountRows(d, entries);
  const bundle: AccountExportBundle = {
    metadata: {
      exported_at: now.toISOString(),
      dataset_generated_at: m.generated_at,
      workbook_sha256: m.workbook.sha256,
      workbook_filename: m.workbook.filename,
      schema_version: m.schema_version,
      dataset_tier: 'public',
      filter,
      count: rows.length,
      disclaimer: EXPORT_DISCLAIMER,
      note: 'Underlaget innehåller inga lösenordsvärden; endast kontonamn, lösenordstyp och bytekrav.',
    },
    rows,
  };
  assertNoForbiddenKeys(bundle);
  return bundle;
}

export function accountsToCsv(bundle: AccountExportBundle): string {
  const header: (keyof AccountExportRow)[] = [
    'id',
    'kind',
    'name',
    'register_id',
    'vendor',
    'category',
    'account_name',
    'account_name_text',
    'account_status',
    'account_scope',
    'initial_password_type',
    'initial_password_type_text',
    'change_requirement',
    'commissioning_action',
    'verification_status',
    'account_source_url',
    'password_status_source_url',
  ];
  const meta = Object.entries(bundle.metadata)
    .filter(([k]) => k !== 'filter')
    .map(([k, v]) => `# ${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`);
  const lines = [
    ...meta,
    `# filter: ${JSON.stringify(bundle.metadata.filter)}`,
    header.join(','),
    ...bundle.rows.map((r) => header.map((h) => csvEscape(r[h])).join(',')),
  ];
  return '\ufeff' + lines.join('\r\n') + '\r\n';
}

export function buildExportBundle(
  d: IndexedDataset,
  entries: CatalogEntry[],
  filters: CatalogFilters,
  now: Date = new Date(),
): ExportBundle {
  const m: Manifest = d.manifest;
  const bundle: ExportBundle = {
    metadata: {
      exported_at: now.toISOString(),
      dataset_generated_at: m.generated_at,
      workbook_sha256: m.workbook.sha256,
      workbook_filename: m.workbook.filename,
      schema_version: m.schema_version,
      dataset_tier: 'public',
      filter: Object.fromEntries(serializeFilters(filters).entries()),
      count: entries.length,
      disclaimer: EXPORT_DISCLAIMER,
    },
    rows: buildExportRows(d, entries),
  };
  assertNoForbiddenKeys(bundle);
  return bundle;
}

export function assertNoForbiddenKeys(obj: unknown, path = ''): void {
  if (Array.isArray(obj)) {
    obj.forEach((v, i) => assertNoForbiddenKeys(v, `${path}[${i}]`));
    return;
  }
  if (obj && typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      if ((FORBIDDEN_PUBLIC_KEYS as readonly string[]).includes(k)) {
        throw new Error(`Förbjuden nyckel i export: ${path}.${k}`);
      }
      assertNoForbiddenKeys(v, `${path}.${k}`);
    }
  }
}

function csvEscape(v: unknown): string {
  const s = v === null || v === undefined ? '' : String(v);
  // Skydd mot formelinjektion i kalkylprogram
  const guarded = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return /[",\n\r;]/.test(guarded) ? `"${guarded.replace(/"/g, '""')}"` : guarded;
}

const EXPORT_COLUMNS: (keyof ExportRow)[] = [
  'id',
  'kind',
  'name',
  'vendor',
  'category',
  'function_text',
  'risk_type',
  'risk_explanation',
  'cve_ids',
  'kev_listed',
  'advisory_ids',
  'affected_versions',
  'fix_status',
  'recommended_action',
  'verification_status',
  'data_quality_flags',
  'documentation_urls',
  'source_urls',
  'excel_row',
  'register_id',
  'origin',
  'register_source_status',
  'register_priority_if_exposed',
  'observed_exposure',
  'account_name',
  'initial_password_type',
  'initial_password_type_text',
  'change_requirement',
  'setup_url',
  'setup_doc_type',
  'setup_manual_verified',
  'poc_statuses',
  'material_types',
  'review_status',
];

export function toCsv(bundle: ExportBundle): string {
  const header: string[] = EXPORT_COLUMNS;
  const meta = Object.entries(bundle.metadata)
    .filter(([k]) => k !== 'filter')
    .map(([k, v]) => `# ${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`);
  const filter = `# filter: ${JSON.stringify(bundle.metadata.filter)}`;
  const lines = [
    ...meta,
    filter,
    header.join(','),
    ...bundle.rows.map((r) =>
      header.map((h) => csvEscape((r as unknown as Record<string, unknown>)[h])).join(','),
    ),
  ];
  return '﻿' + lines.join('\r\n') + '\r\n';
}

export function downloadBlob(filename: string, content: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

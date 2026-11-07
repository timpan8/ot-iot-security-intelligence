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
    };
  });
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

export function toCsv(bundle: ExportBundle): string {
  const header = Object.keys(
    bundle.rows[0] ?? {
      id: '',
      kind: '',
      name: '',
      vendor: '',
      category: '',
      function_text: '',
      risk_type: '',
      risk_explanation: '',
      cve_ids: '',
      kev_listed: '',
      advisory_ids: '',
      affected_versions: '',
      fix_status: '',
      recommended_action: '',
      verification_status: '',
      data_quality_flags: '',
      documentation_urls: '',
      source_urls: '',
      excel_row: '',
    },
  );
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

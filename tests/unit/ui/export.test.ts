import { describe, expect, it } from 'vitest';
import { FORBIDDEN_PUBLIC_KEYS } from '@schemas/index';
import { assertNoForbiddenKeys, buildExportBundle, toCsv } from '@/lib/export';
import { DEFAULT_FILTERS } from '@/lib/filters';
import { indexDataset } from '@/data/loader';
import { makeMockDataset } from './fixtures/mock-dataset';

describe('Export', () => {
  const d = indexDataset(makeMockDataset());
  it('innehåller metadata och inga förbjudna nycklar', () => {
    const bundle = buildExportBundle(
      d,
      d.entries,
      { ...DEFAULT_FILTERS, q: 'danfoss' },
      new Date('2026-11-07T12:00:00Z'),
    );
    expect(bundle.metadata.exported_at).toBe('2026-11-07T12:00:00.000Z');
    expect(bundle.metadata.dataset_generated_at).toBe(d.manifest.generated_at);
    expect(bundle.metadata.workbook_sha256).toBe(d.manifest.workbook.sha256);
    expect(bundle.metadata.filter).toEqual({ q: 'danfoss' });
    expect(bundle.metadata.count).toBe(d.entries.length);
    expect(bundle.rows.length).toBe(d.entries.length);
    const json = JSON.stringify(bundle);
    for (const k of FORBIDDEN_PUBLIC_KEYS) expect(json).not.toContain(`"${k}":`);
  });
  it('stoppar förbjudna nycklar', () => {
    expect(() => assertNoForbiddenKeys({ a: { ip_address: '10.0.0.1' } })).toThrow(/ip_address/);
    expect(() => assertNoForbiddenKeys([{ serial: 'x' }])).toThrow(/serial/);
  });
  it('CSV skyddar mot formelinjektion och innehåller metadata-rader', () => {
    const bundle = buildExportBundle(d, d.entries, DEFAULT_FILTERS);
    bundle.rows[0]!.name = '=HYPERLINK("https://evil")';
    const csv = toCsv(bundle);
    expect(csv).toContain('# dataset_tier: public');
    expect(csv).toContain("'=HYPERLINK");
    expect(csv.startsWith('﻿')).toBe(true);
  });
});

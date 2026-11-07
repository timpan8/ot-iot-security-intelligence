import { describe, expect, it } from 'vitest';
import {
  EXPECTED_HEADERS,
  FIELD_KEYS,
  importWorkbook,
  WORKBOOK_PATH,
} from '../../../scripts/import-xlsx';

describe('import-xlsx (verklig arbetsbok)', () => {
  it('läser alla tre blad och exakt 66 poster: 55 produktfamiljer, 11 tjänster, 18 kategorier', async () => {
    const { workbook, report } = await importWorkbook(WORKBOOK_PATH);
    expect(workbook.sheets.map((s) => s.name)).toEqual([
      '66 system och tjänster',
      'Läs först',
      'Sammanställning',
    ]);
    expect(report.counts.total).toBe(66);
    expect(report.counts.product_families).toBe(55);
    expect(report.counts.protocol_services).toBe(11);
    expect(report.counts.categories).toBe(18);
    expect(report.counts.with_cve_bulletin).toBe(8);
    expect(report.counts.with_security_source_url).toBe(10);
    expect(report.duplicate_names).toEqual([]);
  });

  it('bevarar rubriker, fältnyckelordning och radnummer för spårbarhet', async () => {
    const { workbook } = await importWorkbook(WORKBOOK_PATH);
    expect(workbook.headers).toEqual([...EXPECTED_HEADERS]);
    expect(workbook.field_keys).toEqual([...FIELD_KEYS]);
    expect(workbook.records[0]?.row).toBe(2);
    expect(workbook.records[65]?.row).toBe(67);
    expect(
      workbook.records.every((r) => r.fields.priority_if_exposed === 'P1 vid publik åtkomst'),
    ).toBe(true);
    expect(workbook.sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it('bevarar oexpanderat CVE-intervall och bulletin-ID verbatim', async () => {
    const { workbook } = await importWorkbook(WORKBOOK_PATH);
    const e3 = workbook.records.find((r) => r.fields.name === 'Copeland E3');
    expect(e3?.fields.cve_bulletin).toBe('CVE-2025-6519; CVE-2025-52543–52550');
    const s71500 = workbook.records.find((r) => r.fields.name === 'Siemens S7-1500');
    expect(s71500?.fields.cve_bulletin).toBe('SSA-568427 (se bulletin)');
  });
});

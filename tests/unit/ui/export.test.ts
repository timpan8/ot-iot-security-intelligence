import { describe, expect, it } from 'vitest';
import { FORBIDDEN_PUBLIC_KEYS } from '@schemas/index';
import {
  accountsToCsv,
  assertNoForbiddenKeys,
  buildAccountBundle,
  buildExportBundle,
  toCsv,
} from '@/lib/export';
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
  it('stoppar lösenordsnycklar i export', () => {
    for (const k of [
      'password',
      'password_value',
      'passwd',
      'secret',
      'api_key',
      'credential_value',
    ]) {
      expect((FORBIDDEN_PUBLIC_KEYS as readonly string[]).includes(k)).toBe(true);
      expect(() => assertNoForbiddenKeys({ rows: [{ [k]: 'hemligt' }] })).toThrow(k);
    }
  });
  it('kontoexport innehåller lösenordstyp men inga lösenordsvärden', () => {
    const raw = makeMockDataset();
    raw.product_families[0]!.credentials = {
      account_name: 'Supervisor',
      account_name_text: 'Supervisor',
      account_status_text: 'Dokumenterat fabriksnamn',
      account_scope_text: 'Gäller inte automatiskt 800A',
      account_source_id: null,
      initial_password_type: 'shared_default_documented',
      initial_password_type_text: 'Gemensamt standardlösenord dokumenterat',
      change_requirement_text: 'Byt kvarvarande standardlösenord före skyddad drift.',
      commissioning_action_text: null,
      password_status_source_id: null,
      verification_status: 'needs_review',
      checked_at: '2026-11-07',
      note: 'Underlaget innehåller inga lösenordsvärden; endast kontonamn, lösenordstyp och bytekrav.',
    };
    const dd = indexDataset(raw);
    const bundle = buildAccountBundle(
      dd,
      dd.entries,
      { pwdType: 'all' },
      new Date('2026-11-07T12:00:00Z'),
    );
    expect(bundle.rows).toHaveLength(1);
    expect(bundle.rows[0]!.account_name).toBe('Supervisor');
    expect(bundle.rows[0]!.initial_password_type).toBe('shared_default_documented');
    expect(JSON.stringify(bundle)).not.toMatch(/"password":/);
    const csv = accountsToCsv(bundle);
    expect(csv).toContain('initial_password_type');
    expect(csv).toContain('# note: Underlaget innehåller inga lösenordsvärden');
    expect(csv).not.toMatch(/,password,/);
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

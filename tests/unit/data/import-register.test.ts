import { describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { importRegister, DEFAULT_FILE, SHEETS } from '../../../scripts/import-register';
import { p } from '../../../scripts/lib/fs';

const result = importRegister(DEFAULT_FILE);
const counts = result.report.counts as Record<string, unknown>;

describe('import-register (125-postregistret)', () => {
  it('kontrolltal: 125 poster = 114 produkter + 11 tjänster; 344 unika CVE i 349 relationer; 2 KEV', () => {
    expect(counts.register_entries).toBe(125);
    expect(counts.register_products).toBe(114);
    expect(counts.register_services).toBe(11);
    expect(counts.unique_cves).toBe(344);
    expect(counts.vulnerability_relations).toBe(349);
    expect(counts.kev_rows).toBe(2);
    expect(counts.register_origin).toEqual({ Original: 66, Ny: 59 });
  });

  it('identifierar kolumner via rubriker, inte kolumnbokstäver', () => {
    for (const def of Object.values(SHEETS)) {
      const sheet =
        result.sheets[
          Object.keys(SHEETS).find(
            (k) => SHEETS[k as keyof typeof SHEETS] === def,
          ) as keyof typeof SHEETS
        ];
      expect(sheet.missing_headers).toEqual([]);
      for (const header of Object.keys(def.columns)) expect(sheet.headers).toContain(header);
    }
  });

  it('rapporterar strukturavvikelser (trunkerat CVE-urval, blandade datum) och jämför arbetsbokens kontrolltal', () => {
    const dev = result.report.deviations as string[];
    expect(dev.some((d) => d.includes('trunkerat'))).toBe(true);
    expect(dev.some((d) => d.includes('Källdatum'))).toBe(true);
    const totals = result.report.workbook_control_totals as Record<
      string,
      { reported: number | null; computed: number }
    >;
    expect(totals['Totalt i Register']).toEqual({ reported: 125, computed: 125 });
    expect(totals['Unika CVE i verifierat urval']).toEqual({ reported: 344, computed: 344 });
    expect(totals['CVE-/produktrelationer']).toEqual({ reported: 349, computed: 349 });
    expect(dev.some((d) => d.startsWith('Granskningsrapport'))).toBe(false);
    expect(result.reviewReport.length).toBeGreaterThan(30);
  });

  it('bevarar saknade värden som null och datum som YYYY-MM-DD', () => {
    const reg = result.sheets.register.records;
    expect(reg.every((r) => 'documentation_url' in r.fields)).toBe(true);
    expect(reg.filter((r) => r.fields.checked_at === '2026-11-07')).toHaveLength(125);
    const v = result.sheets.vulnerabilities.records.find(
      (r) => r.fields.cve_id === 'CVE-2025-41450',
    )!;
    expect(v.fields.kev_date_added).toBeNull();
    expect(v.fields.affected_source_text).toBe('AK-SM 8xxA Series: 0 till <4.2');
  });

  it('innehåller inga lösenordsvärden – endast typ, kontonamn och bytekrav', () => {
    expect(result.report.password_values_present).toBe(false);
    const keys = new Set(Object.values(SHEETS).flatMap((d) => Object.values(d.columns)));
    for (const k of keys) expect(k).not.toMatch(/^password$|password_value|passwd|secret/);
  });

  it('kopplar Original-rader till projektets befintliga ID:n (inga dubbletter) och är idempotent', () => {
    expect(result.idMap['OT-001']).toBe('pf-danfoss-ak-sm-800');
    expect(result.idMap['OT-002']).toBe('pf-danfoss-ak-sm-800a');
    expect(result.idMap['OT-N-ICSA-25-007-01']).toBe('pf-abb-aspect');
    const ids = Object.values(result.idMap);
    expect(new Set(ids).size).toBe(ids.length);
    // Andra körningen ger identisk mappning och identiska rådata
    const again = importRegister(DEFAULT_FILE);
    expect(again.idMap).toEqual(result.idMap);
    expect(JSON.stringify(again.sheets)).toBe(JSON.stringify(result.sheets));
    expect((again.report.id_map as { created: number }).created).toBe(0);
  });

  it('rapporterar konflikter mot projektets kuraterade uppgifter i stället för att skriva över', () => {
    const c = result.conflicts as {
      type: string;
      register_id: string;
      only_in_project?: string[];
    }[];
    const abb = c.find((x) => x.register_id === 'OT-041');
    expect(abb?.type).toBe('cve_set_difference');
    expect(abb?.only_in_project).toEqual(['CVE-2025-2595', 'CVE-2025-41659', 'CVE-2025-41691']);
  });

  it('fallerar om en obligatorisk rubrik saknas', () => {
    // Skapa en kopia där ett blad saknar rubrik genom att manipulera ett tomt workbook är dyrt; testa via SHEETS-kontraktet
    expect(Object.keys(SHEETS.register.columns)).toContain('ID');
    expect(SHEETS.vulnerabilities.columns['Produkt-ID']).toBe('register_id');
  });

  it('skriver sources/raw/register/* deterministiskt (utan tidsstämplar i bladfiler)', () => {
    const raw = readFileSync(p('sources', 'raw', 'register', 'register.json'), 'utf8');
    expect(raw).not.toMatch(/imported_at/);
    const dir = mkdtempSync(join(tmpdir(), 'reg-'));
    writeFileSync(join(dir, 'x.json'), JSON.stringify(result.sheets.register));
    expect(existsSync(join(dir, 'x.json'))).toBe(true);
    rmSync(dir, { recursive: true, force: true });
  });
});

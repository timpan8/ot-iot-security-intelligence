import { describe, expect, it } from 'vitest';
import { buildDataset } from '../../../scripts/normalize';
import { validateDataset, loadExpectedCounts } from '../../../scripts/validate';
import {
  initialPasswordTypeCode,
  publicPocStatusCode,
  materialTypeCode,
  setupDocTypeCode,
  accountNameFromText,
} from '../../../scripts/normalize-register';

const ds = buildDataset();
const all = [...ds.product_families, ...ds.protocol_services];
const byId = <T extends { id: string }>(arr: T[]) => new Map(arr.map((x) => [x.id, x]));
const pfs = byId(ds.product_families);
const vulns = byId(ds.vulnerabilities);

describe('registerimport i normaliserad data', () => {
  it('125 poster med registerinformation: 66 original + 59 nya; protokoll separata', () => {
    expect(all).toHaveLength(125);
    expect(ds.product_families).toHaveLength(114);
    expect(ds.protocol_services).toHaveLength(11);
    const withReg = all.filter((e) => e.register);
    expect(withReg).toHaveLength(125);
    expect(withReg.filter((e) => e.register!.origin === 'original')).toHaveLength(66);
    expect(withReg.filter((e) => e.register!.origin === 'new')).toHaveLength(59);
    expect(new Set(withReg.map((e) => e.register!.register_id)).size).toBe(125);
    for (const s of ds.protocol_services) expect(s.match_ids).toEqual([]);
  });

  it('validerar mot importrapporternas kontrolltal', () => {
    const exp = loadExpectedCounts();
    expect(exp.register?.unique_cves).toBe(344);
    const res = validateDataset(ds, exp);
    expect(res.errors).toEqual([]);
  });

  it('produkt–CVE är en många-till-många-relation; 349 registerrelationer, 5 CVE i flera produkter', () => {
    const reg = ds.matches.filter((m) => m.register_relation);
    expect(reg).toHaveLength(349);
    const perCve = new Map<string, number>();
    for (const m of reg)
      perCve.set(m.vulnerability_id!, (perCve.get(m.vulnerability_id!) ?? 0) + 1);
    expect([...perCve.values()].filter((n) => n > 1)).toHaveLength(5);
    expect(new Set(reg.map((m) => m.vulnerability_id)).size).toBe(344);
  });

  it('bevarar projektets manuella bedömningar för originalposter (Danfoss, Desigo, AC500)', () => {
    const d = pfs.get('pf-danfoss-ak-sm-800a')!;
    const m = ds.matches.find((x) => x.id === 'match-danfoss-ak-sm-800a-cve-2025-41450')!;
    expect(m.verification_status).toBe('verified_primary');
    expect(m.register_relation).toBe(true);
    expect(m.affected_source_text).toBe('AK-SM 8xxA Series: 0 till <4.2');
    expect(d.advisory_ids).toContain('adv-danfoss-dsa-2025-03-01');
    expect(ds.claims.some((c) => c.id === 'claim-pf-siemens-desigo-cc-pxc-nvd-text-conflict')).toBe(
      true,
    );
    const abb = pfs.get('pf-abb-ac500-v3')!;
    expect(abb.match_ids.filter((id) => !id.startsWith('match-reg-'))).toHaveLength(3);
    expect(abb.data_quality_flags).toContain('register_conflict');
    expect(
      ds.claims.some(
        (c) =>
          c.entity_id === abb.id && c.status === 'disputed' && c.id.includes('register-conflict'),
      ),
    ).toBe(true);
  });

  it('nya poster får register-ID, kategori som fri text, källor och versionsgräns som källtext', () => {
    const aspect = pfs.get('pf-abb-aspect')!;
    expect(aspect.register?.register_id).toBe('OT-N-ICSA-25-007-01');
    expect(aspect.register?.origin).toBe('new');
    expect(aspect.category).toBe('BMS');
    expect(aspect.match_ids.length).toBeGreaterThanOrEqual(26);
    const anyMatch = ds.matches.find((m) => m.id.startsWith('match-reg-ot-n-icsa-25-007-01-'))!;
    expect(anyMatch.version_rule.type).toBe('source_text');
    expect(anyMatch.affected_source_text).toBeTruthy();
    expect(anyMatch.source_ids.length).toBeGreaterThan(0);
    const medical = ds.product_families.find((p) => p.category === 'Medicinsk bild')!;
    expect(medical.control_ids).toContain('ctl-medical-device-coordination');
    expect(medical.register?.control_codes).toContain('K7');
  });

  it('okända värden förblir okända: lösenordstyp, kontonamn, exponering', () => {
    const unknownPwd = ds.product_families.filter(
      (p) => p.credentials?.initial_password_type === 'unknown_unverified',
    );
    expect(unknownPwd.length).toBe(90); // enligt Granskningsrapport
    const named = all.filter((e) => e.credentials?.account_name);
    expect(named.length).toBe(16); // Granskningsrapport: 16 namngivna; 'Skapas vid driftsättning' är inget kontonamn
    expect(named.every((e) => !/ej verifierat/i.test(e.credentials!.account_name!))).toBe(true);
    for (const e of all) {
      expect(e.risk.exposure.level).toBe('unknown');
      expect(e.register?.observed_exposure_text).toBe('Ej undersökt');
      expect(e.credentials?.note).toContain('inga lösenordsvärden');
    }
    const svc = ds.protocol_services[0]!;
    expect(svc.credentials?.initial_password_type).toBe('not_applicable_implementation');
  });

  it('hotunderlag: fyra separata signaler, SSVC none ≠ frånvarobevis', () => {
    const ti = ds.vulnerabilities.filter((v) => v.threat_intel);
    expect(ti).toHaveLength(344);
    const dist = new Map<string, number>();
    for (const v of ti)
      dist.set(
        v.threat_intel!.public_poc_status,
        (dist.get(v.threat_intel!.public_poc_status) ?? 0) + 1,
      );
    expect(dist.get('poc_reported')).toBe(19);
    expect(dist.get('active_reported')).toBe(2);
    expect(dist.get('unknown_missing')).toBe(22);
    expect(dist.get('none_reported_at_assessment')).toBe(301);
    const d = vulns.get('cve-2025-41450')!;
    expect(d.threat_intel?.public_poc_status).toBe('poc_reported');
    expect(d.threat_intel?.material_type_code).toBe('emulator_or_reconstructed_poc');
    expect(d.threat_intel?.poc_url).toBe('https://github.com/msuiche/fromagegate');
    expect(d.threat_intel?.active_exploitation_status).toBe('not_established');
    const none = ti.find((v) => v.threat_intel!.cisa_ssvc_exploitation_raw === 'none')!;
    expect(none.threat_intel!.cisa_assessment_date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(none.threat_intel!.public_poc_status).toBe('none_reported_at_assessment');
    const kev = ds.vulnerabilities
      .filter((v) => v.kev.listed)
      .map((v) => v.cve_id)
      .sort();
    expect(kev).toEqual(['CVE-2023-6448', 'CVE-2025-0994']);
  });

  it('källor: manifest med dokumenthashar, länkkontroll som metadata, inga http-länkar som Source', () => {
    const withSha = ds.sources.filter((s) => s.document_sha256);
    expect(withSha.length).toBeGreaterThanOrEqual(500);
    expect(ds.link_checks).toHaveLength(210);
    expect(ds.sources.every((s) => s.url.startsWith('https://'))).toBe(true);
    const blocked = ds.sources.filter((s) => s.availability === 'blocked');
    expect(blocked.length).toBeGreaterThan(30);
    const advs = ds.advisories.filter(
      (a) => a.id.startsWith('adv-cisa-icsa-25') || a.id.startsWith('adv-cisa-icsma-25'),
    );
    expect(advs.length).toBe(59);
    expect(
      advs.every((a) => a.csaf_url?.startsWith('https://raw.githubusercontent.com/cisagov/CSAF/')),
    ).toBe(true);
  });

  it('mappningar av kodade värden', () => {
    expect(initialPasswordTypeCode('Gemensamt standardlösenord dokumenterat')).toBe(
      'shared_default_documented',
    );
    expect(initialPasswordTypeCode('Okänt – initiallösenordets typ ej verifierad')).toBe(
      'unknown_unverified',
    );
    expect(initialPasswordTypeCode('Hårdkodade uppgifter i berörd version')).toBe(
      'hardcoded_in_affected_version',
    );
    expect(initialPasswordTypeCode(null)).toBe('unknown_unverified');
    expect(publicPocStatusCode('Ingen PoC uppgiven vid CISA-bedömningen', 'none')).toBe(
      'none_reported_at_assessment',
    );
    expect(publicPocStatusCode('Okänt – CISA SSVC-bedömning saknas', 'missing')).toBe(
      'unknown_missing',
    );
    expect(
      publicPocStatusCode('Ej fastställt separat; aktiv exploatering uppgiven', 'active'),
    ).toBe('active_reported');
    expect(materialTypeCode('Ingen direkt PoC-länk verifierad')).toBe('none_verified');
    expect(setupDocTypeCode('Produktens dokumentportal')).toBe('doc_portal');
    expect(accountNameFromText('Ej verifierat')).toBeNull();
    expect(accountNameFromText('admin')).toBe('admin');
  });
});

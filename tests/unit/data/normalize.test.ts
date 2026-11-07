import { describe, expect, it } from 'vitest';
import { buildDataset } from '../../../scripts/normalize';
import { validateDataset } from '../../../scripts/validate';

const ds = buildDataset();
const byId = <T extends { id: string }>(arr: T[]) => new Map(arr.map((x) => [x.id, x]));
const pfs = byId(ds.product_families);
const matches = byId(ds.matches);
const vulns = byId(ds.vulnerabilities);

describe('normalize – invarianter', () => {
  it('66 poster, 55 produkter, 11 tjänster, 18 kategorier, alla rader unika', () => {
    expect(ds.product_families.length + ds.protocol_services.length).toBe(66);
    expect(ds.product_families).toHaveLength(55);
    expect(ds.protocol_services).toHaveLength(11);
    const cats = new Set([...ds.product_families, ...ds.protocol_services].map((x) => x.category));
    expect(cats.size).toBe(18);
    const rows = [...ds.product_families, ...ds.protocol_services]
      .map((x) => x.original.row)
      .sort((a, b) => a - b);
    expect(rows).toEqual(Array.from({ length: 66 }, (_, i) => i + 2));
  });

  it('validerar utan fel', () => {
    const res = validateDataset(ds);
    expect(res.errors).toEqual([]);
    expect(res.ok).toBe(true);
  });

  it('protokoll har aldrig CVE-matchningar', () => {
    for (const svc of ds.protocol_services) expect(svc.match_ids).toEqual([]);
    for (const m of ds.matches) expect(m.product_family_id.startsWith('pf-')).toBe(true);
  });

  it('Danfoss AK-SM 800A: CVE-2025-41450 ↔ DSA-2025-03-01, 41451/41452 ↔ DSA-2025-08-01 (needs_review)', () => {
    const pf = pfs.get('pf-danfoss-ak-sm-800a')!;
    expect(pf.advisory_ids).toEqual(
      expect.arrayContaining(['adv-danfoss-dsa-2025-03-01', 'adv-danfoss-dsa-2025-08-01']),
    );
    expect(matches.get('match-danfoss-ak-sm-800a-cve-2025-41450')?.advisory_id).toBe(
      'adv-danfoss-dsa-2025-03-01',
    );
    expect(matches.get('match-danfoss-ak-sm-800a-cve-2025-41451')?.advisory_id).toBe(
      'adv-danfoss-dsa-2025-08-01',
    );
    expect(matches.get('match-danfoss-ak-sm-800a-cve-2025-41452')?.advisory_id).toBe(
      'adv-danfoss-dsa-2025-08-01',
    );
    expect(
      ds.advisories.find((a) => a.id === 'adv-danfoss-dsa-2025-08-01')?.verification_status,
    ).toBe('needs_review');
    expect(matches.get('match-danfoss-ak-sm-800a-cve-2025-41450')?.version_rule.text).toBe('< 4.2');
    expect(matches.get('match-danfoss-ak-sm-800a-cve-2025-41451')?.version_rule.text).toBe(
      '< 4.3.1',
    );
  });

  it('Danfoss 58 %-observation är icke-representativ med okänd metod', () => {
    const obs = ds.observations.find((o) => o.id === 'obs-danfoss-storeview-se-2026')!;
    expect(obs.representative).toBe(false);
    expect(obs.method.status).toBe('unknown');
    expect(obs.sample_size).toBe(50);
    expect(pfs.get('pf-danfoss-ak-sm-800a')?.observation_ids).toContain(obs.id);
  });

  it('Siemens Desigo CC: CVE-2026-34223 generaliseras inte – ej berörda varianter och PXC-claim finns', () => {
    const pf = pfs.get('pf-siemens-desigo-cc-pxc')!;
    const my = pf.match_ids.map((id) => matches.get(id)!);
    expect(
      my
        .filter((m) => m.status === 'affected')
        .map((m) => m.component)
        .sort(),
    ).toEqual(
      [
        'Desigo CC ClickOnce Client V6',
        'Desigo CC ClickOnce Client V7',
        'Desigo CC Installed Client V6',
        'Desigo CC Installed Client V7',
      ].sort(),
    );
    expect(my.filter((m) => m.status === 'not_affected')).toHaveLength(4);
    expect(my.filter((m) => m.status === 'affected').every((m) => m.fix.available === 'no')).toBe(
      true,
    );
    expect(my.some((m) => /PXC/i.test(m.component ?? ''))).toBe(false);
    const claim = ds.claims.find((c) => c.id === 'claim-pf-siemens-desigo-cc-pxc-not-pxc');
    expect(claim?.status).toBe('verified_primary');
    expect(pf.data_quality_flags).toContain('conflicting_sources');
  });

  it('Copeland XWEB Pro: fixversion 1.13 är inte verifierad', () => {
    const m = matches.get('match-copeland-xweb-pro-cve-2026-21718')!;
    expect(m.status).toBe('affected');
    expect(m.version_rule.text).toBe('≤ 1.12.1');
    expect(m.fix.status).toBe('needs_review');
    expect(m.fix.version).toBeNull();
    expect(pfs.get('pf-copeland-xweb-pro')?.data_quality_flags).toContain('unverified_fix_version');
  });

  it('Copeland E3: intervallet expanderas bara med verifierade ID:n', () => {
    const pf = pfs.get('pf-copeland-e3')!;
    expect(pf.unexpanded_cve_ranges).toHaveLength(1);
    const rg = pf.unexpanded_cve_ranges[0]!;
    expect(rg.expanded).toBe(true);
    expect(rg.verified_ids).toHaveLength(8);
    for (const id of rg.verified_ids) expect(vulns.has(id)).toBe(true);
    expect(pf.match_ids).toHaveLength(9);
  });

  it('S7-1200/S7-1500: SSA-568427 mappas till CVE-2022-38465 med olika versionsgränser', () => {
    expect(matches.get('match-siemens-s7-1200-cve-2022-38465')?.version_rule.text).toBe('< V4.5.0');
    expect(matches.get('match-siemens-s7-1500-cve-2022-38465')?.version_rule.text).toBe('< V2.9.2');
    expect(pfs.get('pf-siemens-s7-1500')?.advisory_ids).toContain('adv-siemens-ssa-568427');
  });

  it('ABB AC500 V3: CODESYS-CVE:er är under utredning, inte bekräftat berörda', () => {
    const pf = pfs.get('pf-abb-ac500-v3')!;
    const my = pf.match_ids.map((id) => matches.get(id)!);
    expect(my).toHaveLength(3);
    expect(
      my.every(
        (m) => m.status === 'under_investigation' && m.verification_status === 'needs_review',
      ),
    ).toBe(true);
    expect(pf.risk.recommended_action).toBe('verify_model_and_version');
  });

  it('KEV: endast CVE-2023-6448 är listad och ger threat=high och mitigate_if_exposed', () => {
    const kev = ds.vulnerabilities.filter((v) => v.kev.listed).map((v) => v.cve_id);
    expect(kev).toEqual(['CVE-2023-6448']);
    const pf = pfs.get('pf-unitronics-vision')!;
    expect(pf.risk.threat.level).toBe('high');
    expect(pf.risk.recommended_action).toBe('mitigate_if_exposed');
  });

  it('exponering är alltid unknown och ingen post har universell P1', () => {
    for (const e of [...ds.product_families, ...ds.protocol_services]) {
      expect(e.risk.exposure.level).toBe('unknown');
      expect(e.risk.method_version).toBe('risk-method-1.0');
      expect(e.data_quality_flags).toContain('conditional_priority_only');
    }
    const actions = new Set(
      [...ds.product_families, ...ds.protocol_services].map((e) => e.risk.recommended_action),
    );
    expect(actions.size).toBeGreaterThan(2);
  });

  it('poster utan CVE flaggas, inte gissas', () => {
    const noCve = ds.product_families.filter((p) => p.match_ids.length === 0);
    expect(noCve.length).toBeGreaterThan(40);
    for (const p of noCve) {
      expect(p.data_quality_flags).toContain('missing_cve_reference');
      expect(p.risk.threat.level).toBe('unknown');
      expect(p.risk.severity.level).toBe('unknown');
    }
  });

  it('alla originalfält bevaras per post och provenance pekar på rätt blad', () => {
    for (const e of [...ds.product_families, ...ds.protocol_services]) {
      expect(Object.keys(e.original.values)).toHaveLength(15);
      expect(e.original.values['System / produktfamilj']).toBe(e.name);
      expect(
        e.provenance.every((p) => p.sheet === '66 system och tjänster' && p.row === e.original.row),
      ).toBe(true);
    }
  });
});

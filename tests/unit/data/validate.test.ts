import { describe, expect, it } from 'vitest';
import { buildDataset } from '../../../scripts/normalize';
import { findForbiddenKeys, findNonHttpsUrls, validateDataset } from '../../../scripts/validate';
import type { Dataset } from '../../../schemas/index';

const clone = (): Dataset => JSON.parse(JSON.stringify(buildDataset())) as Dataset;

describe('validate – negativa fall (skyddsgräns och integritet)', () => {
  it('upptäcker injicerat privat asset-fält', () => {
    const ds = clone();
    (ds.product_families[0] as unknown as Record<string, unknown>)['ip_address'] = '10.0.0.1';
    const res = validateDataset(ds);
    expect(res.ok).toBe(false);
    expect(res.errors.some((e) => e.includes('Förbjuden nyckel') && e.includes('ip_address'))).toBe(
      true,
    );
  });

  it('upptäcker nästlat förbjudet fält och http-URL', () => {
    expect(findForbiddenKeys({ a: [{ b: { serial_number: 'x' } }] })).toEqual([
      '$.a[0].b.serial_number',
    ]);
    expect(
      findNonHttpsUrls({
        u: 'http://example.com',
        ok: 'https://example.com',
        j: 'javascript:alert(1)',
      }),
    ).toHaveLength(2);
  });

  it('upptäcker dubblett-ID och bruten referens', () => {
    const ds = clone();
    ds.controls.push({ ...ds.controls[0]! });
    ds.product_families[0]!.control_ids.push('ctl-finns-inte');
    const res = validateDataset(ds);
    expect(res.errors.some((e) => e.includes('dubblett-ID'))).toBe(true);
    expect(res.errors.some((e) => e.includes('bruten referens ctl-finns-inte'))).toBe(true);
  });

  it('stoppar CVE-matchning mot protokoll', () => {
    const ds = clone();
    const m = { ...ds.matches[0]!, id: 'match-svc-test', product_family_id: 'svc-modbus-tcp' };
    ds.matches.push(m);
    const res = validateDataset(ds);
    expect(res.errors.some((e) => e.includes('matchning mot protokoll är förbjuden'))).toBe(true);
  });

  it('stoppar påstådd exponering i publik katalog', () => {
    const ds = clone();
    (ds.product_families[0]!.risk.exposure as { level: string }).level = 'high';
    const res = validateDataset(ds);
    expect(res.errors.some((e) => e.includes('exposure måste vara unknown'))).toBe(true);
  });

  it('stoppar expanderat intervall utan verifierade ID:n', () => {
    const ds = clone();
    const e3 = ds.product_families.find((p) => p.id === 'pf-copeland-e3')!;
    e3.unexpanded_cve_ranges[0]!.verified_ids = ['cve-2025-99999'];
    const res = validateDataset(ds);
    expect(
      res.errors.some(
        (e) => e.includes('intervall') || e.includes('bruten referens cve-2025-99999'),
      ),
    ).toBe(true);
  });

  it('stoppar fel antal poster', () => {
    const ds = clone();
    ds.protocol_services.pop();
    const res = validateDataset(ds);
    expect(res.errors.some((e) => e.includes('Antal poster 65'))).toBe(true);
  });
});

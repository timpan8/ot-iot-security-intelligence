import { describe, it, expect } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  findMatchConflicts,
  compareNvdSummaries,
  buildDiff,
  renderMarkdown,
  hasChanges,
  normalizeVersion,
} from '../../../scripts/enrich/diff';
import { summarizeNvd, type NvdResponse } from '../../../scripts/enrich/nvd';

const fixture = JSON.parse(
  readFileSync(new URL('../../fixtures/enrich/nvd-CVE-2025-41450.json', import.meta.url), 'utf8'),
) as NvdResponse;

function withBound(resp: NvdResponse, endExcluding: string): NvdResponse {
  const cve = structuredClone(resp.vulnerabilities[0]!.cve);
  cve.configurations = [
    {
      nodes: [
        {
          cpeMatch: [
            {
              criteria: 'cpe:2.3:o:danfoss:ak-sm_800a_firmware:*:*:*:*:*:*:*:*',
              vulnerable: true,
              versionEndExcluding: endExcluding,
            },
          ],
        },
      ],
    },
  ];
  return { ...resp, vulnerabilities: [{ cve }] };
}

describe('diff – konflikter mot kuraterade matchningar', () => {
  it('flaggar verified_primary-match vars versionsgräns inte finns i NVD:s CPE-gränser', () => {
    const summaries = new Map([['CVE-2025-41450', summarizeNvd(withBound(fixture, '4.3'))!]]);
    const conflicts = findMatchConflicts(
      [
        {
          id: 'match-a',
          product_family_id: 'pf-danfoss-ak-sm-800a',
          cve_id: 'CVE-2025-41450',
          status: 'affected',
          verification_status: 'verified_primary',
          version_rule: { type: 'lt', version: '4.2', text: '< 4.2' },
        },
      ],
      summaries,
    );
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0]!.kind).toBe('version_bound_mismatch');
    expect(conflicts[0]!.detail).toContain('4.2');
  });
  it('ingen konflikt när gränsen stämmer, när matchen inte är verified_primary, eller när NVD saknar CPE', () => {
    const ok = new Map([['CVE-2025-41450', summarizeNvd(withBound(fixture, 'V4.2'))!]]);
    const base = {
      id: 'match-a',
      product_family_id: 'pf-x',
      cve_id: 'CVE-2025-41450',
      status: 'affected',
      version_rule: { type: 'lt', version: '4.2', text: '< 4.2' },
    };
    expect(
      findMatchConflicts([{ ...base, verification_status: 'verified_primary' }], ok),
    ).toHaveLength(0);
    const mismatch = new Map([['CVE-2025-41450', summarizeNvd(withBound(fixture, '4.3'))!]]);
    expect(
      findMatchConflicts([{ ...base, verification_status: 'needs_review' }], mismatch),
    ).toHaveLength(0);
    const noCpe = new Map([['CVE-2025-41450', summarizeNvd(fixture)!]]);
    expect(
      findMatchConflicts([{ ...base, verification_status: 'verified_primary' }], noCpe),
    ).toHaveLength(0);
  });
  it('flaggar Rejected CVE som används i en match', () => {
    const rej = structuredClone(fixture);
    rej.vulnerabilities[0]!.cve.vulnStatus = 'Rejected';
    const conflicts = findMatchConflicts(
      [
        {
          id: 'm',
          product_family_id: 'pf',
          cve_id: 'CVE-2025-41450',
          status: 'affected',
          verification_status: 'needs_review',
        },
      ],
      new Map([['CVE-2025-41450', summarizeNvd(rej)!]]),
    );
    expect(conflicts[0]!.kind).toBe('rejected_cve_in_match');
  });
  it('normaliserar versioner', () => {
    expect(normalizeVersion(' V4.2 ')).toBe('4.2');
  });
});

describe('diff – ändringsdetektion', () => {
  it('upptäcker ändrad CPE-gräns, status och ny referens', () => {
    const prev = summarizeNvd(withBound(fixture, '4.2'))!;
    const curResp = withBound(fixture, '4.3');
    curResp.vulnerabilities[0]!.cve.vulnStatus = 'Analyzed';
    curResp.vulnerabilities[0]!.cve.references = [
      ...(curResp.vulnerabilities[0]!.cve.references ?? []),
      { url: 'https://example.com/new' },
    ];
    const changes = compareNvdSummaries(prev, summarizeNvd(curResp)!);
    expect(changes.some((c) => c.startsWith('vulnStatus'))).toBe(true);
    expect(changes.some((c) => c.includes('CPE-versionsgräns ny/ändrad'))).toBe(true);
    expect(changes.some((c) => c.includes('ny referens: https://example.com/new'))).toBe(true);
  });
  it('buildDiff utan git-bas rapporterar allt som nytt och konflikter mot curated', () => {
    const root = mkdtempSync(join(tmpdir(), 'diffroot-'));
    mkdirSync(join(root, 'sources', 'enrichment', 'nvd'), { recursive: true });
    mkdirSync(join(root, 'sources', 'curated'), { recursive: true });
    writeFileSync(
      join(root, 'sources', 'enrichment', 'nvd', 'CVE-2025-41450.json'),
      JSON.stringify(withBound(fixture, '4.3')),
    );
    writeFileSync(
      join(root, 'sources', 'enrichment', 'nvd', 'CVE-2099-0001.missing.json'),
      JSON.stringify({ cve_id: 'CVE-2099-0001' }),
    );
    writeFileSync(
      join(root, 'sources', 'enrichment', 'kev.json'),
      JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-2025-41450', dateAdded: '2026-01-01' }] }),
    );
    writeFileSync(
      join(root, 'sources', 'curated', 'matches.json'),
      JSON.stringify([
        {
          id: 'match-a',
          product_family_id: 'pf',
          cve_id: 'CVE-2025-41450',
          status: 'affected',
          verification_status: 'verified_primary',
          version_rule: { type: 'lt', version: '4.2', text: '< 4.2' },
        },
      ]),
    );
    writeFileSync(
      join(root, 'sources', 'curated', 'vulnerability_overrides.json'),
      JSON.stringify({
        'CVE-2025-41450': { verification_status: 'verified_primary' },
        'CVE-2030-1': {},
      }),
    );
    const r = buildDiff({ root, baseRef: 'HEAD' });
    expect(r.base_available).toBe(false);
    expect(r.new_cves.map((c) => c.cve_id)).toEqual(['CVE-2025-41450']);
    expect(r.missing_cves).toEqual(['CVE-2099-0001']);
    expect(r.new_kev[0]!.cve_id).toBe('CVE-2025-41450');
    expect(r.conflicts.map((c) => c.kind).sort()).toEqual([
      'override_without_cache',
      'version_bound_mismatch',
    ]);
    expect(hasChanges(r)).toBe(true);
    const md = renderMarkdown(r);
    expect(md).toContain('needs_review');
    expect(md).toContain('disputed-kandidater) (2)');
  });
});

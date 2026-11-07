/**
 * Steg B4 – Validering av public/data (körs före build; exit≠0 vid fel).
 *  - Zod strict på alla filer
 *  - unika ID:n, referensintegritet
 *  - protokoll utan CVE-matchningar
 *  - förväntade antal: 66 / 55 / 11 / 18
 *  - inga förbjudna (interna) nycklar, endast https-URL:er
 *  - exponering alltid 'unknown'
 *  - oexpanderade intervall: expanded=true kräver verifierade ID:n
 */
import { existsSync } from 'node:fs';
import { z } from 'zod';
import {
  Advisory,
  Claim,
  Control,
  DATA_FILES,
  FORBIDDEN_PUBLIC_KEYS,
  Manifest,
  Observation,
  ProductFamily,
  ProductVulnerabilityMatch,
  ProtocolService,
  Source,
  Vendor,
  Vulnerability,
  type Dataset,
} from '../schemas/index';
import { p, readJson } from './lib/fs';

export interface ValidationResult {
  ok: boolean;
  errors: string[];
  warnings: string[];
  counts: Record<string, number>;
}

export const EXPECTED = { total: 66, products: 55, services: 11, categories: 18 } as const;

export function findForbiddenKeys(value: unknown, path = '$'): string[] {
  const found: string[] = [];
  const forbidden = new Set<string>(FORBIDDEN_PUBLIC_KEYS);
  const walk = (v: unknown, pth: string) => {
    if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${pth}[${i}]`));
    else if (v && typeof v === 'object') {
      for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
        if (forbidden.has(k.toLowerCase())) found.push(`${pth}.${k}`);
        walk(val, `${pth}.${k}`);
      }
    }
  };
  walk(value, path);
  return found;
}

export function findNonHttpsUrls(value: unknown, path = '$'): string[] {
  const found: string[] = [];
  const walk = (v: unknown, pth: string) => {
    if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${pth}[${i}]`));
    else if (v && typeof v === 'object')
      for (const [k, val] of Object.entries(v as Record<string, unknown>)) walk(val, `${pth}.${k}`);
    else if (
      typeof v === 'string' &&
      /^(https?|ftp|javascript|data):/i.test(v) &&
      !v.startsWith('https://')
    )
      found.push(`${pth} = ${v.slice(0, 80)}`);
  };
  walk(value, path);
  return found;
}

function parseFile<T>(schema: z.ZodType<T>, file: string, errors: string[]): T | null {
  const path = p('public', 'data', file);
  if (!existsSync(path)) {
    errors.push(`Saknad fil: public/data/${file}`);
    return null;
  }
  const raw = readJson<unknown>(path);
  const res = schema.safeParse(raw);
  if (!res.success) {
    for (const issue of res.error.issues.slice(0, 25))
      errors.push(`${file}: ${issue.path.join('.')} – ${issue.message}`);
    if (res.error.issues.length > 25)
      errors.push(`${file}: … ${res.error.issues.length - 25} fler fel`);
    return null;
  }
  return res.data;
}

export function validateDataset(ds: Dataset): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  const ids = <T extends { id: string }>(arr: T[], name: string) => {
    const seen = new Set<string>();
    for (const x of arr) {
      if (seen.has(x.id)) errors.push(`${name}: dubblett-ID ${x.id}`);
      seen.add(x.id);
    }
    return seen;
  };
  const vendorIds = ids(ds.vendors, 'vendors');
  const pfIds = ids(ds.product_families, 'product_families');
  const svcIds = ids(ds.protocol_services, 'protocol_services');
  const vulnIds = ids(ds.vulnerabilities, 'vulnerabilities');
  const advIds = ids(ds.advisories, 'advisories');
  const matchIds = ids(ds.matches, 'matches');
  const ctlIds = ids(ds.controls, 'controls');
  const srcIds = ids(ds.sources, 'sources');
  const obsIds = ids(ds.observations, 'observations');
  const claimIds = ids(ds.claims, 'claims');
  const entityIds = new Set([...pfIds, ...svcIds]);
  for (const id of pfIds)
    if (svcIds.has(id)) errors.push(`ID-kollision mellan produkt och protokoll: ${id}`);

  const ref = (list: string[], target: Set<string>, ctx: string) => {
    for (const id of list) if (!target.has(id)) errors.push(`${ctx}: bruten referens ${id}`);
  };

  for (const pf of ds.product_families) {
    ref([pf.vendor_id], vendorIds, `${pf.id}.vendor_id`);
    ref(pf.control_ids, ctlIds, `${pf.id}.control_ids`);
    ref(pf.advisory_ids, advIds, `${pf.id}.advisory_ids`);
    ref(pf.match_ids, matchIds, `${pf.id}.match_ids`);
    ref(pf.observation_ids, obsIds, `${pf.id}.observation_ids`);
    ref(pf.claim_ids, claimIds, `${pf.id}.claim_ids`);
    ref(pf.source_ids, srcIds, `${pf.id}.source_ids`);
    ref(pf.protocol_service_ids, svcIds, `${pf.id}.protocol_service_ids`);
    ref(
      pf.documentation.map((d) => d.source_id),
      srcIds,
      `${pf.id}.documentation`,
    );
    if (pf.risk.exposure.level !== 'unknown')
      errors.push(`${pf.id}: exposure måste vara unknown i publik katalog`);
    for (const rg of pf.unexpanded_cve_ranges) {
      if (
        rg.expanded &&
        (rg.verified_ids.length === 0 || !rg.verified_ids.every((id) => vulnIds.has(id)))
      )
        errors.push(`${pf.id}: intervall ${rg.text} markerat expanded utan verifierade ID:n`);
      ref(rg.verified_ids, vulnIds, `${pf.id}.unexpanded_cve_ranges`);
    }
    if (pf.category === 'Tjänst') errors.push(`${pf.id}: produktfamilj med kategori Tjänst`);
  }
  for (const svc of ds.protocol_services) {
    if (svc.match_ids.length > 0) errors.push(`${svc.id}: protokoll får inte ha CVE-matchningar`);
    if (svc.category !== 'Tjänst') errors.push(`${svc.id}: protokoll måste ha kategori Tjänst`);
    ref(svc.control_ids, ctlIds, `${svc.id}.control_ids`);
    ref(svc.source_ids, srcIds, `${svc.id}.source_ids`);
    ref(svc.claim_ids, claimIds, `${svc.id}.claim_ids`);
    if (svc.risk.exposure.level !== 'unknown')
      errors.push(`${svc.id}: exposure måste vara unknown`);
  }
  for (const m of ds.matches) {
    ref([m.product_family_id], pfIds, `${m.id}.product_family_id`);
    if (svcIds.has(m.product_family_id))
      errors.push(`${m.id}: matchning mot protokoll är förbjuden`);
    if (m.vulnerability_id) ref([m.vulnerability_id], vulnIds, `${m.id}.vulnerability_id`);
    if (m.advisory_id) ref([m.advisory_id], advIds, `${m.id}.advisory_id`);
    ref(m.mitigation_control_ids, ctlIds, `${m.id}.mitigation_control_ids`);
    ref(m.source_ids, srcIds, `${m.id}.source_ids`);
    ref(m.fix.source_ids, srcIds, `${m.id}.fix.source_ids`);
    if (!m.vulnerability_id && !m.advisory_id) errors.push(`${m.id}: match utan CVE och bulletin`);
    if (
      m.status === 'affected' &&
      m.verification_status === 'verified_primary' &&
      m.source_ids.length === 0
    )
      errors.push(`${m.id}: verified_primary utan källor`);
    const pf = ds.product_families.find((x) => x.id === m.product_family_id);
    if (pf && !pf.match_ids.includes(m.id)) errors.push(`${m.id}: saknas i ${pf.id}.match_ids`);
  }
  for (const v of ds.vulnerabilities) {
    ref(v.advisory_ids, advIds, `${v.id}.advisory_ids`);
    ref(v.source_ids, srcIds, `${v.id}.source_ids`);
    for (const e of v.exploitation_evidence)
      ref(e.source_ids, srcIds, `${v.id}.exploitation_evidence`);
    if (v.id !== `cve-${v.cve_id.toLowerCase().replace(/^cve-/, '')}`)
      errors.push(`${v.id}: id matchar inte cve_id ${v.cve_id}`);
    if (v.kev.listed && !v.kev.date_added) errors.push(`${v.id}: KEV listad utan datum`);
    if (
      v.verification_status === 'verified_primary' &&
      !v.source_ids.some((s) => ds.sources.find((x) => x.id === s)?.is_primary)
    )
      errors.push(`${v.id}: verified_primary utan primärkälla`);
  }
  for (const a of ds.advisories) {
    if (a.vendor_id) ref([a.vendor_id], vendorIds, `${a.id}.vendor_id`);
    ref(a.source_ids, srcIds, `${a.id}.source_ids`);
    for (const cve of a.cve_ids) {
      const vid = `cve-${cve.toLowerCase().replace(/^cve-/, '')}`;
      if (!vulnIds.has(vid))
        warnings.push(
          `${a.id}: CVE ${cve} listas i bulletinen men saknar vulnerability-post (ej importerad)`,
        );
    }
  }
  for (const c of ds.controls) {
    ref(c.depends_on_control_ids, ctlIds, `${c.id}.depends_on_control_ids`);
    ref(c.protocol_scope, svcIds, `${c.id}.protocol_scope`);
    ref(c.source_ids, srcIds, `${c.id}.source_ids`);
  }
  for (const o of ds.observations) {
    ref(o.subject_ids, entityIds, `${o.id}.subject_ids`);
    ref(o.source_ids, srcIds, `${o.id}.source_ids`);
    if (o.representative !== false) errors.push(`${o.id}: representative måste vara false`);
  }
  for (const c of ds.claims) {
    if (
      !entityIds.has(c.entity_id) &&
      !vulnIds.has(c.entity_id) &&
      !advIds.has(c.entity_id) &&
      !matchIds.has(c.entity_id)
    )
      errors.push(`${c.id}: entity_id ${c.entity_id} finns inte`);
    ref(c.source_ids, srcIds, `${c.id}.source_ids`);
  }
  for (const v of ds.vendors) ref(v.source_ids, srcIds, `${v.id}.source_ids`);
  for (const s of ds.sources) {
    for (const sc of s.supports_claims) {
      if (
        sc.entity_id !== '*' &&
        !entityIds.has(sc.entity_id) &&
        !vulnIds.has(sc.entity_id) &&
        !advIds.has(sc.entity_id) &&
        !matchIds.has(sc.entity_id) &&
        !ctlIds.has(sc.entity_id)
      )
        warnings.push(`${s.id}: supports_claims pekar på okänd entitet ${sc.entity_id}`);
    }
  }

  // Antal
  const total = ds.product_families.length + ds.protocol_services.length;
  const cats = new Set([...ds.product_families, ...ds.protocol_services].map((x) => x.category));
  if (total !== EXPECTED.total) errors.push(`Antal poster ${total} ≠ ${EXPECTED.total}`);
  if (ds.product_families.length !== EXPECTED.products)
    errors.push(`Antal produktfamiljer ${ds.product_families.length} ≠ ${EXPECTED.products}`);
  if (ds.protocol_services.length !== EXPECTED.services)
    errors.push(`Antal tjänster ${ds.protocol_services.length} ≠ ${EXPECTED.services}`);
  if (cats.size !== EXPECTED.categories)
    errors.push(`Antal kategorier ${cats.size} ≠ ${EXPECTED.categories}`);
  if (ds.manifest.counts.total_entries !== total)
    errors.push('manifest.counts.total_entries stämmer inte');
  if (ds.manifest.counts.vulnerabilities !== ds.vulnerabilities.length)
    errors.push('manifest.counts.vulnerabilities stämmer inte');
  const rows = new Set(
    [...ds.product_families, ...ds.protocol_services].map((x) => x.original.row),
  );
  if (rows.size !== total) errors.push('Provenance: flera poster delar samma Excel-rad');

  // Skyddsgräns
  const forbidden = findForbiddenKeys(ds);
  for (const f of forbidden) errors.push(`Förbjuden nyckel i publik data: ${f}`);
  const nonHttps = findNonHttpsUrls(ds);
  for (const u of nonHttps) errors.push(`Icke-https-URL i publik data: ${u}`);

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    counts: {
      total,
      product_families: ds.product_families.length,
      protocol_services: ds.protocol_services.length,
      categories: cats.size,
      vulnerabilities: ds.vulnerabilities.length,
      matches: ds.matches.length,
      sources: ds.sources.length,
      forbidden_keys: forbidden.length,
    },
  };
}

export function loadPublicDataset(errors: string[]): Dataset | null {
  const manifest = parseFile(Manifest, DATA_FILES.manifest, errors);
  const vendors = parseFile(z.array(Vendor), DATA_FILES.vendors, errors);
  const product_families = parseFile(z.array(ProductFamily), DATA_FILES.product_families, errors);
  const protocol_services = parseFile(
    z.array(ProtocolService),
    DATA_FILES.protocol_services,
    errors,
  );
  const vulnerabilities = parseFile(z.array(Vulnerability), DATA_FILES.vulnerabilities, errors);
  const advisories = parseFile(z.array(Advisory), DATA_FILES.advisories, errors);
  const matches = parseFile(z.array(ProductVulnerabilityMatch), DATA_FILES.matches, errors);
  const controls = parseFile(z.array(Control), DATA_FILES.controls, errors);
  const sources = parseFile(z.array(Source), DATA_FILES.sources, errors);
  const observations = parseFile(z.array(Observation), DATA_FILES.observations, errors);
  const claims = parseFile(z.array(Claim), DATA_FILES.claims, errors);
  if (
    !manifest ||
    !vendors ||
    !product_families ||
    !protocol_services ||
    !vulnerabilities ||
    !advisories ||
    !matches ||
    !controls ||
    !sources ||
    !observations ||
    !claims
  )
    return null;
  return {
    manifest,
    vendors,
    product_families,
    protocol_services,
    vulnerabilities,
    advisories,
    matches,
    controls,
    sources,
    observations,
    claims,
  };
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  const errors: string[] = [];
  const ds = loadPublicDataset(errors);
  if (!ds) {
    console.error('Validering misslyckades (schema):');
    for (const e of errors) console.error('  -', e);
    process.exit(1);
  }
  const res = validateDataset(ds);
  for (const w of res.warnings) console.warn('  varning:', w);
  if (!res.ok) {
    console.error('Validering misslyckades:');
    for (const e of res.errors) console.error('  -', e);
    process.exit(1);
  }
  console.log('Validering OK:', JSON.stringify(res.counts));
}

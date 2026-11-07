import { z } from 'zod';
import { SCHEMA_VERSION, IsoDateTime } from './common';
import {
  Advisory,
  Claim,
  Control,
  LinkCheck,
  Observation,
  ProductFamily,
  ProductVulnerabilityMatch,
  ProtocolService,
  Source,
  Vendor,
  Vulnerability,
} from './entities';

export const Manifest = z.strictObject({
  dataset_tier: z.literal('public'),
  schema_version: z.literal(SCHEMA_VERSION),
  generated_at: IsoDateTime,
  workbook: z.strictObject({
    filename: z.string().min(1),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
    sheets: z.array(z.string()),
    data_sheet: z.string(),
    header_row: z.number().int(),
    data_rows: z.number().int(),
  }),
  counts: z.strictObject({
    total_entries: z.number().int(),
    product_families: z.number().int(),
    protocol_services: z.number().int(),
    categories: z.number().int(),
    vendors: z.number().int(),
    vulnerabilities: z.number().int(),
    advisories: z.number().int(),
    matches: z.number().int(),
    controls: z.number().int(),
    sources: z.number().int(),
    observations: z.number().int(),
    claims: z.number().int(),
    entries_with_cve_reference: z.number().int(),
    entries_with_security_source_url: z.number().int(),
    kev_listed_vulnerabilities: z.number().int(),
    register_entries: z.number().int().default(0),
    register_original: z.number().int().default(0),
    register_new: z.number().int().default(0),
    register_cve_unique: z.number().int().default(0),
    register_relations: z.number().int().default(0),
    link_checks: z.number().int().default(0),
    threat_intel: z.number().int().default(0),
  }),
  imports: z
    .array(
      z.strictObject({
        file: z.string(),
        sha256: z.string().regex(/^[a-f0-9]{64}$/),
        imported_at: IsoDateTime,
        import_version: z.string(),
        sheets: z.array(z.string()),
        counts: z.record(
          z.string(),
          z.union([z.number(), z.string(), z.array(z.string()), z.record(z.string(), z.number())]),
        ),
      }),
    )
    .default([]),
  files: z.record(z.string(), z.string()),
  notes: z.array(z.string()).default([]),
});
export type Manifest = z.infer<typeof Manifest>;

export const Dataset = z.strictObject({
  manifest: Manifest,
  vendors: z.array(Vendor),
  product_families: z.array(ProductFamily),
  protocol_services: z.array(ProtocolService),
  vulnerabilities: z.array(Vulnerability),
  advisories: z.array(Advisory),
  matches: z.array(ProductVulnerabilityMatch),
  controls: z.array(Control),
  sources: z.array(Source),
  observations: z.array(Observation),
  claims: z.array(Claim),
  link_checks: z.array(LinkCheck).default([]),
});
export type Dataset = z.infer<typeof Dataset>;

export const DATA_FILES = {
  manifest: 'manifest.json',
  vendors: 'vendors.json',
  product_families: 'product_families.json',
  protocol_services: 'protocol_services.json',
  vulnerabilities: 'vulnerabilities.json',
  advisories: 'advisories.json',
  matches: 'product_vulnerability_matches.json',
  controls: 'controls.json',
  sources: 'sources.json',
  observations: 'observations.json',
  claims: 'claims.json',
  link_checks: 'link_checks.json',
} as const;

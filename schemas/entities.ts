import { z } from 'zod';
import {
  AdvisoryId,
  Category,
  ClaimId,
  ControlId,
  DataQualityFlag,
  LinkCheckId,
  RegisterOrigin,
  ThreatIntelId,
  HistoryEntry,
  HttpsUrl,
  IsoDate,
  IsoDateTime,
  MatchId,
  ObservationId,
  ProductFamilyId,
  ProtocolServiceId,
  Provenance,
  Review,
  SourceId,
  VendorId,
  VerificationStatus,
  VerifiedText,
  VulnerabilityId,
} from './common';
import { RiskAssessment } from './risk';

/* ------------------------------------------------------------------ */
/* Källor                                                              */
/* ------------------------------------------------------------------ */

export const SourceType = z.enum([
  'primary_vendor', // tillverkarens PSIRT/bulletin/manual
  'primary_government', // CISA, CERT-SE, NCSC, NVD
  'primary_standard', // NIST, IEC, OPC Foundation
  'secondary_research', // säkerhetsföretag/forskare
  'secondary_media',
  'database', // NVD/EPSS/KEV-API-svar
  'internal_workbook', // ursprunglig Excel-inventering
]);

export const SourceAvailability = z.enum(['ok', 'broken', 'blocked', 'redirected', 'unchecked']);

export const SupportedClaim = z.strictObject({
  entity_id: z.string().min(1),
  field: z.string().min(1),
  note: z.string().nullable().default(null),
});

export const Source = z.strictObject({
  id: SourceId,
  url: HttpsUrl,
  title: z.string().min(1),
  publisher: z.string().min(1),
  source_type: SourceType,
  is_primary: z.boolean(),
  published_at: IsoDate.nullable().default(null),
  last_checked_at: IsoDate.nullable().default(null),
  last_verified_at: IsoDate.nullable().default(null),
  availability: SourceAvailability.default('unchecked'),
  http_status: z.number().int().nullable().default(null),
  supports_claims: z.array(SupportedClaim).default([]),
  access_note: z.string().nullable().default(null), // t.ex. "kräver inloggning", "bot-skydd"
  notes: z.string().nullable().default(null),
  // Registerimport: dokumenthash är källmetadata, aldrig produktidentitet
  document_sha256: z
    .string()
    .regex(/^[a-f0-9]{64}$/)
    .nullable()
    .default(null),
  fetched_at: IsoDate.nullable().default(null),
  final_url: z.string().nullable().default(null),
  interpretation_text: z.string().nullable().default(null),
  register_source_key: z.string().nullable().default(null), // Käll-ID i Källmanifest (ICSA-…, SETUP-…, CVE-…)
});
export type Source = z.infer<typeof Source>;

/** Länkkontroll från registret. url är ren sträng (kan vara http://) och renderas aldrig som länk om den inte är https. */
export const LinkCheck = z.strictObject({
  id: LinkCheckId,
  url: z.string().min(1),
  http_status_text: z.string().nullable(),
  final_url: z.string().nullable(),
  response_sha256: z
    .string()
    .regex(/^[a-f0-9]{64}$/)
    .nullable(),
  interpretation_text: z.string().nullable(),
  checked_at: IsoDate.nullable(),
  source_ids: z.array(SourceId).default([]),
  entity_ids: z.array(z.string()).default([]), // poster som refererar URL:en
});
export type LinkCheck = z.infer<typeof LinkCheck>;

/* ------------------------------------------------------------------ */
/* Leverantörer                                                        */
/* ------------------------------------------------------------------ */

export const Vendor = z.strictObject({
  id: VendorId,
  name: z.string().min(1),
  aliases: z.array(z.string()).default([]),
  security_portal_url: HttpsUrl.nullable().default(null),
  psirt_contact_url: HttpsUrl.nullable().default(null),
  support_urls: z.array(HttpsUrl).default([]),
  verification_status: VerificationStatus,
  source_ids: z.array(SourceId).default([]),
  notes: z.string().nullable().default(null),
});
export type Vendor = z.infer<typeof Vendor>;

/* ------------------------------------------------------------------ */
/* Gemensamt för produktfamilj och protokoll                           */
/* ------------------------------------------------------------------ */

export const DocumentationLevel = z.enum([
  'product_manual',
  'hardening_guide',
  'security_guidance',
  'bulletin_portal',
  'vendor_support',
  'industry_guide',
  'standard',
  'other',
]);

export const DocumentationLink = z.strictObject({
  url: HttpsUrl,
  level: DocumentationLevel,
  level_text: z.string().min(1), // ursprunglig text från kolumn M
  product_specific: z.boolean(),
  source_id: SourceId,
});

export const DiscoveryHeuristic = z.strictObject({
  query: z.string().nullable(),
  caveat: z.string().min(1),
  purpose: z.literal('authorized_inventory_only'),
});

export const RiskSummary = z.strictObject({
  type_text: z.string().nullable(), // kolumn E
  explanation_text: z.string().nullable(), // kolumn F
  cve_text: z.string().nullable(), // kolumn G (ursprunglig)
  affected_firmware_text: z.string().nullable(), // kolumn H
  fix_text: z.string().nullable(), // kolumn I
  patch_level_text: z.string().nullable(), // kolumn J
  control_text: z.string().nullable(), // kolumn K
  legacy_priority_text: z.string().nullable(), // kolumn O – villkorlig inventeringssignal
});

/** Oexpanderat CVE-intervall från Excel ("CVE-2025-52543–52550"). */
export const UnexpandedCveRange = z.strictObject({
  text: z.string().min(1),
  start: z.string().regex(/^CVE-\d{4}-\d{4,}$/),
  end: z.string().regex(/^CVE-\d{4}-\d{4,}$/),
  expanded: z.boolean(), // true endast om varje ID verifierats och finns i vulnerabilities
  verified_ids: z.array(VulnerabilityId).default([]),
  note: z.string().nullable().default(null),
});

export const OriginalRow = z.strictObject({
  sheet: z.string().min(1),
  row: z.number().int().positive(),
  values: z.record(z.string(), z.string().nullable()), // header -> cellvärde (verbatim)
});

/* ------------------------------------------------------------------ */
/* Registerimport (125-postregistret)                                  */
/* ------------------------------------------------------------------ */

export const ImportProvenance = z.strictObject({
  file: z.string().min(1),
  file_sha256: z.string().regex(/^[a-f0-9]{64}$/),
  import_version: z.string().min(1),
  sheet: z.string().min(1),
  row: z.number().int().positive(),
});

export const RegisterInfo = z.strictObject({
  register_id: z.string().regex(/^OT-[A-Za-z0-9-]+$/),
  origin: RegisterOrigin,
  origin_reference: z.string().nullable(), // "Original rad N" eller bulletin-ID
  normalization_key: z.string().nullable(),
  scope_alias_text: z.string().nullable(),
  source_status_text: z.string().nullable(),
  uncertainty_text: z.string().nullable(),
  exposure_risk_text: z.string().nullable(),
  cve_selection_text: z.string().nullable(),
  kev_text: z.string().nullable(),
  priority_text: z.string().nullable(), // "P1 – verifiera omgående" / "P2 – snar verifiering" – villkorlig vid KONSTATERAD exponering
  control_codes: z.array(z.string().regex(/^K\d$/)).default([]),
  controls_text: z.string().nullable(),
  credentials_status_text: z.string().nullable(),
  change_required_text: z.string().nullable(),
  verify_login_text: z.string().nullable(),
  documentation_limitation_text: z.string().nullable(),
  versions_guidance_text: z.string().nullable(),
  fix_guidance_text: z.string().nullable(),
  source_date_text: z.string().nullable(),
  checked_at: IsoDate.nullable(),
  observed_exposure_text: z.string().nullable(), // "Ej undersökt" – aldrig tolkat som exponerad eller säker
  threat_selection_text: z.string().nullable(),
  threat_links_text: z.string().nullable(),
  threat_tracking_text: z.string().nullable(),
  limitation_text: z.string().nullable(),
  threat_checked_at: IsoDate.nullable(),
  import: ImportProvenance,
});
export type RegisterInfo = z.infer<typeof RegisterInfo>;

/** Typ av initialt/fabrikslösenord. Enbart typ – aldrig värden. */
export const InitialPasswordType = z.enum([
  'shared_default_documented', // gemensamt standardlösenord dokumenterat
  'default_exists_type_unknown', // standardlösenord förekommer – typ ej fastställd
  'device_unique_documented', // enhetsunikt initiallösenord enligt dokumentation
  'device_unique_normal_delivery', // enhetsunikt vid normal leverans
  'model_version_batch_dependent', // modell-/versions-/batchberoende
  'version_dependent_shared_or_unique', // versionsberoende – gemensamt eller enhetsbundet
  'set_at_commissioning', // väljs/skapas vid driftsättning
  'hardcoded_in_affected_version', // hårdkodade uppgifter i berörd version (CVE)
  'predictable_builtin_mechanism', // förutsägbar inbyggd mekanism i berörd version
  'not_applicable_implementation', // protokoll/tjänst – implementation styr
  'unknown_unverified', // okänt – ej verifierat
]);
export type InitialPasswordType = z.infer<typeof InitialPasswordType>;

export const Credentials = z.strictObject({
  account_name: z.string().nullable(), // null när "Ej verifierat"/"Ej tillämpligt"
  account_name_text: z.string().nullable(), // originaltext
  account_status_text: z.string().nullable(),
  account_scope_text: z.string().nullable(), // modell-/versionsgräns för kontouppgiften
  account_source_id: SourceId.nullable(),
  initial_password_type: InitialPasswordType,
  initial_password_type_text: z.string().nullable(),
  change_requirement_text: z.string().nullable(),
  commissioning_action_text: z.string().nullable(),
  password_status_source_id: SourceId.nullable(),
  verification_status: VerificationStatus,
  checked_at: IsoDate.nullable(),
  note: z.literal(
    'Underlaget innehåller inga lösenordsvärden; endast kontonamn, lösenordstyp och bytekrav.',
  ),
});
export type Credentials = z.infer<typeof Credentials>;

export const SetupDocType = z.enum([
  'direct_manual',
  'doc_portal',
  'online_handbook',
  'vendor_entry_unverified',
  'security_guide_unverified',
  'start_guide',
  'not_product',
  'unverified',
  'other',
]);

export const SetupDocumentation = z.strictObject({
  url: HttpsUrl.nullable(),
  title: z.string().nullable(),
  doc_type: SetupDocType,
  doc_type_text: z.string().nullable(),
  scope_text: z.string().nullable(),
  verification_text: z.string().nullable(),
  fetch_status_text: z.string().nullable(),
  identity_verified: z.boolean().default(false), // dokumentidentitet/omfattning kontrollerad enligt registret
  exact_manual_missing: z.boolean().default(false), // registret: "Exakt setupmanual saknas …"
  is_verified_setup_manual: z.boolean(), // identitet kontrollerad OCH direkt manual/handbok (portal/säkerhetsguide ⇒ false)
  source_id: SourceId.nullable(),
  checked_at: IsoDate.nullable(),
});
export type SetupDocumentation = z.infer<typeof SetupDocumentation>;

export const ReviewFinding = z.strictObject({
  finding: z.string().nullable(),
  uncertainty: z.string().nullable(),
  status_text: z.string().nullable(),
  source_ids: z.array(SourceId).default([]),
  checked_at: IsoDate.nullable(),
});
export type ReviewFinding = z.infer<typeof ReviewFinding>;

const CatalogBase = {
  name: z.string().min(1),
  aliases: z.array(z.string()).default([]),
  category: Category,
  function_text: z.string().min(1), // kolumn C
  description: z.string().nullable().default(null),
  documentation: z.array(DocumentationLink).default([]),
  discovery_heuristic: DiscoveryHeuristic,
  risk_summary: RiskSummary,
  control_ids: z.array(ControlId).default([]),
  advisory_ids: z.array(AdvisoryId).default([]),
  match_ids: z.array(MatchId).default([]),
  observation_ids: z.array(ObservationId).default([]),
  claim_ids: z.array(ClaimId).default([]),
  risk: RiskAssessment,
  data_quality_flags: z.array(DataQualityFlag).default([]),
  provenance: z.array(Provenance).min(1),
  original: OriginalRow,
  verification_status: VerificationStatus,
  source_ids: z.array(SourceId).default([]),
  review: Review,
  register: RegisterInfo.nullable().default(null),
  credentials: Credentials.nullable().default(null),
  setup_documentation: SetupDocumentation.nullable().default(null),
  review_findings: z.array(ReviewFinding).default([]),
};

/* ------------------------------------------------------------------ */
/* Produktfamiljer                                                     */
/* ------------------------------------------------------------------ */

export const LifecycleStatus = z.enum(['active', 'eol_announced', 'eol', 'mixed', 'unknown']);

export const Lifecycle = z.strictObject({
  status: LifecycleStatus,
  eol_date: VerifiedText,
  note: z.string().nullable().default(null),
});

export const ProductFamily = z.strictObject({
  id: ProductFamilyId,
  kind: z.literal('product_family'),
  vendor_id: VendorId,
  ...CatalogBase,
  hardware_revisions: z.array(z.string()).default([]),
  lifecycle: Lifecycle,
  ot_role: z.string().nullable().default(null), // t.ex. "överordnad kylstyrning"
  ot_consequence: z.string().nullable().default(null), // vad en kompromettering kan påverka
  secure_configuration_notes: z.array(z.string()).default([]),
  unexpanded_cve_ranges: z.array(UnexpandedCveRange).default([]),
  protocol_service_ids: z.array(ProtocolServiceId).default([]), // protokoll som produkten typiskt talar
});
export type ProductFamily = z.infer<typeof ProductFamily>;

/* ------------------------------------------------------------------ */
/* Protokoll / tjänster                                                */
/* ------------------------------------------------------------------ */

export const PortSpec = z.strictObject({
  port: z.number().int().min(1).max(65535),
  transport: z.enum(['tcp', 'udp', 'tcp/udp']),
  note: z.string().nullable().default(null),
  status: VerificationStatus,
  source_ids: z.array(SourceId).default([]),
});

export const SecurityProperty = z.enum(['none', 'optional', 'required', 'depends', 'unknown']);

export const ProtocolService = z.strictObject({
  id: ProtocolServiceId,
  kind: z.literal('protocol_service'),
  ...CatalogBase,
  category: z.literal('Tjänst'),
  typical_use: z.string().min(1),
  default_ports: z.array(PortSpec).default([]),
  authentication: SecurityProperty,
  encryption: SecurityProperty,
  security_notes: z.string().nullable().default(null),
  allowed_zones: z.string().nullable().default(null), // beskrivande, inte anläggningsspecifikt
  // Protokoll är inte produkter: får aldrig ha CVE-matchningar.
  match_ids: z.array(MatchId).max(0).default([]),
});
export type ProtocolService = z.infer<typeof ProtocolService>;

/* ------------------------------------------------------------------ */
/* Sårbarheter                                                         */
/* ------------------------------------------------------------------ */

export const CveStatus = z.enum(['published', 'reserved', 'rejected', 'disputed', 'unknown']);
export const NvdStatus = z.enum([
  'Received',
  'Awaiting Analysis',
  'Undergoing Analysis',
  'Analyzed',
  'Modified',
  'Deferred',
  'Rejected',
  'unknown',
]);

export const CvssMetric = z.strictObject({
  version: z.enum(['2.0', '3.0', '3.1', '4.0']),
  vector: z.string().min(1),
  base_score: z.number().min(0).max(10),
  base_severity: z.enum(['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).nullable(),
  source: z.string().min(1), // t.ex. "nvd@nist.gov", "productcert@siemens.com"
  type: z.enum(['Primary', 'Secondary']),
});

export const Epss = z.strictObject({
  score: z.number().min(0).max(1),
  percentile: z.number().min(0).max(1),
  date: IsoDate,
  fetched_at: IsoDateTime,
});

export const Kev = z.strictObject({
  listed: z.boolean(),
  date_added: IsoDate.nullable().default(null),
  due_date: IsoDate.nullable().default(null),
  known_ransomware_use: z.enum(['Known', 'Unknown']).nullable().default(null),
  vulnerability_name: z.string().nullable().default(null),
  catalog_version: z.string().nullable().default(null),
  checked_at: IsoDateTime.nullable().default(null),
});

export const ExploitationEvidence = z.strictObject({
  type: z.enum([
    'kev',
    'vendor_statement',
    'cert_report',
    'public_poc',
    'research_report',
    'none_reported',
  ]),
  description: z.string().min(1),
  date: IsoDate.nullable().default(null),
  source_ids: z.array(SourceId).default([]),
  status: VerificationStatus,
});

export const PublicPocStatus = z.enum([
  'poc_reported', // offentlig PoC enligt CISA SSVC vid bedömningsdatumet
  'none_reported_at_assessment', // ingen PoC uppgiven vid CISA-bedömningen – inte frånvarobevis
  'unknown_missing', // CISA SSVC-bedömning saknas
  'active_reported', // aktiv exploatering uppgiven (KEV); PoC ej fastställd separat
]);
export type PublicPocStatus = z.infer<typeof PublicPocStatus>;

export const MaterialTypeCode = z.enum([
  'none_verified',
  'emulator_or_reconstructed_poc',
  'research_artifacts_and_detection',
  'component_exploit_published',
  'component_poc_research',
  'research_publication_with_code',
  'public_exploit_archive',
  'official_active_exploitation_report',
  'incident_analysis_detection',
  'cert_report_public_poc',
  'other',
]);
export type MaterialTypeCode = z.infer<typeof MaterialTypeCode>;

/** Hotunderlag per CVE. Fyra separata signaler som aldrig slås ihop: offentlig PoC, SSVC-råvärde (daterat), aktiv exploatering, materialtyp. */
export const ThreatIntel = z.strictObject({
  id: ThreatIntelId,
  public_poc_status: PublicPocStatus,
  public_poc_status_text: z.string().nullable(),
  cisa_ssvc_exploitation_raw: z.enum(['none', 'poc', 'active', 'missing']).nullable(),
  cisa_assessment_date: IsoDate.nullable(),
  active_exploitation_status: z.enum(['kev_listed', 'not_established']),
  active_exploitation_text: z.string().nullable(),
  poc_url: HttpsUrl.nullable(),
  material_type_code: MaterialTypeCode,
  material_type_text: z.string().nullable(),
  source_critical_note: z.string().nullable(),
  verification_level_text: z.string().nullable(),
  assessment_source_id: SourceId.nullable(),
  record_source_id: SourceId.nullable(), // Hotkällor (CVE/CNA + CISA ADP) med SHA-256
  subject_product_family_id: ProductFamilyId.nullable(),
  checked_at: IsoDate.nullable(),
});
export type ThreatIntel = z.infer<typeof ThreatIntel>;

export const Reference = z.strictObject({
  url: HttpsUrl,
  tags: z.array(z.string()).default([]),
});

export const Vulnerability = z.strictObject({
  id: VulnerabilityId,
  cve_id: z.string().regex(/^CVE-\d{4}-\d{4,}$/),
  cve_status: CveStatus,
  nvd_status: NvdStatus,
  summary: z.string().min(1),
  summary_sv: z.string().nullable().default(null),
  cwe_ids: z.array(z.string().regex(/^(CWE-\d+|NVD-CWE-noinfo|NVD-CWE-Other)$/)).default([]),
  cvss: z.array(CvssMetric).default([]),
  epss: Epss.nullable().default(null),
  kev: Kev,
  exploitation_evidence: z.array(ExploitationEvidence).default([]),
  cna: z.string().nullable().default(null), // CVE Numbering Authority (sourceIdentifier)
  published_at: IsoDateTime.nullable().default(null),
  last_modified_at: IsoDateTime.nullable().default(null),
  references: z.array(Reference).default([]),
  advisory_ids: z.array(AdvisoryId).default([]),
  source_ids: z.array(SourceId).default([]),
  verification_status: VerificationStatus,
  threat_intel: ThreatIntel.nullable().default(null),
  register_cvss: z
    .strictObject({
      version: z.string(),
      base_score: z.number().nullable(),
      vector: z.string().nullable(),
      cwe_text: z.string().nullable(),
    })
    .nullable()
    .default(null),
  enrichment: z.strictObject({
    nvd_fetched_at: IsoDateTime.nullable().default(null),
    epss_fetched_at: IsoDateTime.nullable().default(null),
    kev_checked_at: IsoDateTime.nullable().default(null),
  }),
  review: Review,
});
export type Vulnerability = z.infer<typeof Vulnerability>;

/* ------------------------------------------------------------------ */
/* Bulletiner                                                          */
/* ------------------------------------------------------------------ */

export const AdvisoryStatus = z.enum(['interim', 'final', 'unknown']);

export const Advisory = z.strictObject({
  id: AdvisoryId,
  advisory_id: z.string().min(1), // t.ex. "SSA-330084", "DSA-2025-03-01", "ICSA-26-057-10"
  issuer: z.string().min(1),
  vendor_id: VendorId.nullable().default(null),
  title: z.string().min(1),
  url: HttpsUrl,
  csaf_url: HttpsUrl.nullable().default(null),
  published_at: IsoDate.nullable().default(null),
  updated_at: IsoDate.nullable().default(null),
  status: AdvisoryStatus,
  source_type: SourceType,
  cve_ids: z.array(z.string().regex(/^CVE-\d{4}-\d{4,}$/)).default([]),
  summary: z.string().nullable().default(null),
  history: z.array(HistoryEntry).default([]),
  source_ids: z.array(SourceId).default([]),
  verification_status: VerificationStatus,
  review: Review,
});
export type Advisory = z.infer<typeof Advisory>;

/* ------------------------------------------------------------------ */
/* Produkt–sårbarhetsmatchning                                         */
/* ------------------------------------------------------------------ */

export const MatchStatus = z.enum(['affected', 'not_affected', 'unknown', 'under_investigation']);

export const VersionRule = z.strictObject({
  type: z.enum(['lt', 'lte', 'eq', 'range', 'all', 'source_text', 'unknown']),
  version: z.string().nullable().default(null),
  version_end: z.string().nullable().default(null),
  text: z.string().min(1), // människoläsbar, t.ex. "< 4.2", "≤ 1.12.1", "alla versioner"
});

export const FixAvailability = z.enum([
  'yes',
  'no',
  'partial',
  'planned',
  'none_planned',
  'unknown',
]);

export const Fix = z.strictObject({
  available: FixAvailability,
  version: z.string().nullable().default(null),
  text: z.string().nullable().default(null),
  status: VerificationStatus,
  source_ids: z.array(SourceId).default([]),
});

export const ProductVulnerabilityMatch = z.strictObject({
  id: MatchId,
  product_family_id: ProductFamilyId,
  vulnerability_id: VulnerabilityId.nullable(),
  advisory_id: AdvisoryId.nullable(),
  component: z.string().nullable().default(null), // t.ex. "Desigo CC ClickOnce Client V6"
  affected_versions_text: z.string().min(1),
  version_rule: VersionRule,
  status: MatchStatus,
  attack_prerequisites: z.string().nullable().default(null),
  attack_vector: z.enum(['network', 'adjacent', 'local', 'physical', 'unknown']).default('unknown'),
  authentication_required: z.enum(['none', 'low', 'high', 'unknown']).default('unknown'),
  user_interaction: z.enum(['none', 'required', 'unknown']).default('unknown'),
  fix: Fix,
  mitigation_control_ids: z.array(ControlId).default([]),
  mitigation_text: z.string().nullable().default(null),
  evidence: z.string().min(1), // vad matchningen bygger på
  source_ids: z.array(SourceId).min(1),
  verification_status: VerificationStatus,
  review: Review,
  // Registerimport
  register_relation: z.boolean().default(false),
  affected_source_text: z.string().nullable().default(null), // exakt known_affected/CNA-text
  fixed_source_text: z.string().nullable().default(null), // exakt fixed-matris/osäkerhet
  product_link_limitation_text: z.string().nullable().default(null),
  cwe_text: z.string().nullable().default(null),
  register_verification_note: z.string().nullable().default(null),
});
export type ProductVulnerabilityMatch = z.infer<typeof ProductVulnerabilityMatch>;

/* ------------------------------------------------------------------ */
/* Kontroller / åtgärder                                               */
/* ------------------------------------------------------------------ */

export const OtSuitability = z.enum(['high', 'medium', 'low', 'depends']);

export const FrameworkRef = z.strictObject({
  framework: z.enum([
    'IEC 62443',
    'NIST CSF 2.0',
    'NIST SP 800-82r3',
    'CISA',
    'Cybersäkerhetslagen',
  ]),
  reference: z.string().min(1),
  note: z.string().nullable().default(null),
  status: z.enum(['mapped_reference', 'informational']), // aldrig "compliant"
});

export const Control = z.strictObject({
  id: ControlId,
  name: z.string().min(1),
  goal: z.string().min(1),
  description: z.string().min(1),
  effect: z.string().min(1),
  limitations: z.string().min(1),
  ot_suitability: OtSuitability,
  requires_operational_approval: z.boolean(),
  order_hint: z.number().int().min(1).max(99), // rekommenderad ordning
  depends_on_control_ids: z.array(ControlId).default([]),
  category_scope: z.array(Category).default([]), // tom = generell
  protocol_scope: z.array(ProtocolServiceId).default([]),
  vendor_guide_url: HttpsUrl.nullable().default(null),
  framework_refs: z.array(FrameworkRef).default([]),
  source_ids: z.array(SourceId).default([]),
  register_code: z.string().regex(/^K\d$/).nullable().default(null),
  verification_method: z.string().nullable().default(null),
});
export type Control = z.infer<typeof Control>;

/* ------------------------------------------------------------------ */
/* Observationer (aggregerade, publika)                                */
/* ------------------------------------------------------------------ */

export const Observation = z.strictObject({
  id: ObservationId,
  title: z.string().min(1),
  subject_ids: z.array(z.string().min(1)).min(1),
  method: VerifiedText,
  period: VerifiedText,
  sample_size: z.number().int().nonnegative().nullable(),
  value_text: z.string().min(1),
  uncertainty: z.string().min(1),
  representative: z.literal(false),
  caveat: z.string().min(1),
  source_ids: z.array(SourceId).default([]),
  verification_status: VerificationStatus,
  observed_at: IsoDate.nullable().default(null),
  notes: z.string().nullable().default(null),
});
export type Observation = z.infer<typeof Observation>;

/* ------------------------------------------------------------------ */
/* Atomära påståenden                                                  */
/* ------------------------------------------------------------------ */

export const Claim = z.strictObject({
  id: ClaimId,
  entity_id: z.string().min(1),
  field: z.string().min(1),
  text: z.string().min(1),
  status: VerificationStatus,
  source_ids: z.array(SourceId).default([]),
  conflict_note: z.string().nullable().default(null),
  reviewed_at: IsoDate.nullable().default(null),
  history: z.array(HistoryEntry).default([]),
});
export type Claim = z.infer<typeof Claim>;

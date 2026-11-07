import { z } from 'zod';

/**
 * Gemensamma byggstenar för den PUBLIKA datamodellen.
 * Alla objekt är strikta (okända nycklar = valideringsfel) för att förhindra
 * oavsiktlig inkludering av interna/anläggningsunika uppgifter.
 */

export const SCHEMA_VERSION = '1.0.0';

export const VerificationStatus = z.enum([
  'verified_primary', // bekräftat mot primärkälla (tillverkare/CERT/NVD-post från CNA)
  'corroborated_secondary', // stöds av trovärdig sekundärkälla, ej primärt bekräftat
  'needs_review', // påstående finns men kräver mänsklig granskning
  'unknown', // uppgift saknas
  'disputed', // motstridiga uppgifter mellan källor
]);
export type VerificationStatus = z.infer<typeof VerificationStatus>;

/**
 * Kategori är fri text (registret har 46 kategorier). Kända kategorier får profil i
 * sources/curated/category_profiles.json; okänd kategori ger ot_impact 'unknown'.
 * Protokoll/tjänster har alltid kategorin PROTOCOL_CATEGORY.
 */
export const PROTOCOL_CATEGORY = 'Tjänst';
export const Category = z.string().min(1).max(60);
export type Category = z.infer<typeof Category>;

/** Registrets ursprungsmarkering: Original = fanns i 66-postsinventeringen, new = tillkom i 125-postregistret. */
export const RegisterOrigin = z.enum(['original', 'new']);
export type RegisterOrigin = z.infer<typeof RegisterOrigin>;

/** Endast https-länkar tillåts i publik data. */
export const HttpsUrl = z
  .url()
  .refine((u) => u.startsWith('https://'), { message: 'Endast https:// tillåts' });

export const IsoDate = z.iso.date(); // YYYY-MM-DD
export const IsoDateTime = z.iso.datetime({ offset: true });

/** Spårbarhet till Excel: blad, rad, kolumnbokstav och rubrik. */
export const Provenance = z.strictObject({
  sheet: z.string().min(1),
  row: z.number().int().positive(),
  column: z.string().regex(/^[A-Z]{1,2}$/),
  header: z.string().min(1),
});
export type Provenance = z.infer<typeof Provenance>;

export const IdPrefix = {
  vendor: 'vendor-',
  product_family: 'pf-',
  protocol_service: 'svc-',
  vulnerability: 'cve-',
  advisory: 'adv-',
  match: 'match-',
  control: 'ctl-',
  source: 'src-',
  observation: 'obs-',
  claim: 'claim-',
  link_check: 'lc-',
  threat_intel: 'ti-',
} as const;

const slug = /^[a-z0-9]+(?:-[a-z0-9.]+)*$/;
export const idWithPrefix = (prefix: string) =>
  z
    .string()
    .regex(slug, 'ID måste vara ett slug: små bokstäver, siffror, bindestreck, punkt')
    .refine((s) => s.startsWith(prefix), { message: `ID måste börja med "${prefix}"` });

export const VendorId = idWithPrefix(IdPrefix.vendor);
export const ProductFamilyId = idWithPrefix(IdPrefix.product_family);
export const ProtocolServiceId = idWithPrefix(IdPrefix.protocol_service);
export const VulnerabilityId = idWithPrefix(IdPrefix.vulnerability);
export const AdvisoryId = idWithPrefix(IdPrefix.advisory);
export const MatchId = idWithPrefix(IdPrefix.match);
export const ControlId = idWithPrefix(IdPrefix.control);
export const SourceId = idWithPrefix(IdPrefix.source);
export const ObservationId = idWithPrefix(IdPrefix.observation);
export const ClaimId = idWithPrefix(IdPrefix.claim);
export const LinkCheckId = idWithPrefix(IdPrefix.link_check);
export const ThreatIntelId = idWithPrefix(IdPrefix.threat_intel);

/** Ett textpåstående med egen verifieringsstatus och källor. */
export const VerifiedText = z.strictObject({
  value: z.string().nullable(),
  status: VerificationStatus,
  source_ids: z.array(SourceId).default([]),
  reviewed_at: IsoDate.nullable().default(null),
  note: z.string().nullable().default(null),
});
export type VerifiedText = z.infer<typeof VerifiedText>;

export const HistoryEntry = z.strictObject({
  date: IsoDate,
  status: VerificationStatus.nullable().default(null),
  summary: z.string().min(1),
});

export const Review = z.strictObject({
  reviewed_at: IsoDate.nullable().default(null),
  reviewer: z.string().nullable().default(null), // roll, aldrig personuppgift
  notes: z.array(z.string()).default([]),
  history: z.array(HistoryEntry).default([]),
});

/** Datakvalitetsflaggor som visas i UI och sammanställs i datakvalitetsvyn. */
export const DataQualityFlag = z.enum([
  'missing_primary_source',
  'missing_cve_reference',
  'unknown_version_boundary',
  'unverified_fix_version',
  'possibly_outdated',
  'needs_human_review',
  'generic_control_text',
  'industry_guide_only',
  'conditional_priority_only',
  'patch_level_unknown',
  'unexpanded_cve_range',
  'conflicting_sources',
  'broken_link',
  'setup_manual_unverified',
  'account_name_unverified',
  'initial_password_type_unknown',
  'register_conflict',
]);
export type DataQualityFlag = z.infer<typeof DataQualityFlag>;

/**
 * Nycklar som ALDRIG får förekomma i publik data (skyddsgräns, avsnitt 1).
 * Kontrolleras rekursivt av validate.ts och av artefakttestet mot dist/.
 */
export const FORBIDDEN_PUBLIC_KEYS = [
  'ip',
  'ip_address',
  'ipv4',
  'ipv6',
  'mac',
  'mac_address',
  'serial',
  'serial_number',
  'hostname',
  'site',
  'site_id',
  'facility',
  'building',
  'owner',
  'asset_owner',
  'contact',
  'contact_email',
  'phone',
  'network_zone',
  'vlan',
  'subnet',
  'scan_result',
  'shodan_result',
  'exposure_confirmed',
  'ticket',
  'incident_id',
  'installed_version',
  'actual_version',
  'maintenance_window',
  'risk_acceptance',
  // Autentiseringsuppgifter får aldrig förekomma som värden i publik data
  'password',
  'password_value',
  'passwd',
  'secret',
  'api_key',
  'credential_value',
] as const;

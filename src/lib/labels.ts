import type {
  DataQualityFlag,
  FactorLevel,
  RecommendedAction,
  VerificationStatus,
} from '@schemas/index';

export const UNKNOWN = 'Okänt';
export const MISSING = 'Uppgift saknas';

export const verificationLabel: Record<VerificationStatus, string> = {
  verified_primary: 'Verifierad (primärkälla)',
  corroborated_secondary: 'Stödd av sekundärkälla',
  needs_review: 'Behöver granskning',
  unknown: 'Okänt',
  disputed: 'Motstridiga uppgifter',
};

export const verificationDescription: Record<VerificationStatus, string> = {
  verified_primary: 'Bekräftad mot primärkälla (tillverkare, CERT eller CNA-post i NVD).',
  corroborated_secondary: 'Stöds av trovärdig sekundärkälla men är inte bekräftad av primärkälla.',
  needs_review:
    'Påståendet finns i underlaget men kräver mänsklig granskning innan det kan anses fastställt.',
  unknown: 'Uppgift saknas. Frånvaro av uppgift är inte bevis för frånvaro av risk.',
  disputed: 'Källorna är motstridiga; läs källnoteringen.',
};

export const factorLabel: Record<FactorLevel, string> = {
  high: 'Hög',
  medium: 'Medel',
  low: 'Låg',
  unknown: 'Okänd',
};

export const factorName: Record<string, string> = {
  threat: 'Hot / sannolikhet',
  severity: 'Teknisk allvarlighet',
  relevance: 'Faktisk relevans (versionsmatchning)',
  exposure: 'Exponering',
  ot_impact: 'OT-konsekvens',
  mitigation_feasibility: 'Skydd och genomförbarhet',
  data_quality: 'Datakvalitet',
};

export const actionLabel: Record<RecommendedAction, string> = {
  verify_model_and_version: 'Fastställ modell och version',
  mitigate_if_exposed: 'Åtgärda vid bekräftad exponering',
  apply_vendor_fix: 'Tillämpa leverantörsfix',
  replace_or_isolate_eol: 'Byt ut eller isolera (livscykel)',
  harden_configuration: 'Härda konfiguration',
  monitor: 'Bevaka',
};

export const actionDescription: Record<RecommendedAction, string> = {
  verify_model_and_version:
    'Exakt modell, komponent och firmware måste fastställas innan en sårbarhetsbedömning är meningsfull.',
  mitigate_if_exposed:
    'Om en inventerad tillgång bekräftas exponerad ska kompenserande skydd och leverantörsfix prioriteras.',
  apply_vendor_fix:
    'Verifierad fix finns för verifierat berörda versioner; planera uppdatering i underhållsfönster.',
  replace_or_isolate_eol:
    'Produkten saknar stöd eller är utgående; planera utbyte och isolera strikt tills dess.',
  harden_configuration:
    'Protokollet eller tjänsten saknar inbyggt skydd; segmentera och konfigurera säkert.',
  monitor: 'Inga verifierade CVE-kopplingar i katalogen just nu; bevaka tillverkarens bulletiner.',
};

export const flagLabel: Record<DataQualityFlag, string> = {
  missing_primary_source: 'Saknar primärkälla',
  missing_cve_reference: 'Saknar CVE-/bulletinreferens',
  unknown_version_boundary: 'Okänd versionsgräns',
  unverified_fix_version: 'Overifierad fixversion',
  possibly_outdated: 'Möjligt inaktuellt påstående',
  needs_human_review: 'Behöver mänsklig granskning',
  generic_control_text: 'Generisk kontrolltext',
  industry_guide_only: 'Endast branschguide som dokumentation',
  conditional_priority_only: 'Villkorlig prioritet (P1 vid publik åtkomst)',
  patch_level_unknown: 'Patchningsgrad okänd',
  unexpanded_cve_range: 'Oexpanderat CVE-intervall',
  conflicting_sources: 'Motstridiga källor',
  broken_link: 'Trasig länk',
};

export const matchStatusLabel: Record<string, string> = {
  affected: 'Berörd',
  not_affected: 'Ej berörd',
  unknown: 'Okänt',
  under_investigation: 'Under utredning',
};

export const fixLabel: Record<string, string> = {
  yes: 'Fix finns',
  no: 'Ingen fix',
  partial: 'Delvis fix',
  planned: 'Fix planerad',
  none_planned: 'Ingen fix planerad',
  unknown: 'Okänt',
};

export const lifecycleLabel: Record<string, string> = {
  active: 'Aktiv',
  eol_announced: 'EOL annonserad',
  eol: 'Utgången (EOL)',
  mixed: 'Blandad (varierar inom familjen)',
  unknown: 'Okänd',
};

export const docLevelLabel: Record<string, string> = {
  product_manual: 'Produktmanual',
  hardening_guide: 'Hardening guide',
  security_guidance: 'Säkerhetsvägledning',
  bulletin_portal: 'Bulletinportal',
  vendor_support: 'Tillverkarsupport',
  industry_guide: 'Branschguide',
  standard: 'Standard',
  other: 'Övrigt',
};

export const sourceTypeLabel: Record<string, string> = {
  primary_vendor: 'Primär: tillverkare',
  primary_government: 'Primär: myndighet/CERT',
  primary_standard: 'Primär: standard',
  secondary_research: 'Sekundär: forskning',
  secondary_media: 'Sekundär: media',
  database: 'Databas/API',
  internal_workbook: 'Ursprunglig arbetsbok',
};

export const availabilityLabel: Record<string, string> = {
  ok: 'Tillgänglig',
  broken: 'Trasig',
  blocked: 'Blockerad',
  redirected: 'Omdirigerad',
  unchecked: 'Ej kontrollerad',
};

export const securityPropertyLabel: Record<string, string> = {
  none: 'Saknas',
  optional: 'Valfri',
  required: 'Krävs',
  depends: 'Beror på konfiguration',
  unknown: 'Okänt',
};

export function orMissing(v: string | null | undefined, fallback = MISSING): string {
  return v === null || v === undefined || v === '' ? fallback : v;
}

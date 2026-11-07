import type {
  DataQualityFlag,
  FactorLevel,
  InitialPasswordType,
  MaterialTypeCode,
  PublicPocStatus,
  RecommendedAction,
  RegisterOrigin,
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
  setup_manual_unverified: 'Setupmanual ej verifierad',
  account_name_unverified: 'Kontonamn ej verifierat',
  initial_password_type_unknown: 'Initiallösenordets typ okänd',
  register_conflict: 'Konflikt mellan register och projektdata',
};

export const originLabel: Record<RegisterOrigin, string> = {
  original: 'Original (66-postsinventeringen)',
  new: 'Ny (125-postregistret)',
};
export const originShort: Record<RegisterOrigin, string> = { original: 'Original', new: 'Ny' };

/** Typ av initialt/fabrikslösenord – aldrig värden. */
export const pwdTypeLabel: Record<InitialPasswordType, string> = {
  shared_default_documented: 'Gemensamt standardlösenord dokumenterat',
  default_exists_type_unknown: 'Standardlösenord förekommer – typ ej fastställd',
  device_unique_documented: 'Enhetsunikt initiallösenord enligt dokumentation',
  device_unique_normal_delivery: 'Enhetsunikt initiallösenord vid normal leverans',
  model_version_batch_dependent: 'Modell-/versions-/batchberoende initiallösenord',
  version_dependent_shared_or_unique: 'Versionsberoende – gemensamt eller enhetsbundet',
  set_at_commissioning: 'Lösenord väljs/skapas vid driftsättning',
  hardcoded_in_affected_version: 'Hårdkodade uppgifter i berörd version',
  predictable_builtin_mechanism: 'Förutsägbar inbyggd lösenordsmekanism i berörd version',
  not_applicable_implementation: 'Ej tillämpligt – implementation styr',
  unknown_unverified: 'Okänt – initiallösenordets typ ej verifierad',
};

export const pwdTypeDescription: Record<InitialPasswordType, string> = {
  shared_default_documented:
    'Ett gemensamt standardlösenord är dokumenterat. Byt det före skyddad drift; tekniskt tvång är inte generellt verifierat.',
  default_exists_type_unknown:
    'Leverantören anger att standardlösenord förekommer, men om det är gemensamt eller enhetsunikt är inte fastställt.',
  device_unique_documented: 'Dokumentationen anger ett enhetsunikt initiallösenord.',
  device_unique_normal_delivery:
    'Enhetsunikt initiallösenord vid normal leverans enligt dokumentationen.',
  model_version_batch_dependent:
    'Initiallösenordets typ beror på modell, version eller tillverkningsbatch – kontrollera den egna enheten.',
  version_dependent_shared_or_unique:
    'Beroende på version kan lösenordet vara gemensamt eller enhetsbundet.',
  set_at_commissioning:
    'Lösenordet skapas av installatören vid driftsättning/aktivering – välj ett unikt lösenord.',
  hardcoded_in_affected_version:
    'Hårdkodade uppgifter i berörd version (CVE). Ett vanligt lösenordsbyte räcker inte; följ firmwareåtgärd eller utbyte i bulletinen.',
  predictable_builtin_mechanism:
    'En förutsägbar inbyggd mekanism i berörd version. Kräver leverantörens åtgärd, inte bara lösenordsbyte.',
  not_applicable_implementation:
    'Protokoll/tjänst har inget universellt fabrikslösenord; den konkreta implementationen styr.',
  unknown_unverified:
    'Initiallösenordets typ är inte verifierad i underlaget. Okänt betyder inte säkert – kontrollera manual och lokala kontoinställningar.',
};

export const pocStatusLabel: Record<PublicPocStatus, string> = {
  poc_reported: 'Offentlig PoC rapporterad (CISA SSVC)',
  none_reported_at_assessment: 'Ingen PoC uppgiven vid CISA-bedömningen',
  unknown_missing: 'Okänt – CISA SSVC-bedömning saknas',
  active_reported: 'Aktiv exploatering uppgiven (KEV); PoC ej fastställd separat',
};
export const pocStatusShort: Record<PublicPocStatus, string> = {
  poc_reported: 'PoC rapporterad',
  none_reported_at_assessment: 'Ingen PoC uppgiven',
  unknown_missing: 'PoC-status okänd',
  active_reported: 'Aktiv exploatering',
};

export const materialTypeLabel: Record<MaterialTypeCode, string> = {
  none_verified: 'Ingen direkt PoC-länk verifierad',
  emulator_or_reconstructed_poc: 'Emulator / rekonstruerad PoC + detektionsmaterial',
  research_artifacts_and_detection: 'Forskningsartefakter och separat detektionsverktyg',
  component_exploit_published: 'Publicerad komponentexploit',
  component_poc_research: 'Forskarpublicerad komponent-PoC',
  research_publication_with_code: 'Forskarpublicering med kodlänk',
  public_exploit_archive: 'Publikt exploitarkiv med reproduktionsmaterial',
  official_active_exploitation_report: 'Officiell rapport om aktiv exploatering',
  incident_analysis_detection: 'Incidentanalys och detektionstemplate',
  cert_report_public_poc: 'CERT-rapport om offentlig PoC',
  other: 'Annan materialtyp',
};

export const setupDocTypeLabel: Record<string, string> = {
  direct_manual: 'Direkt instruktion/manual',
  doc_portal: 'Produktens dokumentportal',
  online_handbook: 'Onlinehandbok',
  vendor_entry_unverified: 'Leverantörsingång – setupmanual ej verifierad',
  security_guide_unverified: 'Säkerhetsguide – setupmanual ej verifierad',
  start_guide: 'Tillverkarens startinstruktion',
  not_product: 'Ej produkt – implementationsmanual krävs',
  unverified: 'Setupmanual ej verifierad',
  other: 'Övrigt',
};

export const nvdStatusLabel: Record<string, string> = {
  unknown: 'NVD-post ej hämtad',
  Received: 'NVD: mottagen',
  'Awaiting Analysis': 'NVD: inväntar analys',
  'Undergoing Analysis': 'NVD: under analys',
  Analyzed: 'NVD: analyserad',
  Modified: 'NVD: modifierad',
  Deferred: 'NVD: uppskjuten (Deferred)',
  Rejected: 'NVD: avvisad',
};

export const NO_PASSWORD_VALUES_NOTE =
  'Underlaget innehåller inga lösenordsvärden; endast kontonamn, lösenordstyp och bytekrav.';

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

export const otSuitabilityLabel: Record<string, string> = {
  high: 'hög',
  medium: 'medel',
  low: 'låg',
  depends: 'beror på miljön',
};

export const cveStatusLabel: Record<string, string> = {
  published: 'Publicerad',
  reserved: 'Reserverad',
  rejected: 'Avvisad',
  disputed: 'Ifrågasatt',
  unknown: 'Okänd',
};

export const evidenceTypeLabel: Record<string, string> = {
  kev: 'CISA KEV',
  vendor_statement: 'Leverantörsuppgift',
  cert_report: 'CERT-rapport',
  public_poc: 'Publik PoC',
  research_report: 'Forskningsrapport',
  none_reported: 'Inget rapporterat',
};

const FIELD_LABEL: Record<string, string> = {
  '*': 'hela posten',
  url: 'länk',
  documentation: 'dokumentation',
  threat_intel: 'hotunderlag',
  kev: 'CISA KEV',
  epss: 'EPSS',
  exploitation_evidence: 'exploateringsbelägg',
  references: 'referenser',
  fix: 'fixstatus',
  controls: 'åtgärder',
  methodology: 'metodik',
  default_ports: 'standardportar',
  cve_ids: 'CVE-koppling',
  advisory_ids: 'bulletinkoppling',
  match_ids: 'produkt–CVE-matchningar',
  'risk_summary.fix_text': 'fixuppgift',
  'risk_summary.explanation_text': 'riskförklaring',
  'risk_summary.affected_firmware_text': 'berörd firmware',
  'risk_summary.cve_text': 'CVE-uppgift',
};

/**
 * Översätter en intern fältsökväg (t.ex. "risk_summary.fix_text" eller
 * "matches.match-…-cve-2025-1234.fix") till en läsbar svensk etikett.
 */
export function fieldLabel(path: string): string {
  const m = /^matches\.match-.*?-(cve-\d{4}-\d+)\.(\w+)$/i.exec(path);
  if (m) {
    const cve = m[1]!.toUpperCase();
    return `${FIELD_LABEL[m[2]!] ?? m[2]} för ${cve}`;
  }
  return FIELD_LABEL[path] ?? path.replace(/[._]/g, ' ');
}

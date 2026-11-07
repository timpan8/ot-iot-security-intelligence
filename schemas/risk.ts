import { z } from 'zod';
import { SourceId } from './common';

/**
 * OT-anpassad riskmetod (avsnitt 7). Inspirerad av CISA SSVC:s beslutsfaktorer
 * men är INTE officiell SSVC. Ingen summerad risksiffra – varje faktor redovisas
 * separat med underlag, och exponering är alltid "unknown" i den publika katalogen.
 */

export const FactorLevel = z.enum(['high', 'medium', 'low', 'unknown']);
export type FactorLevel = z.infer<typeof FactorLevel>;

export const RiskFactor = z.strictObject({
  level: FactorLevel,
  basis: z.string().min(1), // kort förklaring av underlaget
  source_ids: z.array(SourceId).default([]),
});

/** Exponering får i publik katalog aldrig påstås – endast 'unknown'. */
export const ExposureFactor = z.strictObject({
  level: z.literal('unknown'),
  basis: z.string().min(1),
  source_ids: z.array(SourceId).default([]),
});

export const RecommendedAction = z.enum([
  'verify_model_and_version', // modell/firmware måste fastställas innan bedömning
  'mitigate_if_exposed', // vid bekräftad exponering: åtgärda omedelbart (fix/kompenserande)
  'apply_vendor_fix', // verifierad fix finns för verifierat berörda versioner
  'replace_or_isolate_eol', // livscykelrisk: utbyte eller strikt isolering
  'harden_configuration', // protokoll/tjänst: konfigurationsåtgärder
  'monitor', // bevaka bulletiner, inga aktiva kända CVE-kopplingar
]);
export type RecommendedAction = z.infer<typeof RecommendedAction>;

export const RiskAssessment = z.strictObject({
  threat: RiskFactor, // KEV, EPSS, exploit-rapporter, attackförutsättningar
  severity: RiskFactor, // CVSS + leverantörskontext
  relevance: RiskFactor, // styrkt modell-/versionsmatchning
  exposure: ExposureFactor, // alltid unknown utan asset-data
  ot_impact: RiskFactor, // potentiell OT-konsekvens (person/process/drift/kylkedja/energi/passage)
  mitigation_feasibility: RiskFactor, // fix finns, EOL, kompenserande kontroller
  data_quality: RiskFactor, // hur väl underbyggd bedömningen är
  recommended_action: RecommendedAction,
  rationale: z.string().min(1),
  method_version: z.literal('risk-method-1.0'),
});
export type RiskAssessment = z.infer<typeof RiskAssessment>;

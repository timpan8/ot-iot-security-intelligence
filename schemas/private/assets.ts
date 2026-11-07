/**
 * PRIVAT ASSET-SCHEMA – endast design för en framtida separat modul.
 * Får ALDRIG importeras av src/ eller inkluderas i public/data eller dist/.
 * Lagra inga poster i detta repo.
 */
import { z } from 'zod';

export const AssetCriticality = z.enum(['safety', 'critical', 'high', 'medium', 'low', 'unknown']);
export const ExposureState = z.enum([
  'internet_exposed_confirmed',
  'internal_only_confirmed',
  'unknown',
]);
export const RemediationStatus = z.enum([
  'open',
  'planned',
  'in_progress',
  'mitigated',
  'fixed',
  'risk_accepted',
  'decommissioned',
]);

export const PrivateAsset = z.strictObject({
  id: z.string().min(1),
  product_family_id: z.string().min(1), // referens till publik katalog
  site: z.string().min(1),
  building: z.string().nullable(),
  owner: z.string().min(1), // organisatorisk ägare (roll/avdelning)
  contact: z.string().nullable(),
  criticality: AssetCriticality,
  network_zone: z.string().min(1),
  ip_address: z.string().nullable(),
  hostname: z.string().nullable(),
  serial_number: z.string().nullable(),
  installed_version: z.string().nullable(),
  exposure: ExposureState,
  exposure_evidence: z.string().nullable(),
  maintenance_window: z.string().nullable(),
  backup_and_restore: z.strictObject({
    backup_exists: z.boolean().nullable(),
    last_tested_restore: z.iso.date().nullable(),
    rto_hours: z.number().nullable(),
  }),
  risk_acceptance: z
    .strictObject({
      accepted_by_role: z.string(),
      accepted_at: z.iso.date(),
      expires_at: z.iso.date().nullable(),
      rationale: z.string(),
    })
    .nullable(),
  remediation: z.array(
    z.strictObject({
      match_id: z.string().min(1),
      status: RemediationStatus,
      ticket: z.string().nullable(),
      updated_at: z.iso.date(),
    }),
  ),
});
export type PrivateAsset = z.infer<typeof PrivateAsset>;

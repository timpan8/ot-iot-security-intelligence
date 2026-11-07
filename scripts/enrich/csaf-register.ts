/**
 * Hämtar CSAF-dokument för alla CISA-bulletiner i registrets källmanifest
 * (sources/raw/register/source_manifest.json, "CISA CSAF") till sources/enrichment/csaf/.
 *   npx tsx scripts/enrich/csaf-register.ts [--dry-run]
 */
import { existsSync } from 'node:fs';
import { p, readJson } from '../lib/fs';
import { fetchCsaf } from './csaf';

interface ManifestJson {
  records: {
    row: number;
    fields: { source_key: string | null; publisher_format: string | null; url: string | null };
  }[];
}

export function csafAdvisoriesFromManifest(
  path = p('sources', 'raw', 'register', 'source_manifest.json'),
) {
  if (!existsSync(path)) return [];
  const m = readJson<ManifestJson>(path);
  return m.records
    .filter((r) => r.fields.publisher_format === 'CISA CSAF' && r.fields.url && r.fields.source_key)
    .map((r) => ({
      advisory_id: r.fields.source_key!,
      issuer: 'CISA ICS',
      csaf_url: r.fields.url!,
    }));
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  const advs = csafAdvisoriesFromManifest();
  console.log(`${advs.length} CISA CSAF-bulletiner i källmanifestet`);
  fetchCsaf(advs, { dryRun: process.argv.includes('--dry-run') })
    .then((r) =>
      console.log(
        `CSAF: hämtade ${r.fetched.length}, hoppade över ${r.skipped.length}, fel ${r.errors.length}`,
        r.errors.slice(0, 5),
      ),
    )
    .catch((e) => {
      console.error(e);
      process.exit(1);
    });
}

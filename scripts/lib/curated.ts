import { existsSync } from 'node:fs';
import { p, readJson } from './fs';

/**
 * Kuraterade filer skrivs som { "_comment": "...", "<key>": [...] } eller som rena arrayer/objekt.
 * Denna hjälpare normaliserar båda formerna så att skript kan läsa dem enhetligt.
 */
export function loadCuratedArray<T = unknown>(file: string, key: string): T[] {
  const path = p('sources', 'curated', file);
  if (!existsSync(path)) return [];
  const raw = readJson<unknown>(path);
  if (Array.isArray(raw)) return raw as T[];
  if (raw && typeof raw === 'object' && Array.isArray((raw as Record<string, unknown>)[key])) {
    return (raw as Record<string, T[]>)[key]!;
  }
  throw new Error(`${file}: förväntade array eller objekt med nyckeln "${key}"`);
}

export function loadCuratedRecord<T = unknown>(file: string, key: string): Record<string, T> {
  const path = p('sources', 'curated', file);
  if (!existsSync(path)) return {};
  const raw = readJson<Record<string, unknown>>(path);
  const inner = raw[key];
  if (inner && typeof inner === 'object' && !Array.isArray(inner))
    return inner as Record<string, T>;
  // Rent objekt utan wrapper: filtrera bort _comment
  const out: Record<string, T> = {};
  for (const [k, v] of Object.entries(raw)) if (!k.startsWith('_')) out[k] = v as T;
  return out;
}

export const CURATED_FILES = {
  vendors: ['vendors.json', 'vendors'],
  sources: ['sources.json', 'sources'],
  advisories: ['advisories.json', 'advisories'],
  matches: ['matches.json', 'matches'],
  controls: ['controls.json', 'controls'],
  observations: ['observations.json', 'observations'],
  overrides: ['overrides.json', 'rows'],
  vulnerability_overrides: ['vulnerability_overrides.json', 'overrides'],
} as const;

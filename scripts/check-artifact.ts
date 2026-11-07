/**
 * Artefaktkontroll (postbuild): dist/ får inte innehålla interna nycklar, arbetsboken
 * eller något utanför den publika datamodellen. Kontrollerar också att dist/data
 * är identisk med public/data.
 */
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { DATA_FILES, FORBIDDEN_PUBLIC_KEYS } from '../schemas/index';
import { p } from './lib/fs';

export interface ArtifactCheckResult {
  ok: boolean;
  errors: string[];
  files_scanned: number;
}

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

export function checkArtifact(
  distDir = p('dist'),
  publicData = p('public', 'data'),
): ArtifactCheckResult {
  const errors: string[] = [];
  if (!existsSync(distDir))
    return { ok: false, errors: [`dist saknas: ${distDir}`], files_scanned: 0 };
  const files = walk(distDir);
  const keyPattern = new RegExp(
    `"(${FORBIDDEN_PUBLIC_KEYS.map((k) => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})"\\s*:`,
    'i',
  );
  for (const f of files) {
    const rel = relative(distDir, f);
    if (/\.(xlsx|xlsm|xls|csv)$/i.test(rel)) errors.push(`Otillåten fil i dist: ${rel}`);
    if (/sources\/|schemas\/private/.test(rel)) errors.push(`Otillåten sökväg i dist: ${rel}`);
    if (/\.(json|js|html|txt|md)$/i.test(rel)) {
      const text = readFileSync(f, 'utf8');
      const m = keyPattern.exec(text);
      if (m && rel.startsWith('data/')) errors.push(`Förbjuden nyckel "${m[1]}" i ${rel}`);
      if (
        /\.json$/i.test(rel) &&
        /"(ip_address|serial_number|network_zone|installed_version)"/.test(text)
      )
        errors.push(`Privat asset-fält i ${rel}`);
      if (/sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}/.test(text))
        errors.push(`Möjlig hemlighet i ${rel}`);
    }
  }
  for (const file of Object.values(DATA_FILES)) {
    const a = join(distDir, 'data', file);
    const b = join(publicData, file);
    if (!existsSync(a)) errors.push(`dist/data/${file} saknas`);
    else if (!existsSync(b)) errors.push(`public/data/${file} saknas`);
    else {
      const ha = createHash('sha256').update(readFileSync(a)).digest('hex');
      const hb = createHash('sha256').update(readFileSync(b)).digest('hex');
      if (ha !== hb) errors.push(`dist/data/${file} skiljer sig från public/data`);
    }
  }
  if (!existsSync(join(distDir, 'index.html'))) errors.push('dist/index.html saknas');
  return { ok: errors.length === 0, errors, files_scanned: files.length };
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  const res = checkArtifact();
  if (!res.ok) {
    console.error('Artefaktkontroll misslyckades:');
    for (const e of res.errors) console.error('  -', e);
    process.exit(1);
  }
  console.log(
    `Artefaktkontroll OK: ${res.files_scanned} filer i dist/, inga interna nycklar, data identisk med public/data.`,
  );
}

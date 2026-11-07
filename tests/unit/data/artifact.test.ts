import { describe, expect, it } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { FORBIDDEN_PUBLIC_KEYS } from '../../../schemas/index';
import { p } from '../../../scripts/lib/fs';

describe('skyddsgräns i källkod och publik data', () => {
  it('src/ importerar aldrig schemas/private', () => {
    const walk = (dir: string): string[] =>
      readdirSync(dir, { withFileTypes: true }).flatMap((d) =>
        d.isDirectory() ? walk(join(dir, d.name)) : [join(dir, d.name)],
      );
    const files = walk(p('src')).filter((f) => /\.(ts|tsx)$/.test(f));
    for (const f of files) expect(readFileSync(f, 'utf8')).not.toMatch(/schemas\/private/);
  });

  it('public/data innehåller inga förbjudna nycklar eller http-länkar', () => {
    const dir = p('public', 'data');
    if (!existsSync(dir)) return; // genereras av data:build
    const re = new RegExp(`"(${FORBIDDEN_PUBLIC_KEYS.join('|')})"\\s*:`, 'i');
    for (const f of readdirSync(dir)) {
      const text = readFileSync(join(dir, f), 'utf8');
      expect(re.test(text), `${f} innehåller förbjuden nyckel`).toBe(false);
      // Prosa (t.ex. NVD-beskrivningar) får innehålla http://-text; URL-fält måste vara https. link_checks.json lagrar kontrollerade URL:er som ren text.
      if (f !== 'link_checks.json')
        expect(
          /"(url|final_url|poc_url|csaf_url|security_portal_url|psirt_contact_url|vendor_guide_url)": "http:\/\//.test(
            text,
          ),
          `${f} innehåller http-länk i URL-fält`,
        ).toBe(false);
    }
  });

  it('inga xlsx-filer i public/', () => {
    const walk = (dir: string): string[] =>
      readdirSync(dir, { withFileTypes: true }).flatMap((d) =>
        d.isDirectory() ? walk(join(dir, d.name)) : [join(dir, d.name)],
      );
    expect(walk(p('public')).some((f) => /\.xlsx$/i.test(f))).toBe(false);
  });
});

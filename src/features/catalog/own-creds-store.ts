/**
 * Egna inloggningsuppgifter per post, ENBART i webbläsarens localStorage på
 * den här enheten. Laddas aldrig upp, committas aldrig och ingår inte i export
 * eller publik data – plattformen har ingen server. Export/import går mot en
 * lokal fil som användaren själv styr över.
 */
export interface OwnCreds {
  u: string;
  p: string;
}

const PREFIX = 'otsi-own-creds:';

export function readOwnCreds(id: string): OwnCreds | null {
  try {
    const raw = localStorage.getItem(PREFIX + id);
    if (!raw) return null;
    const v = JSON.parse(raw) as unknown;
    if (v && typeof v === 'object') {
      const u = typeof (v as OwnCreds).u === 'string' ? (v as OwnCreds).u : '';
      const p = typeof (v as OwnCreds).p === 'string' ? (v as OwnCreds).p : '';
      return u || p ? { u, p } : null;
    }
    return null;
  } catch {
    return null;
  }
}

export function writeOwnCreds(id: string, creds: OwnCreds | null): void {
  try {
    if (creds && (creds.u || creds.p)) localStorage.setItem(PREFIX + id, JSON.stringify(creds));
    else localStorage.removeItem(PREFIX + id);
  } catch {
    /* lagring kan vara blockerad – uppgiften gäller då bara denna visning */
  }
}

export function collectOwnCreds(): Record<string, OwnCreds> {
  const out: Record<string, OwnCreds> = {};
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (!key || !key.startsWith(PREFIX)) continue;
      const c = readOwnCreds(key.slice(PREFIX.length));
      if (c) out[key.slice(PREFIX.length)] = c;
    }
  } catch {
    /* lagring blockerad */
  }
  return out;
}

/** Skriver in uppgifter från en importerad fil. replace=true nollställer först. */
export function importOwnCreds(data: unknown, replace: boolean): number {
  if (!data || typeof data !== 'object') throw new Error('Filen har fel format.');
  const entries = Object.entries(data as Record<string, unknown>).filter(
    ([, v]) =>
      v &&
      typeof v === 'object' &&
      (typeof (v as OwnCreds).u === 'string' || typeof (v as OwnCreds).p === 'string'),
  );
  if (replace) for (const id of Object.keys(collectOwnCreds())) writeOwnCreds(id, null);
  let n = 0;
  for (const [id, v] of entries) {
    const c = v as OwnCreds;
    writeOwnCreds(id, {
      u: typeof c.u === 'string' ? c.u : '',
      p: typeof c.p === 'string' ? c.p : '',
    });
    n++;
  }
  return n;
}

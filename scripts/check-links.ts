/**
 * Länkkontroll för källor. Rapporterar – fallerar ALDRIG bygget.
 * Läser public/data/sources.json (annars sources/curated/sources.json), gör en förfrågan
 * per unik URL (HEAD, fallback GET med Range) med timeout 20 s, max 4 parallellt,
 * och skriver sources/link-report.json.
 */
import { existsSync } from 'node:fs';
import { p, readJson, writeJson, nowIso } from './lib/fs';

export type Availability = 'ok' | 'broken' | 'blocked' | 'redirected' | 'unchecked';

export interface LinkResult {
  source_id: string;
  url: string;
  status_code: number | null;
  availability: Availability;
  checked_at: string;
  final_url: string | null;
  error?: string;
}

interface SourceLike {
  id: string;
  url: string;
}

const UA =
  'ot-iot-security-intelligence-link-check/0.1.0 (+https://github.com/timpan8/ot-iot-security-intelligence)';

export function classify(status: number | null, redirected: boolean, error?: string): Availability {
  if (error) return 'unchecked';
  if (status === null) return 'unchecked';
  if (status === 401 || status === 403 || status === 429 || status === 451) return 'blocked';
  if (status >= 200 && status < 300) return redirected ? 'redirected' : 'ok';
  if (status === 404 || status === 410 || status >= 500) return 'broken';
  if (status >= 300 && status < 400) return 'redirected';
  return 'unchecked';
}

export async function checkUrl(
  url: string,
  fetchImpl: typeof fetch = fetch,
  timeoutMs = 20_000,
): Promise<{
  status: number | null;
  redirected: boolean;
  final_url: string | null;
  error?: string;
}> {
  if (!url.startsWith('https://'))
    return { status: null, redirected: false, final_url: null, error: 'inte https' };
  const attempt = async (method: 'HEAD' | 'GET') => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetchImpl(url, {
        method,
        redirect: 'follow',
        signal: controller.signal,
        headers: {
          'User-Agent': UA,
          Accept: '*/*',
          ...(method === 'GET' ? { Range: 'bytes=0-1023' } : {}),
        },
      });
      // Läs inte kroppen – avbryt direkt.
      try {
        await res.body?.cancel();
      } catch {
        /* ignoreras */
      }
      const finalUrl = res.url && res.url.length > 0 ? res.url : url;
      return {
        status: res.status,
        redirected: res.redirected || finalUrl !== url,
        final_url: finalUrl,
      };
    } finally {
      clearTimeout(timer);
    }
  };
  try {
    const head = await attempt('HEAD');
    if (head.status === 405 || head.status === 403 || head.status === 404 || head.status >= 500) {
      try {
        return await attempt('GET');
      } catch {
        return head;
      }
    }
    return head;
  } catch (err) {
    try {
      return await attempt('GET');
    } catch (err2) {
      return {
        status: null,
        redirected: false,
        final_url: null,
        error:
          (err2 instanceof Error ? err2.message : String(err2)) ||
          (err instanceof Error ? err.message : String(err)),
      };
    }
  }
}

export async function checkLinks(
  sources: SourceLike[],
  concurrency = 4,
  fetchImpl: typeof fetch = fetch,
): Promise<LinkResult[]> {
  const byUrl = new Map<string, SourceLike[]>();
  for (const s of sources) byUrl.set(s.url, [...(byUrl.get(s.url) ?? []), s]);
  const urls = [...byUrl.keys()];
  const results: LinkResult[] = [];
  let i = 0;
  const worker = async () => {
    while (i < urls.length) {
      const url = urls[i++]!;
      const r = await checkUrl(url, fetchImpl);
      const checked_at = nowIso();
      for (const s of byUrl.get(url) ?? []) {
        results.push({
          source_id: s.id,
          url,
          status_code: r.status,
          availability: classify(r.status, r.redirected, r.error),
          checked_at,
          final_url: r.final_url,
          ...(r.error ? { error: r.error } : {}),
        });
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, urls.length) }, worker));
  return results.sort((a, b) => a.source_id.localeCompare(b.source_id));
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  const publicPath = p('public', 'data', 'sources.json');
  const curatedPath = p('sources', 'curated', 'sources.json');
  const path = existsSync(publicPath) ? publicPath : curatedPath;
  if (!existsSync(path)) {
    console.error('Ingen källfil hittades – hoppar över länkkontroll.');
    process.exit(0);
  }
  const raw = readJson<unknown>(path);
  const sources = (Array.isArray(raw) ? raw : []).filter(
    (s): s is SourceLike =>
      !!s &&
      typeof s === 'object' &&
      typeof (s as SourceLike).id === 'string' &&
      typeof (s as SourceLike).url === 'string',
  );
  checkLinks(sources)
    .then((results) => {
      writeJson(p('sources', 'link-report.json'), {
        checked_at: nowIso(),
        source_file: path.replace(p() + '/', ''),
        results,
      });
      const counts = results.reduce<Record<string, number>>(
        (acc, r) => ((acc[r.availability] = (acc[r.availability] ?? 0) + 1), acc),
        {},
      );
      console.log(`Länkkontroll klar: ${results.length} källor`, counts);
      process.exit(0);
    })
    .catch((err) => {
      console.error('Länkkontroll avbröts:', err instanceof Error ? err.message : err);
      process.exit(0);
    });
}

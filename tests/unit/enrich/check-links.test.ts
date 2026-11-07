import { describe, it, expect, vi } from 'vitest';
import { classify, checkLinks } from '../../../scripts/check-links';

describe('check-links', () => {
  it('klassificerar statuskoder', () => {
    expect(classify(200, false)).toBe('ok');
    expect(classify(200, true)).toBe('redirected');
    expect(classify(404, false)).toBe('broken');
    expect(classify(403, false)).toBe('blocked');
    expect(classify(null, false, 'timeout')).toBe('unchecked');
  });
  it('gör en förfrågan per unik URL och mappar till alla källor', async () => {
    const fetchImpl = vi.fn(
      async (url: string) =>
        ({
          status: url.includes('bad') ? 404 : 200,
          redirected: false,
          url,
          body: null,
        }) as unknown as Response,
    ) as unknown as typeof fetch;
    const results = await checkLinks(
      [
        { id: 'src-a', url: 'https://example.com/a' },
        { id: 'src-b', url: 'https://example.com/a' },
        { id: 'src-c', url: 'https://example.com/bad' },
      ],
      2,
      fetchImpl,
    );
    expect(results.map((r) => `${r.source_id}:${r.availability}`)).toEqual([
      'src-a:ok',
      'src-b:ok',
      'src-c:broken',
    ]);
    // a: 1 HEAD; bad: HEAD(404) + GET-fallback = 2
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });
});

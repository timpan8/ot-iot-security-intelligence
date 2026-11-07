import { describe, expect, it } from 'vitest';
import { DEFAULT_FILTERS, countActiveFilters, parseFilters, serializeFilters } from '@/lib/filters';

describe('URL-filter', () => {
  it('tolkar parametrar från URL', () => {
    const f = parseFilters(
      new URLSearchParams(
        'q=danfoss&vendor=vendor-danfoss,vendor-siemens&kind=product_family&kev=yes&flags=missing_primary_source&sort=vendor&dir=desc',
      ),
    );
    expect(f.q).toBe('danfoss');
    expect(f.vendor).toEqual(['vendor-danfoss', 'vendor-siemens']);
    expect(f.kind).toBe('product_family');
    expect(f.kev).toBe('yes');
    expect(f.flags).toEqual(['missing_primary_source']);
    expect(f.sort).toBe('vendor');
    expect(f.dir).toBe('desc');
    expect(countActiveFilters(f)).toBe(5);
  });
  it('ignorerar ogiltiga värden', () => {
    const f = parseFilters(new URLSearchParams('kind=hacker&kev=maybe&sort=evil&dir=sideways'));
    expect(f.kind).toBe('all');
    expect(f.kev).toBe('any');
    expect(f.sort).toBe('name');
    expect(f.dir).toBe('asc');
    expect(countActiveFilters(f)).toBe(0);
  });
  it('serialisering är omvändbar', () => {
    const f = {
      ...DEFAULT_FILTERS,
      q: 'modbus',
      category: ['Tjänst'],
      verification: ['unknown'],
      kev: 'no' as const,
    };
    const back = parseFilters(serializeFilters(f));
    expect(back).toEqual(f);
    expect(serializeFilters(DEFAULT_FILTERS).toString()).toBe('');
  });
});

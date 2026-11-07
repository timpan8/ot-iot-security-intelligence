export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return 'Uppgift saknas';
  return iso.length > 10 ? iso.slice(0, 10) : iso;
}

export function fmtPct(v: number | null | undefined, digits = 1): string {
  if (v === null || v === undefined) return 'Okänt';
  return `${(v * 100).toFixed(digits).replace('.', ',')} %`;
}

export function fmtScore(v: number | null | undefined): string {
  if (v === null || v === undefined) return 'Okänt';
  return v.toFixed(1).replace('.', ',');
}

export function pct(part: number, total: number): string {
  if (total === 0) return '0 %';
  return `${Math.round((part / total) * 100)} %`;
}

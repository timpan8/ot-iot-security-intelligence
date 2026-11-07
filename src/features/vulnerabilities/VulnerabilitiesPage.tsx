import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { useDataset } from '@/data/DatasetContext';
import { Badge, PocBadge, VerificationBadge } from '@/components/Badge';
import { EmptyState, PageHeader } from '@/components/ui';
import { fmtDate, fmtPct, fmtScore } from '@/lib/format';
import { materialTypeLabel, nvdStatusLabel, pocStatusLabel } from '@/lib/labels';
import { MaterialTypeCode, PublicPocStatus } from '@schemas/index';

function bestCvss(v: {
  cvss: Array<{ version: string; base_score: number; type: string }>;
  register_cvss: { version: string; base_score: number | null } | null;
}) {
  const order = ['4.0', '3.1', '3.0', '2.0'];
  const sorted = v.cvss.slice().sort((a, b) => {
    const t = (a.type === 'Primary' ? 0 : 1) - (b.type === 'Primary' ? 0 : 1);
    return t || order.indexOf(a.version) - order.indexOf(b.version);
  });
  const first = sorted[0];
  if (first) return { ...first, from: 'NVD' as const };
  if (v.register_cvss && v.register_cvss.base_score !== null)
    return {
      version: v.register_cvss.version,
      base_score: v.register_cvss.base_score,
      from: 'register' as const,
    };
  return null;
}

export function VulnerabilitiesPage() {
  const d = useDataset();
  const [q, setQ] = useState('');
  const [onlyKev, setOnlyKev] = useState(false);
  const [poc, setPoc] = useState<'any' | PublicPocStatus>('any');
  const [material, setMaterial] = useState<'any' | MaterialTypeCode>('any');
  const [sort, setSort] = useState<'severity' | 'newest'>('severity');
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return d.vulnerabilities
      .filter(
        (v) =>
          (!onlyKev || v.kev.listed) &&
          (poc === 'any' || v.threat_intel?.public_poc_status === poc) &&
          (material === 'any' || v.threat_intel?.material_type_code === material) &&
          (!needle ||
            `${v.cve_id} ${v.summary} ${v.summary_sv ?? ''} ${v.register_cvss?.cwe_text ?? ''}`
              .toLowerCase()
              .includes(needle)),
      )
      .sort((a, b) => {
        if (sort === 'newest') return b.cve_id.localeCompare(a.cve_id);
        const sa = bestCvss(a)?.base_score ?? -1;
        const sb = bestCvss(b)?.base_score ?? -1;
        return (
          Number(b.kev.listed) - Number(a.kev.listed) || sb - sa || b.cve_id.localeCompare(a.cve_id)
        );
      });
  }, [d, q, onlyKev, poc, material, sort]);
  const pocCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const v of d.vulnerabilities)
      if (v.threat_intel)
        m.set(v.threat_intel.public_poc_status, (m.get(v.threat_intel.public_poc_status) ?? 0) + 1);
    return m;
  }, [d]);

  return (
    <>
      <PageHeader
        title="Sårbarheter (CVE)"
        lead="CVE:er med källbelagd produktkoppling (NVD, CISA CSAF eller primär bulletin). CVSS, EPSS, KEV och PoC-status är separata signaler och ersätter inte en OT-konsekvensbedömning. Poster märkta ”NVD-post ej hämtad” bygger på registrets källtext."
      />
      <div className="card flex flex-wrap items-end gap-3 p-3">
        <div className="grow">
          <label htmlFor="vq" className="block text-xs font-medium text-muted">
            Sök CVE-id eller text
          </label>
          <input
            id="vq"
            type="search"
            className="input mt-1"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={onlyKev} onChange={(e) => setOnlyKev(e.target.checked)} />
          Endast CISA KEV
        </label>
        <div>
          <label htmlFor="vpoc" className="block text-xs font-medium text-muted">
            PoC-status (hotunderlag)
          </label>
          <select
            id="vpoc"
            className="input mt-1"
            value={poc}
            onChange={(e) => setPoc(e.target.value as typeof poc)}
          >
            <option value="any">Oavsett</option>
            {PublicPocStatus.options.map((s) => (
              <option key={s} value={s}>
                {pocStatusLabel[s]} ({pocCounts.get(s) ?? 0})
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="vmat" className="block text-xs font-medium text-muted">
            Materialtyp
          </label>
          <select
            id="vmat"
            className="input mt-1"
            value={material}
            onChange={(e) => setMaterial(e.target.value as typeof material)}
          >
            <option value="any">Oavsett</option>
            {MaterialTypeCode.options.map((s) => (
              <option key={s} value={s}>
                {materialTypeLabel[s]}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="vsort" className="block text-xs font-medium text-muted">
            Sortering
          </label>
          <select
            id="vsort"
            className="input mt-1"
            value={sort}
            onChange={(e) => setSort(e.target.value as typeof sort)}
          >
            <option value="severity">KEV och högst CVSS först</option>
            <option value="newest">Nyast CVE-id först</option>
          </select>
        </div>
        <span className="text-sm text-muted" role="status">
          {rows.length} poster
        </span>
      </div>
      {rows.length === 0 ? (
        <div className="mt-4">
          <EmptyState>Inga CVE-poster matchar.</EmptyState>
        </div>
      ) : (
        <div className="mt-4 overflow-x-auto">
          <table className="table card">
            <thead>
              <tr>
                <th scope="col">CVE</th>
                <th scope="col">Sammanfattning</th>
                <th scope="col">CVSS</th>
                <th scope="col">EPSS</th>
                <th scope="col">KEV</th>
                <th scope="col">PoC</th>
                <th scope="col">Berörda produkter</th>
                <th scope="col">Verifiering</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((v) => {
                const c = bestCvss(v);
                const products = (d.matchesByVulnerability.get(v.id) ?? [])
                  .map((m) => d.productById.get(m.product_family_id))
                  .filter((p): p is NonNullable<typeof p> => Boolean(p));
                const uniq = [...new Map(products.map((p) => [p.id, p])).values()];
                return (
                  <tr key={v.id}>
                    <td className={`whitespace-nowrap ${v.kev.listed ? 'bar-danger' : ''}`}>
                      <Link to={`/sarbarheter/${v.cve_id}`} className="font-mono text-sm">
                        {v.cve_id}
                      </Link>
                      <div className="text-xs text-muted">
                        {nvdStatusLabel[v.nvd_status] ?? v.nvd_status}
                      </div>
                    </td>
                    <td className="max-w-md text-xs">
                      <span className="clamp-2" title={v.summary_sv ?? v.summary}>
                        {v.summary_sv ?? v.summary}
                      </span>
                    </td>
                    <td className="num whitespace-nowrap text-sm">
                      {c ? (
                        <>
                          <span className={c.base_score >= 9 ? 'font-semibold text-danger' : ''}>
                            {fmtScore(c.base_score)}
                          </span>{' '}
                          <span className="text-xs text-muted">v{c.version}</span>
                          {c.from === 'register' ? (
                            <div className="text-xs text-muted">registret</div>
                          ) : null}
                        </>
                      ) : (
                        <span className="text-muted">Okänt</span>
                      )}
                    </td>
                    <td className="num whitespace-nowrap text-xs">
                      {v.epss ? (
                        <span title={`EPSS ${fmtDate(v.epss.date)}`}>
                          {fmtPct(v.epss.score, 2)}
                        </span>
                      ) : (
                        <span className="text-muted">Okänt</span>
                      )}
                    </td>
                    <td>
                      {v.kev.listed ? (
                        <Badge tone="danger">KEV {fmtDate(v.kev.date_added)}</Badge>
                      ) : (
                        <span className="text-muted">–</span>
                      )}
                    </td>
                    <td className="text-xs">
                      {v.threat_intel ? (
                        <>
                          {v.threat_intel.public_poc_status === 'none_reported_at_assessment' ? (
                            <span className="text-muted">Ingen uppgiven</span>
                          ) : (
                            <PocBadge status={v.threat_intel.public_poc_status} short />
                          )}
                          {v.threat_intel.material_type_code !== 'none_verified' ? (
                            <div className="mt-1 text-muted">
                              {materialTypeLabel[v.threat_intel.material_type_code]}
                            </div>
                          ) : null}
                        </>
                      ) : (
                        <span className="text-muted">–</span>
                      )}
                    </td>
                    <td className="text-xs">
                      {uniq.length ? (
                        uniq.map((p) => (
                          <Link key={p.id} to={`/produkt/${p.id}`} className="mr-2">
                            {p.name}
                          </Link>
                        ))
                      ) : (
                        <span className="text-muted">Ingen matchning</span>
                      )}
                    </td>
                    <td>
                      <VerificationBadge status={v.verification_status} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

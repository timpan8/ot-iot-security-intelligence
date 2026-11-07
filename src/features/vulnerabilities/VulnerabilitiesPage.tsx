import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { useDataset } from '@/data/DatasetContext';
import { Badge, VerificationBadge } from '@/components/Badge';
import { EmptyState, PageHeader } from '@/components/ui';
import { fmtDate, fmtPct, fmtScore } from '@/lib/format';

function bestCvss(v: { cvss: Array<{ version: string; base_score: number; type: string }> }) {
  const order = ['4.0', '3.1', '3.0', '2.0'];
  const sorted = v.cvss.slice().sort((a, b) => {
    const t = (a.type === 'Primary' ? 0 : 1) - (b.type === 'Primary' ? 0 : 1);
    return t || order.indexOf(a.version) - order.indexOf(b.version);
  });
  return sorted[0] ?? null;
}

export function VulnerabilitiesPage() {
  const d = useDataset();
  const [q, setQ] = useState('');
  const [onlyKev, setOnlyKev] = useState(false);
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return d.vulnerabilities
      .filter(
        (v) =>
          (!onlyKev || v.kev.listed) &&
          (!needle ||
            `${v.cve_id} ${v.summary} ${v.summary_sv ?? ''}`.toLowerCase().includes(needle)),
      )
      .sort((a, b) => b.cve_id.localeCompare(a.cve_id));
  }, [d, q, onlyKev]);

  return (
    <>
      <PageHeader
        title="Sårbarheter (CVE)"
        lead="Endast CVE:er som verifierats individuellt mot NVD eller en primär bulletin. CVSS, EPSS och KEV är separata signaler och ersätter inte en OT-konsekvensbedömning."
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
                    <td>
                      <Link to={`/sarbarheter/${v.cve_id}`} className="font-mono text-sm">
                        {v.cve_id}
                      </Link>
                      <div className="text-xs text-muted">{v.nvd_status}</div>
                    </td>
                    <td className="max-w-md text-xs">{v.summary_sv ?? v.summary}</td>
                    <td className="text-sm tabular-nums">
                      {c ? (
                        `${fmtScore(c.base_score)} (v${c.version})`
                      ) : (
                        <span className="text-muted">Okänt</span>
                      )}
                    </td>
                    <td className="text-xs tabular-nums">
                      {v.epss ? (
                        <>
                          {fmtPct(v.epss.score, 2)}
                          <div className="text-muted">{fmtDate(v.epss.date)}</div>
                        </>
                      ) : (
                        <span className="text-muted">Okänt</span>
                      )}
                    </td>
                    <td>
                      {v.kev.listed ? (
                        <Badge tone="danger">KEV {fmtDate(v.kev.date_added)}</Badge>
                      ) : (
                        <Badge>Ej i KEV</Badge>
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

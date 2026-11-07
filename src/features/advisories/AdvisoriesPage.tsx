import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { useDataset } from '@/data/DatasetContext';
import { Badge, VerificationBadge } from '@/components/Badge';
import { SafeLink } from '@/components/SafeLink';
import { EmptyState, PageHeader } from '@/components/ui';
import { fmtDate } from '@/lib/format';
import { sourceTypeLabel } from '@/lib/labels';

export function AdvisoriesPage() {
  const d = useDataset();
  const [q, setQ] = useState('');
  const [issuer, setIssuer] = useState('all');
  const issuers = useMemo(
    () => [...new Set(d.advisories.map((a) => a.issuer))].sort((a, b) => a.localeCompare(b, 'sv')),
    [d],
  );
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return d.advisories
      .filter(
        (a) =>
          (issuer === 'all' || a.issuer === issuer) &&
          (!needle ||
            `${a.advisory_id} ${a.title} ${a.cve_ids.join(' ')}`.toLowerCase().includes(needle)),
      )
      .sort((a, b) => (b.published_at ?? '').localeCompare(a.published_at ?? ''));
  }, [d, q, issuer]);
  return (
    <>
      <PageHeader
        title="Bulletiner (advisories)"
        lead="Leverantörs- och CERT-bulletiner som ligger till grund för produkt–CVE-matchningarna. Primärkällor märks särskilt; CISA-bulletiner från registret har maskinläsbar CSAF."
      />
      <div className="card mb-4 flex flex-wrap items-end gap-3 p-3">
        <div className="grow">
          <label htmlFor="aq" className="block text-xs font-medium text-muted">
            Sök bulletin-ID, titel eller CVE
          </label>
          <input
            id="aq"
            type="search"
            className="input mt-1"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <div>
          <label htmlFor="aissuer" className="block text-xs font-medium text-muted">
            Utgivare
          </label>
          <select
            id="aissuer"
            className="input mt-1"
            value={issuer}
            onChange={(e) => setIssuer(e.target.value)}
          >
            <option value="all">Alla</option>
            {issuers.map((i) => (
              <option key={i} value={i}>
                {i}
              </option>
            ))}
          </select>
        </div>
        <span className="text-sm text-muted" role="status">
          {rows.length} av {d.advisories.length} bulletiner
        </span>
      </div>
      {rows.length === 0 ? <EmptyState>Inga bulletiner matchar.</EmptyState> : null}
      <div className="overflow-x-auto">
        <table className="table card">
          <thead>
            <tr>
              <th scope="col">ID</th>
              <th scope="col">Titel</th>
              <th scope="col">Utgivare</th>
              <th scope="col">Publicerad</th>
              <th scope="col">Status</th>
              <th scope="col">CVE</th>
              <th scope="col">CSAF</th>
              <th scope="col">Verifiering</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.id}>
                <td>
                  <Link to={`/bulletiner/${a.id}`} className="font-mono text-sm">
                    {a.advisory_id}
                  </Link>
                </td>
                <td className="text-sm">{a.title}</td>
                <td className="text-xs">
                  {a.issuer}
                  <div>
                    <Badge>{sourceTypeLabel[a.source_type] ?? a.source_type}</Badge>
                  </div>
                </td>
                <td className="text-xs">
                  {fmtDate(a.published_at)}
                  {a.updated_at && a.updated_at !== a.published_at ? (
                    <div className="text-muted">uppd. {fmtDate(a.updated_at)}</div>
                  ) : null}
                </td>
                <td className="text-xs">{a.status}</td>
                <td className="text-xs tabular-nums">{a.cve_ids.length}</td>
                <td className="text-xs">
                  {a.csaf_url ? (
                    <SafeLink href={a.csaf_url}>CSAF-JSON</SafeLink>
                  ) : (
                    <span className="text-muted">–</span>
                  )}
                </td>
                <td>
                  <VerificationBadge status={a.verification_status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

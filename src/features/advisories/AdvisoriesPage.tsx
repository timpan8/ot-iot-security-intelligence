import { Link } from 'react-router';
import { useDataset } from '@/data/DatasetContext';
import { Badge, VerificationBadge } from '@/components/Badge';
import { PageHeader } from '@/components/ui';
import { fmtDate } from '@/lib/format';
import { sourceTypeLabel } from '@/lib/labels';

export function AdvisoriesPage() {
  const d = useDataset();
  const rows = d.advisories
    .slice()
    .sort((a, b) => (b.published_at ?? '').localeCompare(a.published_at ?? ''));
  return (
    <>
      <PageHeader
        title="Bulletiner (advisories)"
        lead="Leverantörs- och CERT-bulletiner som ligger till grund för produkt–CVE-matchningarna. Primärkällor märks särskilt."
      />
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
                <td className="text-xs">{a.cve_ids.length}</td>
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

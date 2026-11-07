import { Link, useParams } from 'react-router';
import { useDataset } from '@/data/DatasetContext';
import { Badge, VerificationBadge, MatchStatusBadge } from '@/components/Badge';
import { SafeLink } from '@/components/SafeLink';
import { Callout, DefList, EmptyState, PageHeader, Section, Value } from '@/components/ui';
import { fmtDate } from '@/lib/format';
import { matchStatusLabel, sourceTypeLabel } from '@/lib/labels';
import { ReviewHistory, SourcesList } from '@/features/detail/shared';

export function AdvisoryPage() {
  const { id } = useParams();
  const d = useDataset();
  const a = id ? d.advisoryById.get(id) : undefined;
  if (!a)
    return (
      <Callout tone="warn" title="Bulletinen hittades inte">
        <Link to="/bulletiner">Till listan</Link>
      </Callout>
    );
  const matches = d.matchesByAdvisory.get(a.id) ?? [];
  const vendor = a.vendor_id ? d.vendorById.get(a.vendor_id) : undefined;
  return (
    <>
      <nav aria-label="Brödsmulor" className="mb-3 text-sm text-muted">
        <Link to="/bulletiner">Bulletiner</Link> / {a.advisory_id}
      </nav>
      <PageHeader
        title={`${a.advisory_id} – ${a.title}`}
        lead={
          <div className="flex flex-wrap gap-2">
            <VerificationBadge status={a.verification_status} />
            <Badge>{sourceTypeLabel[a.source_type] ?? a.source_type}</Badge>
            <Badge>Status: {a.status}</Badge>
          </div>
        }
      />
      <div className="space-y-4">
        <Section title="Uppgifter" id="uppgifter">
          <DefList
            items={[
              ['Utgivare', a.issuer],
              [
                'Leverantör',
                vendor ? (
                  vendor.name
                ) : (
                  <Value key="v" value={null} fallback="Ej leverantörsbunden" />
                ),
              ],
              ['Publicerad', fmtDate(a.published_at)],
              ['Uppdaterad', fmtDate(a.updated_at)],
              ['URL', <SafeLink key="u" href={a.url} />],
              [
                'CSAF (maskinläsbar)',
                a.csaf_url ? (
                  <SafeLink key="c" href={a.csaf_url} />
                ) : (
                  <Value value={null} fallback="Ej tillgänglig/okänd" />
                ),
              ],
              ['Sammanfattning', <Value key="s" value={a.summary} />],
            ]}
          />
        </Section>
        <Section
          title={`CVE:er i bulletinen (${a.cve_ids.length})`}
          id="cve"
          description="CVE:er som saknas i kunskapsbasen har inte verifierats individuellt och visas därför utan länk."
        >
          <ul className="flex flex-wrap gap-2 text-sm">
            {a.cve_ids.map((c) => {
              const v = d.vulnerabilityByCve.get(c);
              return (
                <li key={c}>
                  {v ? (
                    <Link to={`/sarbarheter/${c}`} className="font-mono">
                      {c}
                    </Link>
                  ) : (
                    <span
                      className="font-mono text-muted"
                      title="Ej individuellt verifierad i kunskapsbasen"
                    >
                      {c}
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
        </Section>
        <Section title="Produktmatchningar som bygger på bulletinen" id="matchningar">
          {matches.length === 0 ? (
            <EmptyState>Inga matchningar.</EmptyState>
          ) : (
            <ul className="space-y-1 text-sm">
              {matches.map((m) => {
                const p = d.productById.get(m.product_family_id);
                return (
                  <li key={m.id} className="flex flex-wrap items-center gap-2">
                    {p ? <Link to={`/produkt/${p.id}`}>{p.name}</Link> : m.product_family_id}
                    <span className="text-muted">
                      {m.component ? `· ${m.component}` : ''} · {m.affected_versions_text}
                    </span>
                    <MatchStatusBadge
                      status={m.status}
                      label={matchStatusLabel[m.status] ?? m.status}
                    />
                  </li>
                );
              })}
            </ul>
          )}
        </Section>
        <Section title="Historik" id="historik">
          {a.history.length === 0 ? (
            <EmptyState>Ingen revisionshistorik registrerad.</EmptyState>
          ) : (
            <ul className="space-y-1 text-sm">
              {a.history.map((h, i) => (
                <li key={i}>
                  <span className="font-mono text-xs text-muted">{h.date}</span> {h.summary}
                </li>
              ))}
            </ul>
          )}
          <div className="mt-3">
            <ReviewHistory review={a.review} />
          </div>
        </Section>
        <Section title="Källor" id="kallor">
          <SourcesList d={d} sourceIds={a.source_ids} />
        </Section>
      </div>
    </>
  );
}

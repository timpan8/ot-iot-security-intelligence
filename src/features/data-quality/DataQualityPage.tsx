import { Link } from 'react-router';
import { useDataset } from '@/data/DatasetContext';
import { isProduct } from '@/data/loader';
import { Badge, VerificationBadge } from '@/components/Badge';
import { SafeLink } from '@/components/SafeLink';
import { EmptyState, PageHeader, Section } from '@/components/ui';
import { availabilityLabel, flagLabel } from '@/lib/labels';
import { fmtDate } from '@/lib/format';
import { DataQualityFlag } from '@schemas/index';

export function DataQualityPage() {
  const d = useDataset();
  const flagged = DataQualityFlag.options
    .map((f) => [f, d.entries.filter((e) => e.data_quality_flags.includes(f))] as const)
    .filter(([, list]) => list.length > 0)
    .sort((a, b) => b[1].length - a[1].length);
  const badSources = d.sources.filter((s) => s.availability !== 'ok');
  const secondarySources = d.sources.filter(
    (s) => !s.is_primary && s.source_type !== 'internal_workbook',
  );
  const claims = d.claims.filter((c) => c.status === 'disputed' || c.status === 'needs_review');
  const unknownClaims = d.claims.filter((c) => c.status === 'unknown');
  const unverifiedMatches = d.matches.filter((m) => m.verification_status !== 'verified_primary');
  const staleMatches = d.matches.filter(
    (m) => m.fix.status === 'needs_review' || m.fix.status === 'unknown',
  );

  return (
    <>
      <PageHeader
        title="Käll- och datakvalitet"
        lead="Varje betydelsefullt påstående ska kunna spåras till en källa. Här listas det som saknar primärkälla, är okänt, kan vara inaktuellt eller behöver mänsklig granskning."
      />
      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Poster per datakvalitetsflagga" id="flaggor">
          {flagged.length === 0 ? (
            <EmptyState>Inga flaggor.</EmptyState>
          ) : (
            <ul className="space-y-3">
              {flagged.map(([f, list]) => (
                <li key={f}>
                  <details>
                    <summary className="cursor-pointer text-sm">
                      <Badge tone="warn">{flagLabel[f]}</Badge>{' '}
                      <span className="tabular-nums text-muted">{list.length}</span>
                    </summary>
                    <ul className="mt-1 flex flex-wrap gap-x-3 gap-y-1 pl-2 text-sm">
                      {list.map((e) => (
                        <li key={e.id}>
                          <Link to={isProduct(e) ? `/produkt/${e.id}` : `/protokoll/${e.id}`}>
                            {e.name}
                          </Link>
                        </li>
                      ))}
                    </ul>
                  </details>
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title="Påståenden som behöver granskning eller är motstridiga" id="claims">
          {claims.length === 0 ? (
            <EmptyState>Inga.</EmptyState>
          ) : (
            <ul className="space-y-2 text-sm">
              {claims.map((c) => {
                const e = d.entryById.get(c.entity_id);
                return (
                  <li key={c.id} className="rounded-lg border border-border p-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <VerificationBadge status={c.status} />
                      <span className="text-xs text-muted">{c.field}</span>
                      {e ? (
                        <Link
                          to={isProduct(e) ? `/produkt/${e.id}` : `/protokoll/${e.id}`}
                          className="text-xs"
                        >
                          {e.name}
                        </Link>
                      ) : (
                        <span className="text-xs text-muted">{c.entity_id}</span>
                      )}
                    </div>
                    <p className="mt-1">{c.text}</p>
                    {c.conflict_note ? (
                      <p className="mt-1 text-xs text-danger">Konflikt: {c.conflict_note}</p>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          )}
          <p className="mt-3 text-xs text-muted">
            {unknownClaims.length} påståenden har status okänd (uppgift saknas).
          </p>
        </Section>

        <Section title="Källor som inte är tillgängliga eller inte kontrollerats" id="kallor">
          {badSources.length === 0 ? (
            <EmptyState>Alla källor är kontrollerade och tillgängliga.</EmptyState>
          ) : (
            <ul className="space-y-1 text-sm">
              {badSources.map((s) => (
                <li key={s.id} className="flex flex-wrap items-center gap-2">
                  <Badge tone={s.availability === 'broken' ? 'danger' : 'neutral'}>
                    {availabilityLabel[s.availability]}
                  </Badge>
                  <SafeLink href={s.url}>{s.title}</SafeLink>
                  <span className="text-xs text-muted">
                    kontrollerad {fmtDate(s.last_checked_at)}
                    {s.http_status ? ` · HTTP ${s.http_status}` : ''}
                    {s.access_note ? ` · ${s.access_note}` : ''}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section
          title="Sekundära källor (märkta)"
          id="sekundara"
          description="Sekundär forskning redovisas öppet och ersätter inte primärkällor."
        >
          {secondarySources.length === 0 ? (
            <EmptyState>Inga sekundära källor.</EmptyState>
          ) : (
            <ul className="space-y-1 text-sm">
              {secondarySources.map((s) => (
                <li key={s.id}>
                  <SafeLink href={s.url}>{s.title}</SafeLink>{' '}
                  <span className="text-xs text-muted">({s.publisher})</span>
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title="Matchningar som inte är verifierade mot primärkälla" id="matchningar">
          {unverifiedMatches.length === 0 ? (
            <EmptyState>Alla matchningar är primärverifierade.</EmptyState>
          ) : (
            <ul className="space-y-1 text-sm">
              {unverifiedMatches.map((m) => {
                const p = d.productById.get(m.product_family_id);
                const v = m.vulnerability_id
                  ? d.vulnerabilityById.get(m.vulnerability_id)
                  : undefined;
                return (
                  <li key={m.id} className="flex flex-wrap items-center gap-2">
                    <VerificationBadge status={m.verification_status} />
                    {p ? <Link to={`/produkt/${p.id}`}>{p.name}</Link> : null}
                    <span className="text-xs text-muted">
                      {v?.cve_id ?? m.advisory_id} · {m.affected_versions_text}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </Section>

        <Section title="Fixuppgifter som inte är bekräftade (möjligt inaktuella)" id="fix">
          {staleMatches.length === 0 ? (
            <EmptyState>Inga.</EmptyState>
          ) : (
            <ul className="space-y-1 text-sm">
              {staleMatches.map((m) => {
                const p = d.productById.get(m.product_family_id);
                return (
                  <li key={m.id} className="flex flex-wrap items-center gap-2">
                    <VerificationBadge status={m.fix.status} />
                    {p ? <Link to={`/produkt/${p.id}`}>{p.name}</Link> : null}
                    <span className="text-xs text-muted">
                      {m.fix.text ?? m.fix.version ?? 'ingen fixuppgift'}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </Section>
      </div>
    </>
  );
}

import { Link } from 'react-router';
import type { z } from 'zod';
import type {
  Claim,
  Control,
  ProductVulnerabilityMatch,
  Provenance,
  RiskAssessment,
  Source,
} from '@schemas/index';
import type { DocumentationLink as DocLinkSchema, Review as ReviewSchema } from '@schemas/index';
import type { IndexedDataset, CatalogEntry } from '@/data/loader';
import { Badge, FactorBadge, MatchStatusBadge, VerificationBadge } from '@/components/Badge';
import { SafeLink } from '@/components/SafeLink';
import { Callout, DefList, EmptyState, Section, Unknown, Value } from '@/components/ui';
import {
  actionDescription,
  actionLabel,
  availabilityLabel,
  docLevelLabel,
  factorName,
  fixLabel,
  matchStatusLabel,
  sourceTypeLabel,
} from '@/lib/labels';
import { fmtDate } from '@/lib/format';

type DocLink = z.infer<typeof DocLinkSchema>;
type Review = z.infer<typeof ReviewSchema>;

export function RiskPanel({ risk }: { risk: RiskAssessment }) {
  const factors: Array<[string, { level: string; basis: string }]> = [
    ['threat', risk.threat],
    ['severity', risk.severity],
    ['relevance', risk.relevance],
    ['exposure', risk.exposure],
    ['ot_impact', risk.ot_impact],
    ['mitigation_feasibility', risk.mitigation_feasibility],
    ['data_quality', risk.data_quality],
  ];
  return (
    <Section
      title="Riskfaktorer och rekommenderad åtgärd"
      id="risk"
      description="SSVC-inspirerade beslutsfaktorer, redovisade var för sig. Ingen sammanvägd risksiffra. Exponering är alltid okänd i den publika katalogen."
    >
      <div className="rounded-lg border border-border bg-surface-2 p-3">
        <p className="text-sm text-muted">Rekommenderad åtgärd</p>
        <p className="text-lg font-semibold">{actionLabel[risk.recommended_action]}</p>
        <p className="text-sm text-muted">{actionDescription[risk.recommended_action]}</p>
        <p className="mt-2 text-sm">{risk.rationale}</p>
      </div>
      <ul className="mt-3 divide-y divide-border">
        {factors.map(([key, f]) => (
          <li key={key} className="flex flex-col gap-1 py-2 sm:flex-row sm:items-start sm:gap-4">
            <div className="sm:w-64 shrink-0 text-sm font-medium">{factorName[key]}</div>
            <div className="shrink-0">
              <FactorBadge level={f.level as 'high' | 'medium' | 'low' | 'unknown'} />
            </div>
            <p className="text-sm text-muted">{f.basis}</p>
          </li>
        ))}
      </ul>
      <p className="mt-2 text-xs text-muted">
        Metodversion: {risk.method_version}. Se Om / metodik.
      </p>
    </Section>
  );
}

export function MatchesTable({
  d,
  matches,
}: {
  d: IndexedDataset;
  matches: ProductVulnerabilityMatch[];
}) {
  if (matches.length === 0) {
    return (
      <EmptyState>
        Ingen verifierad CVE-/bulletinmatchning finns i katalogen för denna post. Det betyder inte
        att produkten saknar sårbarheter – kontrollera tillverkarens bulletiner för exakt modell och
        version.
      </EmptyState>
    );
  }
  return (
    <div className="overflow-x-auto">
      <table className="table">
        <thead>
          <tr>
            <th scope="col">CVE / bulletin</th>
            <th scope="col">Komponent</th>
            <th scope="col">Berörda versioner</th>
            <th scope="col">Status</th>
            <th scope="col">Förutsättningar</th>
            <th scope="col">Fix</th>
            <th scope="col">Verifiering</th>
          </tr>
        </thead>
        <tbody>
          {matches.map((m) => {
            const v = m.vulnerability_id ? d.vulnerabilityById.get(m.vulnerability_id) : undefined;
            const a = m.advisory_id ? d.advisoryById.get(m.advisory_id) : undefined;
            return (
              <tr key={m.id}>
                <td className="text-sm">
                  {v ? (
                    <Link to={`/sarbarheter/${v.cve_id}`}>{v.cve_id}</Link>
                  ) : (
                    <span className="text-muted">Ingen CVE</span>
                  )}
                  {v?.kev.listed ? (
                    <>
                      {' '}
                      <Badge tone="danger">KEV</Badge>
                    </>
                  ) : null}
                  {a ? (
                    <div className="text-xs">
                      <Link to={`/bulletiner/${a.id}`}>{a.advisory_id}</Link>
                    </div>
                  ) : null}
                </td>
                <td className="text-sm">
                  <Value value={m.component} fallback="Hela produktfamiljen" />
                </td>
                <td className="text-sm">{m.affected_versions_text}</td>
                <td>
                  <MatchStatusBadge
                    status={m.status}
                    label={matchStatusLabel[m.status] ?? m.status}
                  />
                </td>
                <td className="text-xs">
                  <div>Vektor: {m.attack_vector}</div>
                  <div>Autentisering: {m.authentication_required}</div>
                  <div>Användarinteraktion: {m.user_interaction}</div>
                  {m.attack_prerequisites ? (
                    <div className="mt-1 text-muted">{m.attack_prerequisites}</div>
                  ) : null}
                </td>
                <td className="text-xs">
                  <div>
                    {fixLabel[m.fix.available] ?? m.fix.available}
                    {m.fix.version ? ` (${m.fix.version})` : ''}
                  </div>
                  {m.fix.text ? <div className="text-muted">{m.fix.text}</div> : null}
                  <div className="mt-1">
                    <VerificationBadge status={m.fix.status} />
                  </div>
                </td>
                <td>
                  <VerificationBadge status={m.verification_status} />
                  <div className="mt-1 max-w-xs text-xs text-muted">{m.evidence}</div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function ControlsList({ d, controlIds }: { d: IndexedDataset; controlIds: string[] }) {
  const controls = controlIds
    .map((id) => d.controlById.get(id))
    .filter((c): c is Control => Boolean(c))
    .sort((a, b) => a.order_hint - b.order_hint);
  if (controls.length === 0) return <EmptyState>Inga specifika kontroller kopplade.</EmptyState>;
  return (
    <ol className="space-y-3">
      {controls.map((c, i) => (
        <li key={c.id} className="rounded-lg border border-border p-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-semibold">
              {i + 1}. {c.name}
            </span>
            <Badge tone={c.requires_operational_approval ? 'warn' : 'neutral'}>
              {c.requires_operational_approval
                ? 'Kräver driftgodkännande'
                : 'Kan ofta införas utan driftstopp'}
            </Badge>
            <Badge>OT-lämplighet: {c.ot_suitability}</Badge>
          </div>
          <p className="mt-1 text-sm">{c.description}</p>
          <dl className="mt-2 grid gap-1 text-xs text-muted sm:grid-cols-2">
            <div>
              <dt className="inline font-medium">Skyddsmål: </dt>
              <dd className="inline">{c.goal}</dd>
            </div>
            <div>
              <dt className="inline font-medium">Effekt: </dt>
              <dd className="inline">{c.effect}</dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="inline font-medium">Begränsningar: </dt>
              <dd className="inline">{c.limitations}</dd>
            </div>
            {c.depends_on_control_ids.length ? (
              <div className="sm:col-span-2">
                <dt className="inline font-medium">Beror på: </dt>
                <dd className="inline">
                  {c.depends_on_control_ids
                    .map((id) => d.controlById.get(id)?.name ?? id)
                    .join(', ')}
                </dd>
              </div>
            ) : null}
          </dl>
          {c.vendor_guide_url ? (
            <p className="mt-1 text-xs">
              <SafeLink href={c.vendor_guide_url}>Tillverkarens vägledning</SafeLink>
            </p>
          ) : null}
          {c.framework_refs.length ? (
            <p className="mt-1 text-xs text-muted">
              Ramverksreferens (ej efterlevnadspåstående):{' '}
              {c.framework_refs.map((r) => `${r.framework} ${r.reference}`).join('; ')}
            </p>
          ) : null}
        </li>
      ))}
    </ol>
  );
}

export function DocumentationList({ d, docs }: { d: IndexedDataset; docs: DocLink[] }) {
  if (docs.length === 0) return <EmptyState>Ingen dokumentationslänk.</EmptyState>;
  return (
    <ul className="space-y-2 text-sm">
      {docs.map((doc) => {
        const src = d.sourceById.get(doc.source_id);
        return (
          <li key={doc.url} className="rounded-lg border border-border p-2">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={doc.product_specific ? 'ok' : 'warn'}>
                {doc.product_specific ? 'Produktspecifik' : 'Ej produktspecifik'}
              </Badge>
              <Badge>{docLevelLabel[doc.level] ?? doc.level}</Badge>
              {src ? (
                <Badge tone={src.availability === 'ok' ? 'ok' : 'neutral'}>
                  {availabilityLabel[src.availability]}
                </Badge>
              ) : null}
            </div>
            <p className="mt-1 text-xs text-muted">{doc.level_text}</p>
            <SafeLink href={doc.url}>{src?.title ?? doc.url}</SafeLink>
          </li>
        );
      })}
    </ul>
  );
}

export function SourcesList({ d, sourceIds }: { d: IndexedDataset; sourceIds: string[] }) {
  const sources = sourceIds
    .map((id) => d.sourceById.get(id))
    .filter((s): s is Source => Boolean(s));
  if (sources.length === 0) return <EmptyState>Inga källor registrerade.</EmptyState>;
  return (
    <ul className="space-y-2 text-sm">
      {sources.map((s) => (
        <li key={s.id} className="rounded-lg border border-border p-2">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={s.is_primary ? 'ok' : 'warn'}>
              {s.is_primary ? 'Primärkälla' : 'Sekundärkälla'}
            </Badge>
            <Badge>{sourceTypeLabel[s.source_type] ?? s.source_type}</Badge>
            <Badge
              tone={
                s.availability === 'ok' ? 'ok' : s.availability === 'broken' ? 'danger' : 'neutral'
              }
            >
              {availabilityLabel[s.availability]}
            </Badge>
          </div>
          <p className="mt-1 font-medium">{s.title}</p>
          <p className="text-xs text-muted">
            {s.publisher} · publicerad {fmtDate(s.published_at)} · kontrollerad{' '}
            {fmtDate(s.last_checked_at)} · verifierad {fmtDate(s.last_verified_at)}
          </p>
          <SafeLink href={s.url} className="text-xs underline break-all">
            {s.url}
          </SafeLink>
          {s.access_note ? <p className="text-xs text-muted">{s.access_note}</p> : null}
          {s.supports_claims.length ? (
            <p className="mt-1 text-xs text-muted">
              Stödjer:{' '}
              {s.supports_claims.map((c) => `${c.field}${c.note ? ` (${c.note})` : ''}`).join('; ')}
            </p>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

export function ProvenanceList({
  prov,
  original,
}: {
  prov: Provenance[];
  original: CatalogEntry['original'];
}) {
  return (
    <details className="text-sm">
      <summary className="cursor-pointer">
        Spårbarhet: Excel-blad ”{original.sheet}”, rad {original.row} ({prov.length} fält)
      </summary>
      <ul className="mt-2 space-y-1">
        {prov.map((p) => (
          <li key={`${p.column}-${p.row}`} className="grid grid-cols-[6rem_1fr] gap-2 text-xs">
            <span className="font-mono text-muted">
              {p.column}
              {p.row}
            </span>
            <span>
              <span className="font-medium">{p.header}:</span>{' '}
              <Value value={original.values[p.header] ?? null} fallback="(tom)" />
            </span>
          </li>
        ))}
      </ul>
    </details>
  );
}

export function ReviewHistory({ review }: { review: Review }) {
  return (
    <DefList
      items={[
        ['Senast granskad', fmtDate(review.reviewed_at)],
        ['Granskare (roll)', <Value key="r" value={review.reviewer} fallback="Ej angiven" />],
        [
          'Noteringar',
          review.notes.length ? (
            <ul className="list-disc pl-4">
              {review.notes.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          ) : (
            <Unknown>Inga</Unknown>
          ),
        ],
        [
          'Historik',
          review.history.length ? (
            <ul className="space-y-1">
              {review.history.map((h, i) => (
                <li key={i} className="text-sm">
                  <span className="font-mono text-xs text-muted">{h.date}</span> {h.summary}{' '}
                  {h.status ? <VerificationBadge status={h.status} /> : null}
                </li>
              ))}
            </ul>
          ) : (
            <Unknown>Ingen historik</Unknown>
          ),
        ],
      ]}
    />
  );
}

export function ClaimsList({ claims }: { claims: Claim[] }) {
  if (claims.length === 0) return <EmptyState>Inga separat registrerade påståenden.</EmptyState>;
  return (
    <ul className="space-y-2 text-sm">
      {claims.map((c) => (
        <li key={c.id} className="rounded-lg border border-border p-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-medium text-muted">{c.field}</span>
            <VerificationBadge status={c.status} />
            {c.reviewed_at ? (
              <span className="text-xs text-muted">granskad {c.reviewed_at}</span>
            ) : null}
          </div>
          <p className="mt-1">{c.text}</p>
          {c.conflict_note ? (
            <p className="mt-1 text-xs text-danger">Konflikt: {c.conflict_note}</p>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

export function UnverifiedWarning({ d, entry }: { d: IndexedDataset; entry: CatalogEntry }) {
  const matches = entry.kind === 'product_family' ? (d.matchesByProduct.get(entry.id) ?? []) : [];
  const unverifiedVersions = matches.some(
    (m) =>
      m.verification_status === 'needs_review' ||
      m.verification_status === 'unknown' ||
      m.version_rule.type === 'unknown',
  );
  const unverifiedFix = matches.some(
    (m) => m.fix.status === 'needs_review' || m.fix.status === 'unknown',
  );
  const noVersion = entry.data_quality_flags.includes('unknown_version_boundary');
  if (!unverifiedVersions && !unverifiedFix && !noVersion) return null;
  return (
    <Callout tone="warn" title="Modeller, versioner eller fix är inte fullt verifierade">
      <ul className="list-disc pl-5">
        {noVersion ? (
          <li>
            Versionsgräns saknas eller är okänd – bedöm aldrig en installation utan att fastställa
            exakt modell och firmware.
          </li>
        ) : null}
        {unverifiedVersions ? (
          <li>Minst en matchning har status ”behöver granskning” eller okänd versionsregel.</li>
        ) : null}
        {unverifiedFix ? <li>Minst en fixversion är inte bekräftad av primärkälla.</li> : null}
      </ul>
    </Callout>
  );
}

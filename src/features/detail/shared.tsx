import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import type { z } from 'zod';
import type {
  Claim,
  Control,
  ProductVulnerabilityMatch,
  Provenance,
  RiskAssessment,
  Source,
  Vulnerability,
} from '@schemas/index';
import type { DocumentationLink as DocLinkSchema, Review as ReviewSchema } from '@schemas/index';
import type { IndexedDataset, CatalogEntry } from '@/data/loader';
import {
  Badge,
  FactorBadge,
  MatchStatusBadge,
  OriginBadge,
  PocBadge,
  PwdTypeBadge,
  VerificationBadge,
} from '@/components/Badge';
import { SafeLink } from '@/components/SafeLink';
import { Callout, DefList, EmptyState, Section, Unknown, Value } from '@/components/ui';
import {
  actionDescription,
  actionLabel,
  availabilityLabel,
  docLevelLabel,
  factorName,
  fixLabel,
  materialTypeLabel,
  matchStatusLabel,
  NO_PASSWORD_VALUES_NOTE,
  originLabel,
  pwdTypeDescription,
  pwdTypeLabel,
  setupDocTypeLabel,
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

const PAGE = 15;

function bestScore(v: Vulnerability | undefined): number {
  if (!v) return -1;
  const scores = v.cvss.map((c) => c.base_score);
  if (v.register_cvss?.base_score !== null && v.register_cvss?.base_score !== undefined)
    scores.push(v.register_cvss.base_score);
  return scores.length ? Math.max(...scores) : -1;
}

/**
 * Produkt–CVE-matchningar. Sorterade efter högsta CVSS (fallande), 15 åt gången.
 * Varje rad kan expanderas för exakt källtext (affected/fixed), produktkopplingens
 * begränsning, CSAF-verifieringsnot och hotunderlagets PoC-status/materialtyp per CVE.
 */
export function MatchesTable({
  d,
  matches,
}: {
  d: IndexedDataset;
  matches: ProductVulnerabilityMatch[];
}) {
  const [limit, setLimit] = useState(PAGE);
  const [open, setOpen] = useState<Set<string>>(() => new Set());
  const sorted = useMemo(
    () =>
      matches
        .map((m) => ({
          m,
          v: m.vulnerability_id ? d.vulnerabilityById.get(m.vulnerability_id) : undefined,
        }))
        .sort((a, b) => {
          const sa = a.m.status === 'not_affected' ? -2 : bestScore(a.v);
          const sb = b.m.status === 'not_affected' ? -2 : bestScore(b.v);
          return sb - sa || (a.v?.cve_id ?? '').localeCompare(b.v?.cve_id ?? '');
        }),
    [matches, d],
  );
  if (matches.length === 0) {
    return (
      <EmptyState>
        Ingen verifierad CVE-/bulletinmatchning finns i katalogen för denna post. Det betyder inte
        att produkten saknar sårbarheter – kontrollera tillverkarens bulletiner för exakt modell och
        version.
      </EmptyState>
    );
  }
  const shown = sorted.slice(0, limit);
  const toggle = (id: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const regCount = matches.filter((m) => m.register_relation).length;
  return (
    <div>
      <p className="mb-2 text-xs text-muted">
        {matches.length} matchning{matches.length === 1 ? '' : 'ar'}
        {regCount ? ` · ${regCount} från 125-postregistret (Sårbarheter-bladet)` : ''} · sorterade
        efter högsta CVSS. Klicka ”Detaljer” för exakt källtext och hotunderlag.
      </p>
      <div className="overflow-x-auto">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">CVE / bulletin</th>
              <th scope="col">CVSS</th>
              <th scope="col">Komponent / berörda versioner</th>
              <th scope="col">Status</th>
              <th scope="col">PoC / hotunderlag</th>
              <th scope="col">Fix</th>
              <th scope="col">Verifiering</th>
              <th scope="col">
                <span className="sr-only">Detaljer</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {shown.map(({ m, v }) => {
              const a = m.advisory_id ? d.advisoryById.get(m.advisory_id) : undefined;
              const ti = v?.threat_intel ?? null;
              const score = bestScore(v);
              const isOpen = open.has(m.id);
              return (
                <RowGroup key={m.id}>
                  <tr>
                    <td className="text-sm">
                      {v ? (
                        <Link to={`/sarbarheter/${v.cve_id}`} className="font-mono">
                          {v.cve_id}
                        </Link>
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
                      {m.cwe_text ? <div className="text-xs text-muted">{m.cwe_text}</div> : null}
                    </td>
                    <td className="text-sm tabular-nums">
                      {score >= 0 ? score.toFixed(1).replace('.', ',') : <Unknown>Okänt</Unknown>}
                    </td>
                    <td className="text-sm">
                      {m.component ? <div className="font-medium">{m.component}</div> : null}
                      <div className={m.version_rule.type === 'source_text' ? 'text-xs' : ''}>
                        {m.version_rule.type === 'source_text' ? (
                          <span className="text-muted">Källtext: </span>
                        ) : null}
                        {truncate(m.affected_versions_text, 140)}
                      </div>
                    </td>
                    <td>
                      <MatchStatusBadge
                        status={m.status}
                        label={matchStatusLabel[m.status] ?? m.status}
                      />
                      {m.product_link_limitation_text ? (
                        <div className="mt-1 max-w-[12rem] text-xs text-muted">
                          {m.product_link_limitation_text}
                        </div>
                      ) : null}
                    </td>
                    <td className="text-xs">
                      {ti ? (
                        <div className="flex flex-col gap-1">
                          <PocBadge status={ti.public_poc_status} short />
                          <span className="text-muted">
                            {materialTypeLabel[ti.material_type_code]}
                          </span>
                          {ti.cisa_assessment_date ? (
                            <span className="text-muted">
                              SSVC {ti.cisa_ssvc_exploitation_raw ?? '–'} ·{' '}
                              {ti.cisa_assessment_date}
                            </span>
                          ) : null}
                        </div>
                      ) : (
                        <span className="text-muted">Inget hotunderlag</span>
                      )}
                    </td>
                    <td className="text-xs">
                      <div>
                        {fixLabel[m.fix.available] ?? m.fix.available}
                        {m.fix.version ? ` (${m.fix.version})` : ''}
                      </div>
                      <div className="mt-1">
                        <VerificationBadge status={m.fix.status} />
                      </div>
                    </td>
                    <td>
                      <VerificationBadge status={m.verification_status} />
                      {m.register_relation ? (
                        <div className="mt-1">
                          <Badge tone="info">Registerrelation</Badge>
                        </div>
                      ) : null}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn text-xs"
                        aria-expanded={isOpen}
                        aria-controls={`match-detail-${m.id}`}
                        onClick={() => toggle(m.id)}
                      >
                        {isOpen ? 'Dölj' : 'Detaljer'}
                      </button>
                    </td>
                  </tr>
                  {isOpen ? (
                    <tr id={`match-detail-${m.id}`}>
                      <td colSpan={8} className="bg-surface-2 text-sm">
                        <DefList
                          items={[
                            [
                              'Berörda versioner – exakt källtext',
                              <pre
                                key="a"
                                className="whitespace-pre-wrap break-words font-sans text-xs"
                              >
                                {m.affected_source_text ?? m.affected_versions_text}
                              </pre>,
                            ],
                            [
                              'Fix – exakt produktmatris / osäkerhet',
                              <Value
                                key="f"
                                value={m.fixed_source_text ?? m.fix.text}
                                fallback="Ingen fixuppgift i underlaget"
                              />,
                            ],
                            [
                              'Produktkoppling / begränsning',
                              <Value key="l" value={m.product_link_limitation_text} />,
                            ],
                            [
                              'Verifiering mot CSAF/primärkälla',
                              <Value key="n" value={m.register_verification_note ?? m.evidence} />,
                            ],
                            [
                              'Förutsättningar',
                              `Vektor ${m.attack_vector}, autentisering ${m.authentication_required}, användarinteraktion ${m.user_interaction}${m.attack_prerequisites ? ` – ${m.attack_prerequisites}` : ''}`,
                            ],
                            ...(ti
                              ? ([
                                  [
                                    'Hotunderlag (separata signaler)',
                                    <div key="ti" className="space-y-1 text-xs">
                                      <div>
                                        <PocBadge status={ti.public_poc_status} />{' '}
                                        {ti.cisa_assessment_date
                                          ? `enligt CISA SSVC vid bedömningsdatum ${ti.cisa_assessment_date}`
                                          : ''}
                                      </div>
                                      <div>
                                        Materialtyp: {materialTypeLabel[ti.material_type_code]}
                                      </div>
                                      <div>
                                        Aktiv exploatering:{' '}
                                        {ti.active_exploitation_status === 'kev_listed'
                                          ? 'Ja – CISA KEV'
                                          : 'Ej fastställt i detta underlag'}
                                      </div>
                                      {ti.source_critical_note ? (
                                        <div className="text-muted">
                                          Källkritik: {ti.source_critical_note}
                                        </div>
                                      ) : null}
                                      {ti.poc_url ? (
                                        <div>
                                          Länk (ej körd eller funktionstestad):{' '}
                                          <SafeLink href={ti.poc_url} />
                                        </div>
                                      ) : null}
                                    </div>,
                                  ],
                                ] as Array<[string, React.ReactNode]>)
                              : []),
                            [
                              'Källor',
                              <SourceLinks
                                key="s"
                                d={d}
                                ids={[...m.source_ids, ...m.fix.source_ids]}
                              />,
                            ],
                          ]}
                        />
                      </td>
                    </tr>
                  ) : null}
                </RowGroup>
              );
            })}
          </tbody>
        </table>
      </div>
      {sorted.length > limit ? (
        <button type="button" className="btn mt-3" onClick={() => setLimit((l) => l + PAGE * 2)}>
          Visa fler ({sorted.length - limit} till)
        </button>
      ) : null}
    </div>
  );
}

function RowGroup({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

function SourceLinks({ d, ids }: { d: IndexedDataset; ids: string[] }) {
  const srcs = [...new Set(ids)]
    .map((id) => d.sourceById.get(id))
    .filter((s): s is Source => Boolean(s));
  if (srcs.length === 0) return <Unknown>Inga källor</Unknown>;
  return (
    <ul className="space-y-0.5 text-xs">
      {srcs.map((s) => (
        <li key={s.id}>
          <Badge tone={s.is_primary ? 'ok' : 'warn'}>{s.is_primary ? 'Primär' : 'Sekundär'}</Badge>{' '}
          <SafeLink href={s.url}>{s.title}</SafeLink>
          {s.document_sha256 ? (
            <span className="ml-1 font-mono text-muted">
              sha256 {s.document_sha256.slice(0, 12)}…
            </span>
          ) : null}
        </li>
      ))}
    </ul>
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

/* ------------------------------------------------------------------ */
/* Registerimport (125-postregistret)                                  */
/* ------------------------------------------------------------------ */

export function RegisterSection({ d, entry }: { d: IndexedDataset; entry: CatalogEntry }) {
  const r = entry.register;
  if (!r) return null;
  const kControls = r.control_codes
    .map((code) => d.controls.filter((c) => c.register_code === code))
    .flat();
  const isP1 = /^P1/i.test(r.priority_text ?? '');
  return (
    <Section
      title="Registeruppgifter och granskning"
      id="register"
      description="Uppgifter från det utökade OT/IoT-registret (125 poster). Källstatus och osäkerhet redovisas verbatim; inget här är bevis på faktisk exponering eller kompromettering."
    >
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className="font-mono text-sm">{r.register_id}</span>
        <OriginBadge origin={r.origin} />
        <Badge tone={isP1 ? 'danger' : 'warn'} title="Prioritet vid KONSTATERAD exponering">
          {r.priority_text ?? 'Prioritet saknas'}
        </Badge>
      </div>
      <Callout tone="info" title="Prioriteten gäller vid konstaterad exponering">
        Observerad internetexponering:{' '}
        <strong>{r.observed_exposure_text ?? 'Uppgift saknas'}</strong>. Prioriteten är en förberedd
        signal för det fall en behörig inventering konstaterar exponering; den säger inget om att
        systemet faktiskt är exponerat eller sårbart.
      </Callout>
      <div className="mt-3">
        <DefList
          items={[
            ['Ursprung', originLabel[r.origin]],
            ['Originalrad / bulletin', <Value key="o" value={r.origin_reference} />],
            ['Omfattning / alias', <Value key="s" value={r.scope_alias_text} />],
            ['Källstatus', <Value key="st" value={r.source_status_text} />],
            ['Osäkerhet / kvarstående granskning', <Value key="u" value={r.uncertainty_text} />],
            [
              'Risk vid internetexponering (dokumenterad risktyp)',
              <Value key="e" value={r.exposure_risk_text} />,
            ],
            [
              'CVE – verifierat urval (registrets text)',
              <Value key="c" value={r.cve_selection_text} />,
            ],
            ['KEV – matchade CVE (registrets text)', <Value key="k" value={r.kev_text} />],
            ['Berörda versioner – vägledning', <Value key="v" value={r.versions_guidance_text} />],
            ['Åtgärd / fix – vägledning', <Value key="f" value={r.fix_guidance_text} />],
            [
              'Riskkontroller (K-koder)',
              <span key="kc">
                {r.control_codes.length ? (
                  <span className="flex flex-wrap gap-1">
                    {r.control_codes.map((code) => (
                      <Badge key={code}>{code}</Badge>
                    ))}
                  </span>
                ) : (
                  <Unknown />
                )}
                {r.controls_text ? (
                  <span className="block text-xs text-muted">{r.controls_text}</span>
                ) : null}
                {kControls.length ? (
                  <ul className="mt-1 list-disc pl-4 text-xs">
                    {kControls.map((c) => (
                      <li key={c.id}>
                        <Link to={`/atgarder#${c.id}`}>
                          {c.register_code}: {c.name}
                        </Link>
                        {c.verification_method ? (
                          <span className="text-muted">
                            {' '}
                            – verifiering: {c.verification_method}
                          </span>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                ) : null}
              </span>,
            ],
            ['Så verifieras inloggningsskydd', <Value key="vl" value={r.verify_login_text} />],
            ['Dokumentets begränsning', <Value key="dl" value={r.documentation_limitation_text} />],
            ['PoC / aktiv exploatering – urval', <Value key="t" value={r.threat_selection_text} />],
            ['Spårning av hotunderlag', <Value key="tt" value={r.threat_tracking_text} />],
            ['Begränsning', <Value key="l" value={r.limitation_text} />],
            [
              'Källdatum / kontrolldatum',
              `${r.source_date_text ?? '–'} / ${r.checked_at ?? '–'} (hotstatus ${r.threat_checked_at ?? '–'})`,
            ],
          ]}
        />
      </div>
      <h3 className="mt-4 text-sm font-semibold">Radgranskning</h3>
      {entry.review_findings.length === 0 ? (
        <EmptyState>Ingen radgranskning registrerad.</EmptyState>
      ) : (
        <ul className="mt-1 space-y-2">
          {entry.review_findings.map((f, i) => (
            <li key={i} className="rounded-lg border border-border p-3 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone={/öppen/i.test(f.status_text ?? '') ? 'warn' : 'neutral'}>
                  {f.status_text ?? 'Status saknas'}
                </Badge>
              </div>
              <p className="mt-1">
                <span className="font-medium">Fynd: </span>
                <Value value={f.finding} />
              </p>
              <p className="mt-1 text-muted">
                <span className="font-medium">Osäkerhet: </span>
                <Value value={f.uncertainty} />
              </p>
              <div className="mt-1">
                <SourceLinks d={d} ids={f.source_ids} />
              </div>
            </li>
          ))}
        </ul>
      )}
      <p className="mt-3 text-xs text-muted">
        Importproveniens: {r.import.file} · sha256 {r.import.file_sha256.slice(0, 12)}… · blad ”
        {r.import.sheet}”, rad {r.import.row} · {r.import.import_version}
      </p>
    </Section>
  );
}

export function CredentialsSection({ d, entry }: { d: IndexedDataset; entry: CatalogEntry }) {
  const c = entry.credentials;
  if (!c) return null;
  const danger =
    c.initial_password_type === 'hardcoded_in_affected_version' ||
    c.initial_password_type === 'predictable_builtin_mechanism';
  return (
    <Section
      title="Konton och initiallösenord"
      id="konton"
      description="Dokumenterade kontonamn och typ av initialt/fabrikslösenord. Ett dokumenterat kontonamn bevisar inte att ett standardlösenord finns, och ”okänt” betyder inte ”säkert”."
    >
      <Callout tone="info" title="Inga lösenordsvärden">
        {NO_PASSWORD_VALUES_NOTE}
      </Callout>
      {danger ? (
        <div className="mt-3">
          <Callout tone="danger" title="Lösenordsbyte räcker inte">
            {pwdTypeDescription[c.initial_password_type]}
          </Callout>
        </div>
      ) : null}
      <div className="mt-3">
        <DefList
          items={[
            [
              'Kontonamn (dokumenterat)',
              c.account_name ? (
                <code key="a">{c.account_name}</code>
              ) : (
                <Unknown key="a">{c.account_name_text ?? 'Ej verifierat'}</Unknown>
              ),
            ],
            ['Kontostatus', <Value key="s" value={c.account_status_text} />],
            [
              'Modell-/versionsgräns för kontouppgiften',
              <Value key="sc" value={c.account_scope_text} />,
            ],
            [
              'Typ av initiallösenord',
              <span key="t">
                <PwdTypeBadge type={c.initial_password_type} />
                <span className="block text-xs text-muted">
                  {pwdTypeDescription[c.initial_password_type]}
                </span>
                {c.initial_password_type_text &&
                c.initial_password_type_text !== pwdTypeLabel[c.initial_password_type] ? (
                  <span className="block text-xs text-muted">
                    Registrets text: {c.initial_password_type_text}
                  </span>
                ) : null}
              </span>,
            ],
            [
              'Byte / initial kontokonfiguration',
              <Value key="ch" value={c.change_requirement_text} />,
            ],
            [
              'Kontroll / åtgärd vid driftsättning',
              <Value key="co" value={c.commissioning_action_text} />,
            ],
            [
              'Verifieringsstatus',
              <span key="v">
                <VerificationBadge status={c.verification_status} />{' '}
                <span className="text-xs text-muted">kontrollerad {c.checked_at ?? '–'}</span>
              </span>,
            ],
            [
              'Källor',
              <SourceLinks
                key="src"
                d={d}
                ids={[c.account_source_id, c.password_status_source_id].filter((x): x is string =>
                  Boolean(x),
                )}
              />,
            ],
          ]}
        />
      </div>
    </Section>
  );
}

export function SetupSection({ d, entry }: { d: IndexedDataset; entry: CatalogEntry }) {
  const s = entry.setup_documentation;
  if (!s) {
    return (
      <Section title="Setup och installation" id="setup">
        <EmptyState>Ingen setup-/installationsinstruktion registrerad för posten.</EmptyState>
      </Section>
    );
  }
  const src = s.source_id ? d.sourceById.get(s.source_id) : undefined;
  return (
    <Section
      title="Setup och installation"
      id="setup"
      description="Officiell installations-/setupinstruktion enligt registret. Dokumentets identitet och omfattning är kontrollerade; proceduren är inte funktionstestad."
    >
      {!s.is_verified_setup_manual ? (
        <Callout tone="warn" title="Ingen verifierad installationsmanual">
          En dokumentportal, leverantörsingång eller säkerhetsguide är inte automatiskt en
          verifierad installationsmanual. Dokumenttyp: {setupDocTypeLabel[s.doc_type] ?? s.doc_type}
          .{s.verification_text ? ` ${s.verification_text}.` : ''}
        </Callout>
      ) : null}
      <div className="mt-3">
        <DefList
          items={[
            [
              'Manual / instruktion',
              s.url ? (
                <SafeLink key="u" href={s.url}>
                  {s.title ?? s.url}
                </SafeLink>
              ) : (
                <Unknown key="u">Ingen länk</Unknown>
              ),
            ],
            [
              'Dokumenttyp',
              <span key="t">
                <Badge tone={s.is_verified_setup_manual ? 'ok' : 'warn'}>
                  {setupDocTypeLabel[s.doc_type] ?? s.doc_type}
                </Badge>
                {s.doc_type_text && s.doc_type_text !== (setupDocTypeLabel[s.doc_type] ?? '') ? (
                  <span className="ml-1 text-xs text-muted">({s.doc_type_text})</span>
                ) : null}
              </span>,
            ],
            ['Omfattning / läsanvisning', <Value key="s" value={s.scope_text} />],
            ['Verifieringsstatus', <Value key="v" value={s.verification_text} />],
            [
              'Direkt hämtning (kontroll)',
              <span key="f">
                <Value value={s.fetch_status_text} />
                {src ? (
                  <>
                    {' '}
                    <Badge
                      tone={
                        src.availability === 'ok'
                          ? 'ok'
                          : src.availability === 'blocked'
                            ? 'warn'
                            : 'neutral'
                      }
                    >
                      {availabilityLabel[src.availability]}
                    </Badge>
                    {src.document_sha256 ? (
                      <span className="ml-1 font-mono text-xs text-muted">
                        sha256 {src.document_sha256.slice(0, 12)}…
                      </span>
                    ) : null}
                  </>
                ) : null}
              </span>,
            ],
            ['Kontrolldatum', s.checked_at ?? '–'],
          ]}
        />
      </div>
    </Section>
  );
}

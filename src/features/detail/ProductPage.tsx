import { Link, useParams } from 'react-router';
import { useDataset } from '@/data/DatasetContext';
import { Badge, OriginBadge, VerificationBadge } from '@/components/Badge';
import { Callout, DefList, PageHeader, Section, Unknown, Value } from '@/components/ui';
import { flagLabel, lifecycleLabel } from '@/lib/labels';
import {
  ClaimsList,
  ControlsList,
  CredentialsSection,
  DocumentationList,
  MatchesTable,
  ProvenanceList,
  RegisterSection,
  ReviewHistory,
  RiskPanel,
  SetupSection,
  SourcesList,
  UnverifiedWarning,
} from './shared';
import { SafeLink } from '@/components/SafeLink';

export function ProductPage() {
  const { id } = useParams();
  const d = useDataset();
  const p = id ? d.productById.get(id) : undefined;
  if (!p) {
    return (
      <Callout tone="warn" title="Produktfamiljen hittades inte">
        <Link to="/katalog">Till katalogen</Link>
      </Callout>
    );
  }
  const vendor = d.vendorById.get(p.vendor_id);
  const matches = d.matchesByProduct.get(p.id) ?? [];
  const advisories = p.advisory_ids
    .map((a) => d.advisoryById.get(a))
    .filter((a): a is NonNullable<typeof a> => Boolean(a));
  const observations = p.observation_ids
    .map((o) => d.observationById.get(o))
    .filter((o): o is NonNullable<typeof o> => Boolean(o));
  const claims = d.claimsByEntity.get(p.id) ?? [];
  const protocols = p.protocol_service_ids
    .map((s) => d.protocolById.get(s))
    .filter((s): s is NonNullable<typeof s> => Boolean(s));

  return (
    <>
      <nav aria-label="Brödsmulor" className="mb-3 text-sm text-muted">
        <Link to="/katalog">Katalog</Link> / {p.category} / {p.name}
      </nav>
      <PageHeader
        title={p.name}
        lead={
          <div className="flex flex-wrap items-center gap-2">
            <span>{vendor?.name ?? 'Okänd leverantör'}</span>
            <Badge>{p.category}</Badge>
            <Badge>Produktfamilj</Badge>
            {p.register ? (
              <>
                <OriginBadge origin={p.register.origin} />
                <span className="font-mono text-xs text-muted">{p.register.register_id}</span>
              </>
            ) : null}
            <VerificationBadge status={p.verification_status} />
            <Badge
              tone={
                p.lifecycle.status === 'eol'
                  ? 'danger'
                  : p.lifecycle.status === 'unknown'
                    ? 'neutral'
                    : 'info'
              }
            >
              Livscykel: {lifecycleLabel[p.lifecycle.status]}
            </Badge>
          </div>
        }
      />
      <div className="space-y-4">
        <UnverifiedWarning d={d} entry={p} />
        {p.data_quality_flags.length ? (
          <div className="flex flex-wrap gap-1">
            {p.data_quality_flags.map((f) => (
              <Link key={f} to={`/katalog?flags=${f}`} className="no-underline">
                <Badge tone="warn">{flagLabel[f]}</Badge>
              </Link>
            ))}
          </div>
        ) : null}

        <Section title="Teknisk funktion och OT-roll" id="funktion">
          <DefList
            items={[
              ['Funktion', p.function_text],
              ['Beskrivning', <Value key="d" value={p.description} />],
              ['OT-roll', <Value key="r" value={p.ot_role} />],
              [
                'Säkerhetskonsekvens vid kompromettering',
                <Value key="c" value={p.ot_consequence} />,
              ],
              ['Alias', p.aliases.length ? p.aliases.join(', ') : <Unknown>Inga</Unknown>],
              [
                'Hårdvarurevisioner / varianter',
                p.hardware_revisions.length ? p.hardware_revisions.join(', ') : <Unknown />,
              ],
              [
                'Livscykel',
                `${lifecycleLabel[p.lifecycle.status]}${p.lifecycle.note ? ` – ${p.lifecycle.note}` : ''}`,
              ],
              [
                'EOL/EOS-datum',
                <span key="e">
                  <Value value={p.lifecycle.eol_date.value} />{' '}
                  <VerificationBadge status={p.lifecycle.eol_date.status} />
                </span>,
              ],
              [
                'Typiska protokoll',
                protocols.length ? (
                  protocols.map((s) => (
                    <Link key={s.id} to={`/protokoll/${s.id}`} className="mr-2">
                      {s.name}
                    </Link>
                  ))
                ) : (
                  <Unknown>Ej angivet</Unknown>
                ),
              ],
              [
                'Leverantörens säkerhetsportal',
                vendor?.security_portal_url ? (
                  <SafeLink key="v" href={vendor.security_portal_url} />
                ) : (
                  <Unknown>Ej verifierad</Unknown>
                ),
              ],
            ]}
          />
        </Section>

        <RegisterSection d={d} entry={p} />
        <CredentialsSection d={d} entry={p} />
        <SetupSection d={d} entry={p} />

        <Section
          title="Typiska OT-risker (från inventeringen)"
          id="risker"
          description="Texterna är hämtade från arbetsboken och beskriver risktyper, inte exploateringssteg."
        >
          <DefList
            items={[
              ['Sårbarhetstyp / klass', <Value key="t" value={p.risk_summary.type_text} />],
              ['Vad risktypen innebär', <Value key="x" value={p.risk_summary.explanation_text} />],
              [
                'CVE / bulletin (ursprunglig text)',
                <Value
                  key="c"
                  value={p.risk_summary.cve_text}
                  fallback="Ingen uppgift i arbetsboken"
                />,
              ],
              [
                'Berörd firmware / modell (ursprunglig text)',
                <Value key="f" value={p.risk_summary.affected_firmware_text} />,
              ],
              [
                'Fix / senaste offentlig uppgift (ursprunglig text)',
                <Value key="g" value={p.risk_summary.fix_text} />,
              ],
              ['Patchningsgrad / urval', <Value key="p" value={p.risk_summary.patch_level_text} />],
              [
                'Inventeringsprio (villkorlig signal)',
                <Value key="o" value={p.risk_summary.legacy_priority_text} />,
              ],
            ]}
          />
          {p.unexpanded_cve_ranges.length ? (
            <div className="mt-3">
              <Callout
                tone={p.unexpanded_cve_ranges.every((r) => r.expanded) ? 'ok' : 'warn'}
                title="CVE-intervall i arbetsboken"
              >
                <ul className="list-disc pl-5">
                  {p.unexpanded_cve_ranges.map((r) => (
                    <li key={r.text}>
                      ”{r.text}” ({r.start} – {r.end}):{' '}
                      {r.expanded
                        ? `samtliga ${r.verified_ids.length} ID:n har verifierats individuellt.`
                        : 'inte expanderat – varje ID måste verifieras innan det blir en egen post.'}
                      {r.note ? ` ${r.note}` : ''}
                    </li>
                  ))}
                </ul>
              </Callout>
            </div>
          ) : null}
        </Section>

        <Section
          title="Explicit versions- och CVE-matchning"
          id="matchning"
          description="Varje rad är en separat, källbelagd koppling mellan komponent, version och sårbarhet. Status ”ej berörd” redovisas lika tydligt som ”berörd”."
        >
          <MatchesTable d={d} matches={matches} />
          {advisories.length ? (
            <p className="mt-3 text-sm">
              Bulletiner:{' '}
              {advisories.map((a) => (
                <Link key={a.id} to={`/bulletiner/${a.id}`} className="mr-2">
                  {a.advisory_id}
                </Link>
              ))}
            </p>
          ) : null}
        </Section>

        <RiskPanel risk={p.risk} />

        <Section title="Åtgärder i rekommenderad ordning" id="atgarder">
          <ControlsList d={d} controlIds={p.control_ids} />
          {p.secure_configuration_notes.length ? (
            <ul className="mt-3 list-disc pl-5 text-sm">
              {p.secure_configuration_notes.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          ) : null}
        </Section>

        {observations.length ? (
          <Section title="Observationer (aggregerade, icke-representativa)" id="observationer">
            {observations.map((o) => (
              <div key={o.id} className="rounded-lg border border-border p-3 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{o.title}</span>
                  <VerificationBadge status={o.verification_status} />
                  <Badge tone="warn">Ej representativ</Badge>
                </div>
                <p className="mt-1">{o.value_text}</p>
                <DefList
                  items={[
                    [
                      'Metod',
                      <span key="m">
                        <Value value={o.method.value} />{' '}
                        <VerificationBadge status={o.method.status} />
                      </span>,
                    ],
                    [
                      'Period',
                      <span key="p">
                        <Value value={o.period.value} />{' '}
                        <VerificationBadge status={o.period.status} />
                      </span>,
                    ],
                    ['Urval', o.sample_size === null ? <Unknown /> : `${o.sample_size}`],
                    ['Osäkerhet', o.uncertainty],
                    ['Förbehåll', o.caveat],
                  ]}
                />
              </div>
            ))}
          </Section>
        ) : null}

        <Section title="Dokumentation" id="dokumentation">
          <DocumentationList d={d} docs={p.documentation} />
        </Section>

        <Section title="Påståenden och verifiering" id="pastaenden">
          <ClaimsList claims={claims} />
        </Section>

        <Section title="Källor" id="kallor">
          <SourcesList d={d} sourceIds={p.source_ids} />
        </Section>

        <Section title="Granskning och historik" id="granskning">
          <ReviewHistory review={p.review} />
          <div className="mt-3">
            <ProvenanceList prov={p.provenance} original={p.original} />
          </div>
          <p className="mt-2 text-xs text-muted">
            Upptäcktsheuristik (endast för egen/auktoriserad inventering):{' '}
            <code className="text-xs">{p.discovery_heuristic.query ?? '–'}</code>.{' '}
            {p.discovery_heuristic.caveat}
          </p>
        </Section>
      </div>
    </>
  );
}

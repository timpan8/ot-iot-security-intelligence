import { Link, useParams } from 'react-router';
import { useDataset } from '@/data/DatasetContext';
import { Badge, OriginBadge, VerificationBadge } from '@/components/Badge';
import { Callout, DefList, PageHeader, Section, Unknown, Value } from '@/components/ui';
import { flagLabel, securityPropertyLabel } from '@/lib/labels';
import {
  ClaimsList,
  ControlsList,
  CredentialsSection,
  DocumentationList,
  ProvenanceList,
  RegisterSection,
  ReviewHistory,
  RiskPanel,
  SetupSection,
  SourcesList,
} from './shared';

export function ProtocolPage() {
  const { id } = useParams();
  const d = useDataset();
  const s = id ? d.protocolById.get(id) : undefined;
  if (!s) {
    return (
      <Callout tone="warn" title="Protokollet hittades inte">
        <Link to="/katalog">Till katalogen</Link>
      </Callout>
    );
  }
  const usedBy = d.product_families.filter((p) => p.protocol_service_ids.includes(s.id));
  const claims = d.claimsByEntity.get(s.id) ?? [];
  return (
    <>
      <nav aria-label="Brödsmulor" className="mb-3 text-sm text-muted">
        <Link to="/katalog">Katalog</Link> / Tjänst / {s.name}
      </nav>
      <PageHeader
        title={s.name}
        lead={
          <div className="flex flex-wrap items-center gap-2">
            <Badge>Protokoll / tjänst</Badge>
            {s.register ? (
              <>
                <OriginBadge origin={s.register.origin} />
                <span className="font-mono text-xs text-muted">{s.register.register_id}</span>
              </>
            ) : null}
            <VerificationBadge status={s.verification_status} />
          </div>
        }
      />
      <div className="space-y-4">
        <Callout tone="info" title="Protokoll är inte produkter">
          Ett protokoll eller en tjänst tilldelas aldrig produkt-CVE:er i denna kunskapsbas. En
          portträff visar en protokollmöjlighet, inte en specifik enhet eller en specifik sårbarhet.
          Risken ligger i protokollets inbyggda egenskaper och i hur det exponeras och konfigureras.
        </Callout>
        {s.data_quality_flags.length ? (
          <div className="flex flex-wrap gap-1">
            {s.data_quality_flags.map((f) => (
              <Badge key={f} tone="warn">
                {flagLabel[f]}
              </Badge>
            ))}
          </div>
        ) : null}
        <Section title="Teknisk funktion" id="funktion">
          <DefList
            items={[
              ['Funktion', s.function_text],
              ['Typisk användning', s.typical_use],
              ['Beskrivning', <Value key="d" value={s.description} />],
              ['Alias', s.aliases.length ? s.aliases.join(', ') : <Unknown>Inga</Unknown>],
              [
                'Standardportar',
                s.default_ports.length ? (
                  <ul key="p" className="space-y-1">
                    {s.default_ports.map((p) => (
                      <li key={`${p.port}-${p.transport}`}>
                        {p.port}/{p.transport} {p.note ? `– ${p.note}` : ''}{' '}
                        <VerificationBadge status={p.status} />
                      </li>
                    ))}
                  </ul>
                ) : (
                  <Unknown />
                ),
              ],
              ['Autentisering', securityPropertyLabel[s.authentication] ?? s.authentication],
              ['Kryptering', securityPropertyLabel[s.encryption] ?? s.encryption],
              ['Säkerhetsnoteringar', <Value key="n" value={s.security_notes} />],
              [
                'Tillåtna zoner (generell rekommendation)',
                <Value key="z" value={s.allowed_zones} />,
              ],
            ]}
          />
        </Section>
        <RegisterSection d={d} entry={s} />
        <CredentialsSection d={d} entry={s} />
        <SetupSection d={d} entry={s} />
        <Section title="Typiska OT-risker (från inventeringen)" id="risker">
          <DefList
            items={[
              ['Sårbarhetstyp / klass', <Value key="t" value={s.risk_summary.type_text} />],
              ['Vad risktypen innebär', <Value key="x" value={s.risk_summary.explanation_text} />],
              [
                'Inventeringsprio (villkorlig signal)',
                <Value key="o" value={s.risk_summary.legacy_priority_text} />,
              ],
            ]}
          />
        </Section>
        <RiskPanel risk={s.risk} />
        <Section title="Defensiva kontroller i rekommenderad ordning" id="atgarder">
          <ControlsList d={d} controlIds={s.control_ids} />
        </Section>
        {usedBy.length ? (
          <Section
            title="Produktfamiljer i katalogen som typiskt använder protokollet"
            id="anvands-av"
          >
            <ul className="flex flex-wrap gap-2 text-sm">
              {usedBy.map((p) => (
                <li key={p.id}>
                  <Link to={`/produkt/${p.id}`}>{p.name}</Link>
                </li>
              ))}
            </ul>
          </Section>
        ) : null}
        <Section title="Dokumentation" id="dokumentation">
          <DocumentationList d={d} docs={s.documentation} />
        </Section>
        <Section title="Påståenden och verifiering" id="pastaenden">
          <ClaimsList claims={claims} />
        </Section>
        <Section title="Källor" id="kallor">
          <SourcesList d={d} sourceIds={s.source_ids} />
        </Section>
        <Section title="Granskning och historik" id="granskning">
          <ReviewHistory review={s.review} />
          <div className="mt-3">
            <ProvenanceList prov={s.provenance} original={s.original} />
          </div>
          <p className="mt-2 text-xs text-muted">
            Upptäcktsheuristik (endast för egen/auktoriserad inventering):{' '}
            <code className="text-xs">{s.discovery_heuristic.query ?? '–'}</code>.{' '}
            {s.discovery_heuristic.caveat}
          </p>
        </Section>
      </div>
    </>
  );
}

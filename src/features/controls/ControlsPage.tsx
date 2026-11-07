import { Link } from 'react-router';
import { useDataset } from '@/data/DatasetContext';
import { Badge } from '@/components/Badge';
import { SafeLink } from '@/components/SafeLink';
import { Callout, PageHeader, Section } from '@/components/ui';
import type { Control } from '@schemas/index';
import { otSuitabilityLabel } from '@/lib/labels';

function ControlCard({ c, n, names }: { c: Control; n: number; names: Map<string, string> }) {
  return (
    <li className="rounded-lg border border-border p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-semibold">
          {n}. {c.name}
        </span>
        <Badge tone={c.requires_operational_approval ? 'warn' : 'neutral'}>
          {c.requires_operational_approval
            ? 'Kräver driftgodkännande'
            : 'Kan ofta införas utan driftstopp'}
        </Badge>
        <Badge>OT-lämplighet: {otSuitabilityLabel[c.ot_suitability] ?? c.ot_suitability}</Badge>
      </div>
      <p className="mt-1">{c.description}</p>
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
              {c.depends_on_control_ids.map((id) => names.get(id) ?? id).join(', ')}
            </dd>
          </div>
        ) : null}
      </dl>
      {c.vendor_guide_url ? (
        <p className="mt-1 text-xs">
          <SafeLink href={c.vendor_guide_url}>Tillverkarens hardening guide</SafeLink>
        </p>
      ) : null}
      {c.framework_refs.length ? (
        <ul className="mt-2 flex flex-wrap gap-1">
          {c.framework_refs.map((r, i) => (
            <li key={i}>
              <Badge tone="info" title={r.note ?? undefined}>
                {r.framework} {r.reference} · referens, ej efterlevnadspåstående
              </Badge>
            </li>
          ))}
        </ul>
      ) : null}
    </li>
  );
}

export function ControlsPage() {
  const d = useDataset();
  const names = new Map(d.controls.map((c) => [c.id, c.name]));
  const sorted = d.controls.slice().sort((a, b) => a.order_hint - b.order_hint);
  const general = sorted.filter(
    (c) => c.category_scope.length === 0 && c.protocol_scope.length === 0,
  );
  const categories = [...new Set(sorted.flatMap((c) => c.category_scope))].sort((a, b) =>
    a.localeCompare(b, 'sv'),
  );
  const protocols = [...new Set(sorted.flatMap((c) => c.protocol_scope))];
  return (
    <>
      <PageHeader
        title="Defensiva åtgärdsguider"
        lead="Rekommendationer per produktkategori och protokoll: segmentering, brandvägg/ACL, skyddad fjärråtkomst, MFA där möjligt, loggning, backup och återställning, livscykel- och leverantörsrisk. Inga exploateringsinstruktioner."
      />
      <div className="space-y-4">
        <Callout tone="info" title="Om ramverksreferenserna">
          Hänvisningar till IEC 62443, NIST CSF 2.0 och NIST SP 800-82 Rev. 3 är
          kartläggningsreferenser som hjälper till att placera en åtgärd i ett ramverk. De är inte
          påståenden om certifiering eller efterlevnad. Åtgärder som påverkar drift kräver
          riskbedömning och driftgodkännande före införande.
        </Callout>
        <Section title="Generella kontroller (alla kategorier)" id="generella">
          <ol className="space-y-2">
            {general.map((c, i) => (
              <ControlCard key={c.id} c={c} n={i + 1} names={names} />
            ))}
          </ol>
        </Section>
        {categories.map((cat) => {
          const list = sorted.filter((c) => c.category_scope.includes(cat));
          return (
            <Section
              key={cat}
              title={`Kategori: ${cat}`}
              id={`kat-${cat.replace(/[^a-z0-9]/gi, '-').toLowerCase()}`}
            >
              <ol className="space-y-2">
                {list.map((c, i) => (
                  <ControlCard key={c.id} c={c} n={i + 1} names={names} />
                ))}
              </ol>
              <p className="mt-2 text-xs">
                <Link to={`/katalog?category=${encodeURIComponent(cat)}`}>
                  Visa poster i kategorin
                </Link>
              </p>
            </Section>
          );
        })}
        {protocols.map((pid) => {
          const svc = d.protocolById.get(pid);
          const list = sorted.filter((c) => c.protocol_scope.includes(pid));
          return (
            <Section key={pid} title={`Protokoll: ${svc?.name ?? pid}`} id={`proto-${pid}`}>
              <ol className="space-y-2">
                {list.map((c, i) => (
                  <ControlCard key={c.id} c={c} n={i + 1} names={names} />
                ))}
              </ol>
              {svc ? (
                <p className="mt-2 text-xs">
                  <Link to={`/protokoll/${svc.id}`}>Till protokollsidan</Link>
                </p>
              ) : null}
            </Section>
          );
        })}
      </div>
    </>
  );
}

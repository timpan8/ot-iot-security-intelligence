import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { useDataset } from '@/data/DatasetContext';
import { isProduct } from '@/data/loader';
import { FactorBadge, VerificationBadge } from '@/components/Badge';
import { Callout, PageHeader, Section } from '@/components/ui';
import { actionDescription, actionLabel, factorName } from '@/lib/labels';
import { RecommendedAction } from '@schemas/index';

const FACTORS = [
  'threat',
  'severity',
  'relevance',
  'exposure',
  'ot_impact',
  'mitigation_feasibility',
  'data_quality',
] as const;

export function PrioritizationPage() {
  const d = useDataset();
  const [action, setAction] = useState<string>('all');
  const rows = useMemo(() => {
    const order = RecommendedAction.options;
    return d.entries
      .filter((e) => action === 'all' || e.risk.recommended_action === action)
      .slice()
      .sort(
        (a, b) =>
          order.indexOf(a.risk.recommended_action) - order.indexOf(b.risk.recommended_action) ||
          a.name.localeCompare(b.name, 'sv'),
      );
  }, [d, action]);
  const counts = RecommendedAction.options.map(
    (a) => [a, d.entries.filter((e) => e.risk.recommended_action === a).length] as const,
  );

  return (
    <>
      <PageHeader
        title="Prioritering (OT-anpassad, utan falsk precision)"
        lead="Varje post bedöms på sju separata faktorer. Ingen universell risksiffra beräknas och ingen post kallas automatiskt P1."
      />
      <div className="space-y-4">
        <Callout tone="warn" title="Exponering är alltid okänd i den publika katalogen">
          <p>
            Faktorn ”Exponering” kan bara fastställas för behörigt inventerade tillgångar.
            Arbetsbokens ”P1 vid publik åtkomst” på samtliga 66 poster är en villkorlig
            inventeringssignal (”om publikt åtkomlig, hantera som P1”), inte en uppgift om faktisk
            exponering eller individuell risknivå. Bekräftad exponering, riskacceptans och manuell
            granskning hör hemma i en framtida privat modul.
          </p>
        </Callout>
        <Section title="Fördelning per rekommenderad åtgärd" id="fordelning">
          <ul className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {counts.map(([a, n]) => (
              <li key={a}>
                <button
                  type="button"
                  className={`btn w-full justify-between ${action === a ? 'btn-primary' : ''}`}
                  onClick={() => setAction(action === a ? 'all' : a)}
                  aria-pressed={action === a}
                >
                  <span>{actionLabel[a]}</span>
                  <span className="tabular-nums">{n}</span>
                </button>
                <p className="mt-1 text-xs text-muted">{actionDescription[a]}</p>
              </li>
            ))}
          </ul>
        </Section>
        <Section
          title={`Poster (${rows.length})`}
          id="poster"
          description="Faktorer: hot/sannolikhet (KEV, EPSS, attackförutsättningar), teknisk allvarlighet (CVSS + leverantörskontext), faktisk relevans (styrkt versionsmatchning), exponering (alltid okänd här), OT-konsekvens, skydd/genomförbarhet och datakvalitet."
        >
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Post</th>
                  <th scope="col">Åtgärd</th>
                  {FACTORS.map((f) => (
                    <th key={f} scope="col" className="text-xs">
                      {factorName[f]}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.id}>
                    <td>
                      <Link
                        to={isProduct(e) ? `/produkt/${e.id}` : `/protokoll/${e.id}`}
                        className="font-medium"
                      >
                        {e.name}
                      </Link>
                      <div className="text-xs text-muted">
                        {e.category} · <VerificationBadge status={e.verification_status} />
                      </div>
                    </td>
                    <td className="text-xs">
                      {actionLabel[e.risk.recommended_action]}
                      <div className="mt-1 max-w-xs text-muted">{e.risk.rationale}</div>
                    </td>
                    {FACTORS.map((f) => (
                      <td key={f}>
                        <FactorBadge level={e.risk[f].level} />
                        <div className="mt-1 max-w-[12rem] text-xs text-muted">
                          {e.risk[f].basis}
                        </div>
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>
      </div>
    </>
  );
}

import { Link } from 'react-router';
import { isProduct, type CatalogEntry, type IndexedDataset } from '@/data/loader';
import { Badge, FactorBadge, PocBadge, PwdTypeBadge, VerificationBadge } from '@/components/Badge';
import { SafeLink } from '@/components/SafeLink';
import { collect, portsFor } from './collect';
import { fmtScore } from '@/lib/format';
import { actionDescription, actionLabel, flagLabel, orMissing } from '@/lib/labels';

const CVE_PREVIEW = 10;

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="font-cond text-xs font-semibold text-muted">{label}</dt>
      <dd className="mt-0.5">{children}</dd>
    </div>
  );
}

/** Allt som är dokumenterat om en post, i ett utfällt block direkt i katalogen. */
export function EntryPanel({
  d,
  e,
  hideVerification = false,
}: {
  d: IndexedDataset;
  e: CatalogEntry;
  hideVerification?: boolean;
}) {
  const { cves, pocs } = collect(d, e);
  const ports = portsFor(d, e);
  const detail = isProduct(e) ? `/produkt/${e.id}` : `/protokoll/${e.id}`;
  const cred = e.credentials;
  const setup = e.setup_documentation;

  return (
    <div className="@container">
      <div className="grid gap-x-8 gap-y-4 text-sm @2xl:grid-cols-2 @5xl:grid-cols-[1.1fr_1fr_1fr]">
        <dl className="space-y-3">
          <Field label="Rekommenderad åtgärd">
            <span className="font-medium">{actionLabel[e.risk.recommended_action]}</span>
            <span className="block text-xs text-muted">
              {actionDescription[e.risk.recommended_action]}
            </span>
          </Field>
          <Field label="Riskfaktorer">
            <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
              <span>
                Hot <FactorBadge level={e.risk.threat.level} />
              </span>
              <span>
                Allvarlighet <FactorBadge level={e.risk.severity.level} />
              </span>
              <span>
                OT-konsekvens <FactorBadge level={e.risk.ot_impact.level} />
              </span>
              <span>
                Exponering <FactorBadge level={e.risk.exposure.level} />
              </span>
            </span>
          </Field>
          {hideVerification ? null : (
            <Field label="Verifiering">
              <VerificationBadge status={e.verification_status} />
            </Field>
          )}
          {e.risk_summary.type_text ? (
            <Field label="Risktyp">
              <span className="text-xs">{e.risk_summary.type_text}</span>
            </Field>
          ) : null}
        </dl>

        <dl className="space-y-3">
          <Field label="Standardkonto">
            {cred?.account_name ? (
              <code className="rounded-[3px] bg-surface-2 px-1 py-0.5">{cred.account_name}</code>
            ) : (
              <span className="italic text-muted">
                {orMissing(cred?.account_name_text, 'Ej verifierat')}
              </span>
            )}
          </Field>
          <Field label="Initiallösenord (typ, aldrig värde)">
            {cred ? <PwdTypeBadge type={cred.initial_password_type} /> : <span>–</span>}
            {cred?.change_requirement_text ? (
              <span className="mt-1 block text-xs text-muted">{cred.change_requirement_text}</span>
            ) : null}
          </Field>
          <Field label="Setup och dokumentation">
            {setup?.url ? (
              <SafeLink href={setup.url}>{setup.title ?? 'Installationsdokument'}</SafeLink>
            ) : (
              <span className="italic text-muted">Uppgift saknas</span>
            )}
            {setup && !setup.is_verified_setup_manual ? (
              <span className="block text-xs text-warn">
                Dokumentportal eller guide – inte en verifierad installationsmanual
              </span>
            ) : null}
          </Field>
          <Field label="Standardportar (via protokoll)">
            {ports.length === 0 ? (
              <span className="italic text-muted">Ej angivet</span>
            ) : (
              <ul className="space-y-0.5">
                {ports.map((g) => (
                  <li key={g.serviceId} className="flex flex-wrap items-baseline gap-x-2">
                    <span className="font-mono text-xs">
                      {g.ports.map((p) => `${p.port}/${p.transport}`).join('  ')}
                    </span>
                    <Link to={`/protokoll/${g.serviceId}`} className="text-xs text-muted">
                      {g.service}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Field>
          <Field label="Sökord för egen inventering">
            {e.discovery_heuristic.query ? (
              <code className="break-all">{e.discovery_heuristic.query}</code>
            ) : (
              <span className="italic text-muted">Uppgift saknas</span>
            )}
          </Field>
        </dl>

        <dl className="space-y-3 @2xl:col-span-2 @5xl:col-span-1">
          <Field label={`Sårbarheter${cves.length ? ` (${cves.length})` : ''}`}>
            {cves.length === 0 ? (
              <span className="text-xs italic text-muted">
                {isProduct(e)
                  ? 'Inga verifierade CVE-kopplingar. Frånvaro av CVE är inte bevis för frånvaro av sårbarheter.'
                  : 'Protokoll tilldelas inga produkt-CVE; risken styrs av konfiguration och bakomliggande produkter.'}
              </span>
            ) : (
              <ul className="mt-1 flex flex-wrap gap-1.5">
                {cves.slice(0, CVE_PREVIEW).map((r) => (
                  <li
                    key={r.cve}
                    className={`inline-flex items-center gap-1.5 rounded-[3px] border border-border bg-surface px-1.5 py-0.5 text-xs ${r.kev ? 'bar-danger pl-2.5' : ''}`}
                  >
                    <Link to={`/sarbarheter/${r.cve}`} className="font-mono">
                      {r.cve}
                    </Link>
                    {r.score !== null ? (
                      <span className="num text-muted">{fmtScore(r.score)}</span>
                    ) : null}
                    {r.kev ? <Badge tone="danger">KEV</Badge> : null}
                    {r.poc === 'poc_reported' || r.poc === 'active_reported' ? (
                      <PocBadge status={r.poc} short />
                    ) : null}
                  </li>
                ))}
                {cves.length > CVE_PREVIEW ? (
                  <li>
                    <Link to={detail} className="text-xs">
                      {cves.length - CVE_PREVIEW} till på detaljsidan
                    </Link>
                  </li>
                ) : null}
              </ul>
            )}
          </Field>
          {pocs.length > 0 ? (
            <Field label={`Hotunderlag (${pocs.length}) – evidensnivå, inte exploateringssteg`}>
              <ul className="space-y-1 text-xs">
                {pocs.map((p) => (
                  <li key={p.url}>
                    <span className="font-mono">{p.cve}</span> · {p.material} ·{' '}
                    <SafeLink href={p.url} className="break-all" />
                  </li>
                ))}
              </ul>
            </Field>
          ) : null}
          {e.data_quality_flags.length > 0 ? (
            <Field label="Luckor i underlaget">
              <span className="text-xs text-muted">
                {e.data_quality_flags.map((f) => flagLabel[f] ?? f).join(', ')}
              </span>
            </Field>
          ) : null}
          <p>
            <Link to={detail} className="font-medium">
              Öppna hela detaljsidan
            </Link>
          </p>
        </dl>
      </div>
    </div>
  );
}

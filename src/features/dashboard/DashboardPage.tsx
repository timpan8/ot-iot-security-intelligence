import { useMemo, type ReactNode } from 'react';
import { Link } from 'react-router';
import { useDataset } from '@/data/DatasetContext';
import { isProduct } from '@/data/loader';
import { Badge, PocBadge } from '@/components/Badge';
import { PageHeader } from '@/components/ui';
import { applyFilters, DEFAULT_FILTERS, deriveEntry, strongestPoc } from '@/lib/filters';
import {
  actionLabel,
  flagLabel,
  pocStatusShort,
  pwdTypeLabel,
  verificationLabel,
} from '@/lib/labels';
import { fmtScore, pct } from '@/lib/format';
import {
  RecommendedAction,
  VerificationStatus,
  type DataQualityFlag,
  type InitialPasswordType,
  type PublicPocStatus,
} from '@schemas/index';

type Tone = 'danger' | 'warn' | null;

/** En rad i larmlistan. Hela raden är en länk till det filtrerade urvalet. */
function AlarmRow({
  n,
  tone,
  to,
  children,
}: {
  n: number;
  tone: Tone;
  to: string;
  children: ReactNode;
}) {
  return (
    <li>
      <Link
        to={to}
        className={`grid grid-cols-[3.5rem_1fr] items-baseline gap-3 px-4 py-2.5 text-text no-underline hover:bg-surface-2 ${
          tone === 'danger' ? 'bar-danger' : tone === 'warn' ? 'bar-warn' : ''
        }`}
      >
        <span
          className={`num text-right text-[1.75rem] leading-none font-semibold ${
            n === 0 ? 'text-muted' : tone === 'danger' ? 'text-danger' : ''
          }`}
        >
          {n}
        </span>
        <span className="text-sm">{children}</span>
      </Link>
    </li>
  );
}

/** Horisontell stapellista. Neutral fyllnad – färg är förbehållen avvikelser. */
function BarList({
  items,
  total,
}: {
  items: Array<{ key: string; label: ReactNode; n: number; to?: string; tone?: Tone }>;
  total: number;
}) {
  const max = Math.max(1, ...items.map((i) => i.n));
  return (
    <ul className="space-y-1">
      {items.map((i) => {
        const inner = (
          <>
            <span className="min-w-0 truncate">{i.label}</span>
            <span className="num shrink-0 text-muted">
              {i.n}
              <span className="ml-1.5 inline-block w-9 text-right text-xs">{pct(i.n, total)}</span>
            </span>
            <span
              aria-hidden="true"
              className="absolute inset-x-2 bottom-0 h-[3px] rounded-full bg-surface-2"
            >
              <span
                className={`block h-full rounded-full ${
                  i.tone === 'danger'
                    ? 'bg-danger-bar'
                    : i.tone === 'warn'
                      ? 'bg-warn-bar'
                      : 'bg-muted/50'
                }`}
                style={{ width: `${(i.n / max) * 100}%` }}
              />
            </span>
          </>
        );
        const cls = 'relative flex items-center justify-between gap-3 px-2 pt-1 pb-2 text-sm';
        return (
          <li key={i.key}>
            {i.to ? (
              <Link to={i.to} className={`${cls} text-text no-underline hover:underline`}>
                {inner}
              </Link>
            ) : (
              <div className={cls}>{inner}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}

function Panel({
  title,
  more,
  children,
  className = '',
}: {
  title: string;
  more?: { to: string; label: string };
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`card min-w-0 ${className}`}>
      <div className="flex items-baseline justify-between gap-3 border-b border-rule px-4 py-2.5">
        <h2 className="text-base font-semibold">{title}</h2>
        {more ? (
          <Link to={more.to} className="text-sm">
            {more.label}
          </Link>
        ) : null}
      </div>
      {children}
    </section>
  );
}

const PWD_TONE: Partial<Record<InitialPasswordType, Tone>> = {
  hardcoded_in_affected_version: 'danger',
  predictable_builtin_mechanism: 'danger',
  shared_default_documented: 'warn',
  default_exists_type_unknown: 'warn',
};

export function DashboardPage() {
  const d = useDataset();
  const total = d.entries.length;
  const der = useMemo(() => new Map(d.entries.map((e) => [e.id, deriveEntry(d, e)])), [d]);
  const all = [...der.values()];

  const kev = all.filter((x) => x.kevCount > 0).length;
  const active = all.filter((x) => x.pocStatuses.includes('active_reported')).length;
  const pocReported = all.filter((x) => x.pocStatuses.includes('poc_reported')).length;
  const weak = all.filter((x) => x.weakPwd).length;
  const eol = d.entries.filter(
    (e) => e.risk.recommended_action === 'replace_or_isolate_eol',
  ).length;
  const withCve = d.product_families.filter((p) => (der.get(p.id)?.cveIds.length ?? 0) > 0).length;

  const worst = useMemo(
    () =>
      applyFilters(d, d.entries, { ...DEFAULT_FILTERS, sort: 'severity' }, null)
        .filter((e) => (der.get(e.id)?.maxCvss ?? 0) > 0)
        .slice(0, 8),
    [d, der],
  );

  const actionItems = RecommendedAction.options
    .map((a) => ({
      key: a,
      label: actionLabel[a],
      n: d.entries.filter((e) => e.risk.recommended_action === a).length,
      to: `/katalog?action=${a}&sort=severity`,
    }))
    .sort((a, b) => b.n - a.n);

  const pwdCounts = new Map<InitialPasswordType, number>();
  for (const e of d.entries)
    if (e.credentials)
      pwdCounts.set(
        e.credentials.initial_password_type,
        (pwdCounts.get(e.credentials.initial_password_type) ?? 0) + 1,
      );
  const pwdItems = [...pwdCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([t, n]) => ({
      key: t,
      label: pwdTypeLabel[t],
      n,
      to: `/konton?pwdType=${t}`,
      tone: PWD_TONE[t] ?? null,
    }));

  const pocCounts = new Map<PublicPocStatus, number>();
  for (const v of d.vulnerabilities)
    if (v.threat_intel)
      pocCounts.set(
        v.threat_intel.public_poc_status,
        (pocCounts.get(v.threat_intel.public_poc_status) ?? 0) + 1,
      );
  const pocTotal = [...pocCounts.values()].reduce((a, b) => a + b, 0);
  const pocItems = (
    [
      'active_reported',
      'poc_reported',
      'none_reported_at_assessment',
      'unknown_missing',
    ] as PublicPocStatus[]
  ).map((s) => ({
    key: s,
    label: pocStatusShort[s],
    n: pocCounts.get(s) ?? 0,
    to: `/katalog?poc=${s}&sort=severity`,
    tone: (s === 'active_reported' ? 'danger' : s === 'poc_reported' ? 'warn' : null) as Tone,
  }));

  const verItems = VerificationStatus.options.map((s) => ({
    key: s,
    label: verificationLabel[s],
    n: d.entries.filter((e) => e.verification_status === s).length,
    to: `/katalog?verification=${s}`,
  }));

  const flagCounts = new Map<DataQualityFlag, number>();
  for (const e of d.entries)
    for (const f of e.data_quality_flags) flagCounts.set(f, (flagCounts.get(f) ?? 0) + 1);
  const flagItems = [...flagCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([f, n]) => ({ key: f, label: flagLabel[f], n, to: `/katalog?flags=${f}` }));

  const catCounts = new Map<string, number>();
  for (const e of d.entries) catCounts.set(e.category, (catCounts.get(e.category) ?? 0) + 1);

  const mc = d.manifest.counts;
  const linkOk = d.sources.filter(
    (s) => s.availability === 'ok' || s.availability === 'redirected',
  ).length;
  const linkBroken = d.sources.filter((s) => s.availability === 'broken').length;

  return (
    <>
      <PageHeader
        title="Översikt"
        lead={
          <>
            Läget i kunskapsbasen för {d.product_families.length} produktfamiljer och{' '}
            {d.protocol_services.length} protokoll. Siffrorna gäller produktfamiljer, aldrig
            installerade enheter. Klicka på en rad för att se posterna.
          </>
        }
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <Panel title="Produktfamiljer som kräver uppmärksamhet">
          <ul className="divide-y divide-rule py-1">
            <AlarmRow n={kev} tone="danger" to="/katalog?has=kev&sort=severity">
              har en CVE i <strong>CISA KEV</strong>, alltså bekräftat utnyttjad
            </AlarmRow>
            <AlarmRow n={active} tone="danger" to="/katalog?poc=active_reported&sort=severity">
              har rapporterad <strong>aktiv exploatering</strong> enligt CISA SSVC
            </AlarmRow>
            <AlarmRow n={pocReported} tone="warn" to="/katalog?poc=poc_reported&sort=severity">
              har en <strong>publik PoC</strong> rapporterad för minst en CVE
            </AlarmRow>
            <AlarmRow n={weak} tone="warn" to="/katalog?has=defaultpw&sort=severity">
              har <strong>svag standarduppgift</strong>: gemensamt, hårdkodat eller förutsägbart
              lösenord
            </AlarmRow>
            <AlarmRow n={eol} tone="warn" to="/katalog?action=replace_or_isolate_eol">
              bör <strong>bytas ut eller isoleras</strong> (livscykel)
            </AlarmRow>
            <AlarmRow n={withCve} tone={null} to="/katalog?has=cve&sort=severity">
              av {d.product_families.length} produktfamiljer har minst en verifierad CVE-koppling (
              {pct(withCve, d.product_families.length)})
            </AlarmRow>
          </ul>
        </Panel>

        <Panel
          title="Allvarligast just nu"
          more={{ to: '/katalog?sort=severity&has=cve', label: 'Alla i katalogen' }}
        >
          <table className="table">
            <thead className="sr-only">
              <tr>
                <th scope="col">Produkt</th>
                <th scope="col">Kategori</th>
                <th scope="col">CVE</th>
                <th scope="col" className="hidden sm:table-cell">
                  Signal
                </th>
              </tr>
            </thead>
            <tbody>
              {worst.map((e) => {
                const x = der.get(e.id)!;
                const p = strongestPoc(x.pocStatuses);
                return (
                  <tr key={e.id}>
                    <td className={x.kevCount > 0 ? 'bar-danger' : ''}>
                      <Link
                        to={isProduct(e) ? `/produkt/${e.id}` : `/protokoll/${e.id}`}
                        className="font-medium"
                      >
                        {e.name}
                      </Link>
                      <span className="ml-2 text-xs text-muted">{x.vendorName}</span>
                    </td>
                    <td className="hidden text-xs text-muted sm:table-cell">{e.category}</td>
                    <td className="num whitespace-nowrap">
                      {x.cveIds.length} CVE ·{' '}
                      <span className={(x.maxCvss ?? 0) >= 9 ? 'font-semibold text-danger' : ''}>
                        {fmtScore(x.maxCvss ?? 0)}
                      </span>
                    </td>
                    <td className="hidden whitespace-nowrap sm:table-cell">
                      {x.kevCount > 0 ? <Badge tone="danger">KEV</Badge> : null}{' '}
                      {p === 'active_reported' || p === 'poc_reported' ? (
                        <PocBadge status={p} short />
                      ) : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 items-start gap-4 md:grid-cols-2 xl:grid-cols-3">
        <Panel title="Rekommenderad åtgärd" more={{ to: '/prioritering', label: 'Prioritering' }}>
          <div className="p-3">
            <BarList items={actionItems} total={total} />
          </div>
        </Panel>
        <Panel title="Initiallösenord per post" more={{ to: '/konton', label: 'Konton' }}>
          <div className="p-3">
            <BarList items={pwdItems} total={total} />
            <p className="mt-2 px-2 text-xs text-muted">
              Underlaget innehåller inga lösenordsvärden. ”Okänt” betyder inte ”säkert”.
            </p>
          </div>
        </Panel>
        <Panel
          title={`PoC-status för ${pocTotal} CVE`}
          more={{ to: '/sarbarheter', label: 'Sårbarheter' }}
        >
          <div className="p-3">
            <BarList items={pocItems} total={pocTotal} />
            <p className="mt-2 px-2 text-xs text-muted">
              Enligt CISA SSVC vid bedömningsdatum. ”Ingen PoC uppgiven” är inte ett frånvarobevis.
            </p>
          </div>
        </Panel>
        <Panel title="Verifieringsgrad">
          <div className="p-3">
            <BarList items={verItems} total={total} />
          </div>
        </Panel>
        <Panel
          title="Vanligaste luckorna i underlaget"
          more={{ to: '/datakvalitet', label: 'Datakvalitet' }}
        >
          <div className="p-3">
            <BarList items={flagItems} total={total} />
          </div>
        </Panel>
        <Panel title={`${catCounts.size} kategorier`}>
          <ul className="flex flex-wrap gap-1 p-3">
            {[...catCounts.entries()]
              .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], 'sv'))
              .map(([c, n]) => (
                <li key={c}>
                  <Link className="chip" to={`/katalog?category=${encodeURIComponent(c)}`}>
                    {c} <span className="n">{n}</span>
                  </Link>
                </li>
              ))}
          </ul>
        </Panel>
      </div>

      <section aria-labelledby="underlag-h" className="mt-6 border-t border-border pt-4 text-sm">
        <h2 id="underlag-h" className="text-base font-semibold">
          Om underlaget
        </h2>
        <dl className="mt-2 grid grid-cols-2 gap-x-6 gap-y-2 sm:grid-cols-3 lg:grid-cols-6">
          {(
            [
              [
                'Katalogposter',
                total,
                `${d.product_families.length} produktfamiljer, ${d.protocol_services.length} protokoll`,
              ],
              [
                'CVE-poster',
                d.vulnerabilities.length,
                `${mc.register_relations} produktkopplingar`,
              ],
              ['Bulletiner', d.advisories.length, 'CISA, leverantörer'],
              ['Källor', d.sources.length, `${linkOk} nåbara, ${linkBroken} trasiga`],
              [
                'Registerposter',
                mc.register_entries,
                `${mc.register_original} original, ${mc.register_new} nya`,
              ],
              [
                'Påståenden att granska',
                d.claims.filter((c) => c.status === 'needs_review' || c.status === 'disputed')
                  .length,
                `${d.claims.filter((c) => c.status === 'unknown').length} med okänd status`,
              ],
            ] as Array<[string, number, string]>
          ).map(([k, v, h]) => (
            <div key={k}>
              <dt className="text-muted">{k}</dt>
              <dd>
                <span className="num text-lg font-semibold">{v}</span>
                <span className="block text-xs text-muted">{h}</span>
              </dd>
            </div>
          ))}
        </dl>
        <details className="mt-4 max-w-3xl">
          <summary className="cursor-pointer font-medium">
            Varför visas inte antal ”sårbara installationer”?
          </summary>
          <div className="mt-2 space-y-2 pl-4 text-muted">
            <p>
              Katalogen innehåller produktfamiljer och protokoll, inte inventerade tillgångar. Om en
              installation är sårbar beror på exakt modell, komponent, firmware, konfiguration och
              exponering – uppgifter som bara finns i en behörig anläggningsinventering. En sådan
              modul kräver separat autentiserad arkitektur och ingår inte i den publika webbplatsen.
            </p>
            <p>
              Arbetsbokens ”P1 vid publik åtkomst” på samtliga poster är en villkorlig
              inventeringssignal, inte en bedömning av faktisk exponering. Se{' '}
              <Link to="/prioritering">prioriteringsvyn</Link>.
            </p>
          </div>
        </details>
      </section>
    </>
  );
}

import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { useDataset } from '@/data/DatasetContext';
import { isProduct, type CatalogEntry, type IndexedDataset } from '@/data/loader';
import {
  Badge,
  FactorBadge,
  OriginBadge,
  PocBadge,
  PwdTypeBadge,
  VerificationBadge,
} from '@/components/Badge';
import { SafeLink } from '@/components/SafeLink';
import { Callout, EmptyState, PageHeader, StatTile } from '@/components/ui';
import { fmtScore } from '@/lib/format';
import {
  actionLabel,
  flagLabel,
  materialTypeLabel,
  NO_PASSWORD_VALUES_NOTE,
  orMissing,
} from '@/lib/labels';
import type { Vulnerability as TVulnerability } from '@schemas/index';

/** En CVE kopplad till en post, med de signaler som behövs för snabböversikten. */
interface CveRow {
  cve: string;
  score: number | null;
  kev: boolean;
  pocStatus: string | null;
  vuln: TVulnerability;
}

interface PocRow {
  cve: string;
  url: string;
  material: string;
  note: string | null;
}

/** Lösenordstyper som i sig signalerar en svaghet som kräver åtgärd (inte bara okänt). */
const WEAK_PWD = new Set([
  'shared_default_documented',
  'hardcoded_in_affected_version',
  'predictable_builtin_mechanism',
  'default_exists_type_unknown',
]);

interface Aggregate {
  entry: CatalogEntry;
  cves: CveRow[];
  maxScore: number | null;
  kevCount: number;
  pocUrls: PocRow[];
  pocReportedCount: number;
  namedAccount: string | null;
  weakPwd: boolean;
}

function aggregate(d: IndexedDataset, e: CatalogEntry): Aggregate {
  const matches = isProduct(e) ? (d.matchesByProduct.get(e.id) ?? []) : [];
  const seen = new Map<string, CveRow>();
  const pocUrls = new Map<string, PocRow>();
  for (const m of matches) {
    if (!m.vulnerability_id) continue;
    const v = d.vulnerabilityById.get(m.vulnerability_id);
    if (!v) continue;
    const score = v.cvss.length ? Math.max(...v.cvss.map((c) => c.base_score)) : null;
    if (!seen.has(v.cve_id)) {
      seen.set(v.cve_id, {
        cve: v.cve_id,
        score,
        kev: v.kev.listed,
        pocStatus: v.threat_intel?.public_poc_status ?? null,
        vuln: v,
      });
    }
    const ti = v.threat_intel;
    if (ti?.poc_url && !pocUrls.has(ti.poc_url)) {
      pocUrls.set(ti.poc_url, {
        cve: v.cve_id,
        url: ti.poc_url,
        material: materialTypeLabel[ti.material_type_code] ?? ti.material_type_text ?? 'okänd typ',
        note: ti.source_critical_note,
      });
    }
  }
  const cves = [...seen.values()].sort((a, b) => (b.score ?? -1) - (a.score ?? -1));
  const c = e.credentials;
  return {
    entry: e,
    cves,
    maxScore: cves.reduce<number | null>((max, r) => {
      if (r.score === null) return max;
      return max === null ? r.score : Math.max(max, r.score);
    }, null),
    kevCount: cves.filter((r) => r.kev).length,
    pocUrls: [...pocUrls.values()],
    pocReportedCount: cves.filter(
      (r) => r.pocStatus === 'poc_reported' || r.pocStatus === 'active_reported',
    ).length,
    namedAccount: c?.account_name ?? null,
    weakPwd: c ? WEAK_PWD.has(c.initial_password_type) : false,
  };
}

const CVE_PREVIEW = 8;

export function ProductOverviewPage() {
  const d = useDataset();
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState('');
  const scope = params.get('scope') ?? 'all';
  const origin = params.get('origin') ?? 'all';
  const hasParam = params.get('has') ?? '';
  const has = useMemo(() => new Set(hasParam.split(',').filter(Boolean)), [hasParam]);
  const sort = params.get('sort') ?? 'severity';

  const setParam = (k: string, v: string | null) => {
    const next = new URLSearchParams(params);
    if (v === null || v === '' || v === 'all') next.delete(k);
    else next.set(k, v);
    setParams(next, { replace: true });
  };
  const toggleHas = (key: string) => {
    const next = new Set(has);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    setParam('has', [...next].join(','));
  };

  const aggregates = useMemo(() => d.entries.map((e) => aggregate(d, e)), [d]);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    let list = aggregates.filter((a) => {
      const e = a.entry;
      if (scope === 'products' && !isProduct(e)) return false;
      if (scope === 'protocols' && isProduct(e)) return false;
      if (origin !== 'all' && e.register?.origin !== origin) return false;
      if (has.has('cve') && a.cves.length === 0) return false;
      if (has.has('kev') && a.kevCount === 0) return false;
      if (has.has('poc') && a.pocUrls.length === 0) return false;
      if (has.has('account') && !a.namedAccount) return false;
      if (has.has('defaultpw') && !a.weakPwd) return false;
      if (needle) {
        const hay =
          `${e.name} ${e.aliases.join(' ')} ${e.register?.register_id ?? ''} ${e.category} ${a.namedAccount ?? ''} ${a.cves.map((c) => c.cve).join(' ')}`.toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
    list = [...list].sort((a, b) => {
      if (sort === 'name') return a.entry.name.localeCompare(b.entry.name, 'sv');
      if (sort === 'cves') return b.cves.length - a.cves.length;
      // severity (default): KEV först, sedan högsta CVSS, sedan namn
      if (b.kevCount !== a.kevCount) return b.kevCount - a.kevCount;
      const bs = b.maxScore ?? -1;
      const as = a.maxScore ?? -1;
      if (bs !== as) return bs - as;
      return a.entry.name.localeCompare(b.entry.name, 'sv');
    });
    return list;
  }, [aggregates, q, scope, origin, has, sort]);

  const totals = useMemo(
    () => ({
      withCve: aggregates.filter((a) => a.cves.length > 0).length,
      withKev: aggregates.filter((a) => a.kevCount > 0).length,
      withPoc: aggregates.filter((a) => a.pocUrls.length > 0).length,
      withAccount: aggregates.filter((a) => a.namedAccount).length,
      weakPwd: aggregates.filter((a) => a.weakPwd).length,
    }),
    [aggregates],
  );

  return (
    <div className="space-y-5">
      <PageHeader
        title="Snabböversikt per produkt"
        lead="En rad per produkt eller protokoll med allt som är dokumenterat på ett ställe: verifierade CVE-kopplingar, KEV- och PoC-status, dokumenterat standardkonto och typ av initiallösenord, upptäcktsheuristik och rekommenderad åtgärd. Översikten återanvänder data som redan finns på detaljsidorna."
      />

      <Callout tone="info" title="Så ska översikten läsas (defensiv inventering)">
        <ul className="ml-4 list-disc space-y-1">
          <li>
            <strong>Inga lösenordsvärden finns i underlaget.</strong> {NO_PASSWORD_VALUES_NOTE}{' '}
            Kolumnen visar dokumenterat kontonamn och <em>typ</em> av initiallösenord, aldrig ett
            lösenord.
          </li>
          <li>
            <strong>Upptäcktsheuristiken (Shodan-sökord)</strong> är till för din egen eller
            auktoriserad inventering. Komplettera med ditt eget IP-intervall. Träffar är inte
            enhetsbevis. Plattformen utför inga sökningar.
          </li>
          <li>
            <strong>PoC-/hotunderlag</strong> redovisas som daterad evidensnivå (offentlig PoC,
            emulator, detektionsverktyg, aktiv exploatering) – inte som exploateringssteg. Ingen kod
            har körts.
          </li>
          <li>
            Dokumenterad risk är inte bevis på exponering eller kompromettering. Observerad
            internetexponering är <em>ej undersökt</em> på alla poster.
          </li>
        </ul>
      </Callout>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        <StatTile label="Poster med CVE-koppling" value={totals.withCve} />
        <StatTile label="Poster med KEV-CVE" value={totals.withKev} hint="Bekräftat utnyttjande" />
        <StatTile label="Poster med PoC-länk" value={totals.withPoc} />
        <StatTile label="Dokumenterat kontonamn" value={totals.withAccount} />
        <StatTile
          label="Svag standarduppgift"
          value={totals.weakPwd}
          hint="Gemensamt/hårdkodat/förutsägbart"
        />
      </div>

      <div className="card space-y-3 p-4">
        <div className="grid gap-3 sm:grid-cols-[1fr_auto_auto_auto]">
          <label className="block">
            <span className="text-sm font-medium text-muted">
              Sök (namn, alias, register-ID, kategori, konto, CVE)
            </span>
            <input
              type="search"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="t.ex. Siemens, OT-015, CVE-2023-6448, admin"
              className="mt-1 w-full rounded-md border border-border bg-bg px-3 py-2 text-sm"
            />
          </label>
          <label className="block">
            <span className="text-sm font-medium text-muted">Typ</span>
            <select
              value={scope}
              onChange={(e) => setParam('scope', e.target.value)}
              className="mt-1 w-full rounded-md border border-border bg-bg px-3 py-2 text-sm"
            >
              <option value="all">Alla</option>
              <option value="products">Produkter</option>
              <option value="protocols">Protokoll/tjänster</option>
            </select>
          </label>
          <label className="block">
            <span className="text-sm font-medium text-muted">Ursprung</span>
            <select
              value={origin}
              onChange={(e) => setParam('origin', e.target.value)}
              className="mt-1 w-full rounded-md border border-border bg-bg px-3 py-2 text-sm"
            >
              <option value="all">Alla</option>
              <option value="original">Original</option>
              <option value="new">Ny</option>
            </select>
          </label>
          <label className="block">
            <span className="text-sm font-medium text-muted">Sortering</span>
            <select
              value={sort}
              onChange={(e) => setParam('sort', e.target.value)}
              className="mt-1 w-full rounded-md border border-border bg-bg px-3 py-2 text-sm"
            >
              <option value="severity">KEV och CVSS först</option>
              <option value="cves">Flest CVE</option>
              <option value="name">Namn (A–Ö)</option>
            </select>
          </label>
        </div>
        <fieldset className="flex flex-wrap items-center gap-2">
          <legend className="sr-only">Snabbfilter</legend>
          <span className="text-sm font-medium text-muted">Visa endast med:</span>
          {(
            [
              ['cve', 'CVE-koppling'],
              ['kev', 'KEV'],
              ['poc', 'PoC-länk'],
              ['account', 'namngivet konto'],
              ['defaultpw', 'svag standarduppgift'],
            ] as const
          ).map(([key, label]) => (
            <button
              key={key}
              type="button"
              aria-pressed={has.has(key)}
              onClick={() => toggleHas(key)}
              className={`rounded-md border px-2.5 py-1 text-xs font-medium ${
                has.has(key)
                  ? 'border-info bg-info-bg text-info'
                  : 'border-border text-muted hover:text-text'
              }`}
            >
              {label}
            </button>
          ))}
        </fieldset>
        <p className="text-sm text-muted">
          {rows.length} av {aggregates.length} poster
        </p>
      </div>

      {rows.length === 0 ? (
        <EmptyState>Inga poster matchar filtret.</EmptyState>
      ) : (
        <ul className="space-y-4">
          {rows.map((a) => (
            <OverviewCard key={a.entry.id} a={a} d={d} />
          ))}
        </ul>
      )}
    </div>
  );
}

function OverviewCard({ a, d }: { a: Aggregate; d: IndexedDataset }) {
  const e = a.entry;
  const vendor = isProduct(e) ? d.vendorById.get(e.vendor_id) : null;
  const detail = isProduct(e) ? `/produkt/${e.id}` : `/protokoll/${e.id}`;
  const cred = e.credentials;
  const setup = e.setup_documentation;

  return (
    <li className="card p-4 sm:p-5">
      {/* Rubrik */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Link to={detail} className="text-lg font-semibold break-words underline">
              {e.name}
            </Link>
            {e.register ? <OriginBadge origin={e.register.origin} /> : null}
            <Badge tone="neutral">{e.category}</Badge>
          </div>
          <p className="mt-0.5 text-sm text-muted">
            {vendor ? vendor.name : 'Protokoll/tjänst'}
            {e.register ? ` · ${e.register.register_id}` : ''} · {e.function_text}
          </p>
        </div>
        <div className="flex flex-shrink-0 flex-wrap items-center justify-end gap-2">
          {a.kevCount > 0 ? (
            <Badge tone="danger" title="Minst en CVE i CISA KEV">
              KEV ×{a.kevCount}
            </Badge>
          ) : null}
          {a.maxScore !== null ? (
            <Badge tone={a.maxScore >= 9 ? 'danger' : a.maxScore >= 7 ? 'warn' : 'neutral'}>
              Max CVSS {fmtScore(a.maxScore)}
            </Badge>
          ) : null}
          <VerificationBadge status={e.verification_status} />
        </div>
      </div>

      {/* Åtgärd + riskfaktorer */}
      <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
        <Badge tone="info" title="Rekommenderad åtgärd (se prioriteringsvyn)">
          {actionLabel[e.risk.recommended_action]}
        </Badge>
        <span className="text-muted">Hot</span>
        <FactorBadge level={e.risk.threat.level} />
        <span className="text-muted">Allvarlighet</span>
        <FactorBadge level={e.risk.severity.level} />
        <span className="text-muted">OT-konsekvens</span>
        <FactorBadge level={e.risk.ot_impact.level} />
        <span className="text-muted">Exponering</span>
        <FactorBadge level={e.risk.exposure.level} />
      </div>

      {/* Fält-grid */}
      <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-3 text-sm md:grid-cols-2">
        <div>
          <dt className="font-medium text-muted">Standardkonto</dt>
          <dd className="mt-0.5">
            {cred?.account_name ? (
              <code className="rounded bg-muted/10 px-1 py-0.5">{cred.account_name}</code>
            ) : (
              <span className="italic text-muted">
                {orMissing(cred?.account_name_text, 'Ej verifierat')}
              </span>
            )}
          </dd>
        </div>
        <div>
          <dt className="font-medium text-muted">Initiallösenord (typ, ej värde)</dt>
          <dd className="mt-0.5 flex flex-wrap items-center gap-2">
            {cred ? <PwdTypeBadge type={cred.initial_password_type} /> : <span>–</span>}
            {cred?.change_requirement_text ? (
              <span className="text-xs text-muted">{cred.change_requirement_text}</span>
            ) : null}
          </dd>
        </div>
        <div>
          <dt className="font-medium text-muted">Upptäcktsheuristik (Shodan-sökord)</dt>
          <dd className="mt-0.5">
            {e.discovery_heuristic.query ? (
              <code className="rounded bg-muted/10 px-1 py-0.5 text-xs break-all">
                {e.discovery_heuristic.query}
              </code>
            ) : (
              <span className="italic text-muted">Uppgift saknas</span>
            )}
            <span className="ml-1 text-xs text-muted">
              För egen/auktoriserad inventering. Komplettera med ditt IP-intervall; träffar är inte
              enhetsbevis.
            </span>
          </dd>
        </div>
        <div>
          <dt className="font-medium text-muted">Setup/dokumentation</dt>
          <dd className="mt-0.5">
            {setup?.url ? (
              <SafeLink href={setup.url}>{setup.title ?? 'Installationsdokument'}</SafeLink>
            ) : (
              <span className="italic text-muted">Uppgift saknas</span>
            )}
            {setup && !setup.is_verified_setup_manual ? (
              <span className="ml-1 text-xs text-warn">
                (dokumentportal/guide – ej verifierad installationsmanual)
              </span>
            ) : null}
          </dd>
        </div>
      </dl>

      {/* Sårbarheter */}
      <div className="mt-4">
        <p className="text-sm font-medium text-muted">
          Sårbarheter{a.cves.length ? ` (${a.cves.length})` : ''}
        </p>
        {a.cves.length === 0 ? (
          <p className="mt-1 text-sm italic text-muted">
            {isProduct(e)
              ? 'Inga verifierade CVE-kopplingar i katalogen. Frånvaro av CVE är inte bevis för frånvaro av sårbarheter.'
              : 'Protokoll/tjänst tilldelas inga produkt-CVE:er; risken styrs av konfiguration och bakomliggande produkter.'}
          </p>
        ) : (
          <div className="mt-2 flex flex-wrap gap-2">
            {a.cves.slice(0, CVE_PREVIEW).map((r) => (
              <span
                key={r.cve}
                className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs"
              >
                <Link to={`/sarbarheter/${r.cve}`} className="font-medium underline">
                  {r.cve}
                </Link>
                {r.score !== null ? (
                  <span className="tabular-nums text-muted">{fmtScore(r.score)}</span>
                ) : null}
                {r.kev ? <Badge tone="danger">KEV</Badge> : null}
                {r.pocStatus === 'poc_reported' || r.pocStatus === 'active_reported' ? (
                  <PocBadge status={r.pocStatus} short />
                ) : null}
              </span>
            ))}
            {a.cves.length > CVE_PREVIEW ? (
              <Link
                to={detail}
                className="inline-flex items-center rounded-md border border-dashed border-border px-2 py-1 text-xs text-muted underline"
              >
                +{a.cves.length - CVE_PREVIEW} fler på detaljsidan
              </Link>
            ) : null}
          </div>
        )}
      </div>

      {/* PoC-/hotunderlag */}
      {a.pocUrls.length > 0 ? (
        <details className="mt-3">
          <summary className="cursor-pointer text-sm font-medium text-muted">
            PoC-/hotunderlag ({a.pocUrls.length}) – evidensnivå, ej exploateringssteg
          </summary>
          <ul className="mt-2 space-y-2 text-sm">
            {a.pocUrls.map((p) => (
              <li key={p.url} className="rounded-md border border-border p-2">
                <div className="flex flex-wrap items-center gap-2">
                  <Link to={`/sarbarheter/${p.cve}`} className="font-medium underline">
                    {p.cve}
                  </Link>
                  <Badge tone="neutral">{p.material}</Badge>
                  <SafeLink href={p.url} className="text-xs break-all underline" />
                </div>
                {p.note ? <p className="mt-1 text-xs text-muted">{p.note}</p> : null}
              </li>
            ))}
          </ul>
        </details>
      ) : null}

      {/* Datakvalitetsflaggor */}
      {e.data_quality_flags.length > 0 ? (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {e.data_quality_flags.map((f) => (
            <Badge key={f} tone="warn" title={flagLabel[f]}>
              {flagLabel[f] ?? f}
            </Badge>
          ))}
        </div>
      ) : null}

      <div className="mt-3 flex flex-wrap gap-3 text-sm">
        <Link to={detail} className="underline">
          Öppna detaljsida →
        </Link>
        {a.cves.length > 0 ? (
          <span className="text-muted">
            {a.kevCount > 0 ? `${a.kevCount} KEV · ` : ''}
            {a.pocReportedCount > 0 ? `${a.pocReportedCount} med rapporterad PoC` : ''}
          </span>
        ) : null}
      </div>
    </li>
  );
}

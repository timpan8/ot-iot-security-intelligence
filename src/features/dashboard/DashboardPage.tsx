import { Link } from 'react-router';
import { useDataset } from '@/data/DatasetContext';
import { isProduct } from '@/data/loader';
import { Callout, PageHeader, Section, StatTile } from '@/components/ui';
import { VerificationBadge } from '@/components/Badge';
import { flagLabel } from '@/lib/labels';
import { pct } from '@/lib/format';
import type { DataQualityFlag, VerificationStatus } from '@schemas/index';

const STATUSES: VerificationStatus[] = [
  'verified_primary',
  'corroborated_secondary',
  'needs_review',
  'unknown',
  'disputed',
];

export function DashboardPage() {
  const d = useDataset();
  const total = d.entries.length;
  const categories = new Set(d.entries.map((e) => e.category)).size;
  const withCve = d.product_families.filter((p) =>
    (d.matchesByProduct.get(p.id) ?? []).some((m) => m.vulnerability_id),
  ).length;
  const kevVulns = d.vulnerabilities.filter((v) => v.kev.listed).length;
  const statusCounts = STATUSES.map(
    (s) => [s, d.entries.filter((e) => e.verification_status === s).length] as const,
  );
  const unknownFields = d.claims.filter((c) => c.status === 'unknown').length;
  const reviewClaims = d.claims.filter(
    (c) => c.status === 'needs_review' || c.status === 'disputed',
  ).length;
  const sourcesToReview = d.sources.filter((s) => s.availability !== 'ok' || !s.is_primary).length;
  const primarySources = d.sources.filter((s) => s.is_primary).length;

  const flagCounts = new Map<DataQualityFlag, number>();
  for (const e of d.entries)
    for (const f of e.data_quality_flags) flagCounts.set(f, (flagCounts.get(f) ?? 0) + 1);
  const topFlags = [...flagCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);

  const catCounts = new Map<string, number>();
  for (const e of d.entries) catCounts.set(e.category, (catCounts.get(e.category) ?? 0) + 1);

  return (
    <>
      <PageHeader
        title="Översikt"
        lead={
          <>
            Kunskapsbasen beskriver <strong>produktfamiljer och protokoll</strong>, inte
            installerade enheter. Siffrorna nedan gäller katalogposter och verifierade källor,
            aldrig faktiska anläggningar.
          </>
        }
      />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatTile
          label="Katalogposter"
          value={total}
          hint={`${d.manifest.counts.product_families} produktfamiljer + ${d.manifest.counts.protocol_services} tjänster`}
        />
        <StatTile label="Produktfamiljer" value={d.product_families.length} />
        <StatTile
          label="Protokoll / tjänster"
          value={d.protocol_services.length}
          hint="Protokoll tilldelas aldrig produkt-CVE"
        />
        <StatTile label="Kategorier" value={categories} />
        <StatTile
          label="Poster med verifierad CVE-koppling"
          value={withCve}
          hint={`${pct(withCve, d.product_families.length)} av produktfamiljerna`}
        />
        <StatTile
          label="CVE-poster"
          value={d.vulnerabilities.length}
          hint={`${kevVulns} i CISA KEV`}
        />
        <StatTile label="Bulletiner" value={d.advisories.length} />
        <StatTile
          label="Källor"
          value={d.sources.length}
          hint={`${primarySources} primära · ${sourcesToReview} att granska`}
        />
      </div>

      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <Section
          title="Verifieringsgrad per katalogpost"
          description="Andel poster per högsta sammanvägda verifieringsstatus."
        >
          <ul className="space-y-2">
            {statusCounts.map(([s, n]) => (
              <li key={s} className="flex items-center justify-between gap-3 text-sm">
                <VerificationBadge status={s} />
                <span className="tabular-nums">
                  {n} <span className="text-muted">({pct(n, total)})</span>
                </span>
              </li>
            ))}
          </ul>
        </Section>

        <Section title="Okända uppgifter och granskningsbehov">
          <dl className="grid grid-cols-2 gap-3 text-sm">
            <div className="card p-3">
              <dt className="text-muted">Påståenden med status okänd</dt>
              <dd className="text-xl font-semibold">{unknownFields}</dd>
            </div>
            <div className="card p-3">
              <dt className="text-muted">Påståenden som behöver granskning</dt>
              <dd className="text-xl font-semibold">{reviewClaims}</dd>
            </div>
          </dl>
          <ul className="mt-3 space-y-1 text-sm">
            {topFlags.map(([f, n]) => (
              <li key={f} className="flex justify-between gap-2">
                <Link to={`/katalog?flags=${f}`}>{flagLabel[f]}</Link>
                <span className="tabular-nums text-muted">{n}</span>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-sm">
            <Link to="/datakvalitet">Till datakvalitetsvyn</Link>
          </p>
        </Section>

        <Section title="Kategorier">
          <ul className="grid grid-cols-2 gap-1 text-sm sm:grid-cols-3">
            {[...catCounts.entries()]
              .sort((a, b) => b[1] - a[1])
              .map(([c, n]) => (
                <li
                  key={c}
                  className="flex justify-between gap-2 rounded px-2 py-1 hover:bg-surface-2"
                >
                  <Link to={`/katalog?category=${encodeURIComponent(c)}`}>{c}</Link>
                  <span className="tabular-nums text-muted">{n}</span>
                </li>
              ))}
          </ul>
        </Section>

        <Callout tone="info" title="Varför visas inte antal ”sårbara installationer”?">
          <p>
            Katalogen innehåller produktfamiljer och protokoll, inte inventerade tillgångar. Om en
            installation är sårbar beror på exakt modell, komponent, firmware, konfiguration och
            exponering – uppgifter som bara finns i en behörig anläggningsinventering. En sådan
            modul kräver separat autentiserad arkitektur och ingår inte i den publika webbplatsen.
          </p>
          <p className="mt-2">
            Arbetsbokens ”P1 vid publik åtkomst” på samtliga poster är en villkorlig
            inventeringssignal, inte en bedömning av faktisk exponering. Se{' '}
            <Link to="/prioritering">prioriteringsvyn</Link>.
          </p>
        </Callout>
      </div>

      <Section title="Snabbval" id="snabbval">
        <div className="flex flex-wrap gap-2 text-sm">
          <Link className="btn" to="/katalog?kev=yes">
            Poster med KEV-listad CVE
          </Link>
          <Link className="btn" to="/katalog?verification=needs_review,disputed">
            Behöver granskning
          </Link>
          <Link className="btn" to="/katalog?kind=protocol_service">
            Alla protokoll
          </Link>
          <Link className="btn" to="/katalog?flags=industry_guide_only">
            Endast branschguide
          </Link>
          <Link className="btn" to="/sarbarheter">
            Alla CVE-poster
          </Link>
        </div>
        <p className="mt-3 text-xs text-muted">
          {
            d.entries.filter(
              (e) =>
                isProduct(e) && e.lifecycle.status !== 'unknown' && e.lifecycle.status !== 'active',
            ).length
          }{' '}
          produktfamiljer har livscykelmarkering (EOL/blandad).
        </p>
      </Section>
    </>
  );
}

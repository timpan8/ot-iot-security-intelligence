import { Link } from 'react-router';
import { useDataset } from '@/data/DatasetContext';
import { isProduct } from '@/data/loader';
import { Callout, PageHeader, Section, StatTile } from '@/components/ui';
import { PocBadge, PwdTypeBadge, VerificationBadge } from '@/components/Badge';
import { flagLabel } from '@/lib/labels';
import { pct } from '@/lib/format';
import type {
  DataQualityFlag,
  InitialPasswordType,
  PublicPocStatus,
  VerificationStatus,
} from '@schemas/index';

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

  // Registerimport (125-postregistret)
  const mc = d.manifest.counts;
  const hasRegister = mc.register_entries > 0;
  const pocCounts = new Map<PublicPocStatus, number>();
  for (const v of d.vulnerabilities)
    if (v.threat_intel)
      pocCounts.set(
        v.threat_intel.public_poc_status,
        (pocCounts.get(v.threat_intel.public_poc_status) ?? 0) + 1,
      );
  const pwdCounts = new Map<InitialPasswordType, number>();
  for (const e of d.entries)
    if (e.credentials)
      pwdCounts.set(
        e.credentials.initial_password_type,
        (pwdCounts.get(e.credentials.initial_password_type) ?? 0) + 1,
      );
  const setupUnverified = d.entries.filter(
    (e) => e.setup_documentation && !e.setup_documentation.is_verified_setup_manual,
  ).length;
  const setupMissing = d.entries.filter((e) => isProduct(e) && !e.setup_documentation).length;
  const linkOk = d.sources.filter(
    (s) => s.availability === 'ok' || s.availability === 'redirected',
  ).length;
  const linkBlocked = d.sources.filter((s) => s.availability === 'blocked').length;
  const linkBroken = d.sources.filter((s) => s.availability === 'broken').length;
  const linkUnchecked = d.sources.filter((s) => s.availability === 'unchecked').length;

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
      <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4">
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

      {hasRegister ? (
        <Section
          title="Utökat register (125 poster)"
          id="register"
          description="Importerat från OT_IoT_125_poster_losenordsstatus.xlsx med källmanifest (SHA-256), hotunderlag, konto-/lösenordsstatus och länkkontroll. Siffrorna gäller katalogposter och CVE-poster, inte installerade enheter."
        >
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <StatTile
              label="Registerposter"
              value={mc.register_entries}
              hint={`${mc.register_original} original · ${mc.register_new} nya`}
            />
            <StatTile
              label="Unika CVE i registret"
              value={mc.register_cve_unique}
              hint={`${mc.register_relations} produkt–CVE-relationer`}
            />
            <StatTile
              label="CVE med hotunderlag"
              value={mc.threat_intel}
              hint="PoC, SSVC, aktiv exploatering, materialtyp"
            />
            <StatTile
              label="Länkar kontrollerade i registret"
              value={mc.link_checks}
              hint={`källor: ${linkOk} ok · ${linkBlocked} blockerade · ${linkBroken} trasiga · ${linkUnchecked} ej kontrollerade`}
            />
          </div>
          <div className="mt-4 grid gap-4 lg:grid-cols-3">
            <div>
              <h3 className="text-sm font-semibold">PoC-/exploateringsstatus per CVE</h3>
              <p className="text-xs text-muted">
                Enligt CISA SSVC vid respektive bedömningsdatum. ”Ingen PoC uppgiven” är inte
                frånvarobevis.
              </p>
              <ul className="mt-2 space-y-1 text-sm">
                {(
                  [
                    'active_reported',
                    'poc_reported',
                    'none_reported_at_assessment',
                    'unknown_missing',
                  ] as PublicPocStatus[]
                ).map((s) => (
                  <li key={s} className="flex items-center justify-between gap-2">
                    <Link to={`/katalog?poc=${s}`} className="no-underline">
                      <PocBadge status={s} short />
                    </Link>
                    <span className="tabular-nums text-muted">{pocCounts.get(s) ?? 0}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <h3 className="text-sm font-semibold">Typ av initiallösenord per post</h3>
              <p className="text-xs text-muted">
                Inga lösenordsvärden i underlaget. ”Okänt” betyder inte ”säkert”.
              </p>
              <ul className="mt-2 space-y-1 text-sm">
                {[...pwdCounts.entries()]
                  .sort((a, b) => b[1] - a[1])
                  .map(([t, n]) => (
                    <li key={t} className="flex items-center justify-between gap-2">
                      <Link to={`/konton?pwdType=${t}`} className="no-underline">
                        <PwdTypeBadge type={t} />
                      </Link>
                      <span className="tabular-nums text-muted">{n}</span>
                    </li>
                  ))}
              </ul>
              <p className="mt-2 text-sm">
                <Link to="/konton">Till kontosammanställningen</Link>
              </p>
            </div>
            <div>
              <h3 className="text-sm font-semibold">Dokumentationsluckor</h3>
              <ul className="mt-2 space-y-1 text-sm">
                <li className="flex justify-between gap-2">
                  <Link to="/katalog?docgap=unverified">Setupmanual ej verifierad</Link>
                  <span className="tabular-nums text-muted">{setupUnverified}</span>
                </li>
                <li className="flex justify-between gap-2">
                  <span>Produkter utan setupdokument i registret</span>
                  <span className="tabular-nums text-muted">{setupMissing}</span>
                </li>
                <li className="flex justify-between gap-2">
                  <Link to="/katalog?flags=account_name_unverified">Kontonamn ej verifierat</Link>
                  <span className="tabular-nums text-muted">
                    {flagCounts.get('account_name_unverified') ?? 0}
                  </span>
                </li>
                <li className="flex justify-between gap-2">
                  <Link to="/katalog?flags=register_conflict">Konflikt register/projektdata</Link>
                  <span className="tabular-nums text-muted">
                    {flagCounts.get('register_conflict') ?? 0}
                  </span>
                </li>
              </ul>
              <p className="mt-2 text-sm">
                <Link to="/katalog?origin=new">Visa de {mc.register_new} nya posterna</Link>
              </p>
            </div>
          </div>
        </Section>
      ) : null}

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

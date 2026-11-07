import { Fragment, useMemo, useState } from 'react';
import { Link } from 'react-router';
import { useCatalogFilters } from './useCatalogFilters';
import { useDataset } from '@/data/DatasetContext';
import { isProduct } from '@/data/loader';
import { Badge, OriginBadge, PocBadge, PwdTypeBadge, VerificationBadge } from '@/components/Badge';
import { EntryPanel } from './EntryPanel';
import { ProductCard } from './ProductCard';
import { DetailTable } from './DetailTable';
import { EmptyState, PageHeader } from '@/components/ui';
import {
  applyFilters,
  countActiveFilters,
  DEFAULT_FILTERS,
  deriveEntry,
  serializeFilters,
  strongestPoc,
  type CatalogFilters,
  type EntryDerived,
  type HasKey,
} from '@/lib/filters';
import { buildSearchDocs, buildSearchIndex, searchIds } from '@/lib/search';
import {
  actionLabel,
  fixLabel,
  flagLabel,
  materialTypeLabel,
  pocStatusLabel,
  pwdTypeLabel,
  verificationLabel,
  NO_PASSWORD_VALUES_NOTE,
} from '@/lib/labels';
import { fmtScore } from '@/lib/format';
import { buildExportBundle, downloadBlob, toCsv } from '@/lib/export';
import {
  DataQualityFlag,
  InitialPasswordType,
  MaterialTypeCode,
  PublicPocStatus,
  RecommendedAction,
  VerificationStatus,
} from '@schemas/index';

/** Kryssruta-lista för flerval – ersätter <select multiple>, som kräver Ctrl-klick. */
function CheckList({
  legend,
  options,
  value,
  onChange,
  scroll = false,
}: {
  legend: string;
  options: Array<{ value: string; label: string; n?: number }>;
  value: string[];
  onChange: (v: string[]) => void;
  scroll?: boolean;
}) {
  const toggle = (v: string) =>
    onChange(value.includes(v) ? value.filter((x) => x !== v) : [...value, v]);
  return (
    <fieldset>
      <legend className="font-cond text-xs font-semibold text-muted">
        {legend}
        {value.length ? ` (${value.length})` : ''}
      </legend>
      <ul
        className={`mt-1 space-y-px text-sm ${scroll ? 'max-h-44 overflow-y-auto rounded-[3px] border border-rule p-1' : ''}`}
      >
        {options.map((o) => (
          <li key={o.value}>
            <label className="flex cursor-pointer items-start gap-2 rounded-[3px] px-1 py-0.5 hover:bg-surface-2">
              <input
                type="checkbox"
                className="mt-1 accent-[var(--accent)]"
                checked={value.includes(o.value)}
                onChange={() => toggle(o.value)}
              />
              <span className="min-w-0 grow">{o.label}</span>
              {o.n !== undefined ? <span className="num text-xs text-muted">{o.n}</span> : null}
            </label>
          </li>
        ))}
      </ul>
    </fieldset>
  );
}

/** Ett-av-flera-val som knapprad. */
function Segmented<T extends string>({
  legend,
  options,
  value,
  onChange,
}: {
  legend: string;
  options: Array<{ value: T; label: string }>;
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <fieldset>
      <legend className="font-cond text-xs font-semibold text-muted">{legend}</legend>
      <div className="mt-1 flex flex-wrap gap-1">
        {options.map((o) => (
          <button
            key={o.value}
            type="button"
            className="chip"
            aria-pressed={value === o.value}
            onClick={() => onChange(o.value)}
          >
            {o.label}
          </button>
        ))}
      </div>
    </fieldset>
  );
}

const HAS_LABEL: Record<HasKey, string> = {
  kev: 'CVE i CISA KEV',
  poc: 'Länk till PoC-/hotunderlag',
  cve: 'Verifierad CVE-koppling',
  defaultpw: 'Svag standarduppgift',
  account: 'Namngivet standardkonto',
};
const HAS_ORDER: HasKey[] = ['kev', 'poc', 'cve', 'defaultpw', 'account'];

function hasMatch(k: HasKey, der: EntryDerived): boolean {
  switch (k) {
    case 'cve':
      return der.cveIds.length > 0;
    case 'kev':
      return der.kevCount > 0;
    case 'poc':
      return der.pocLinkCount > 0;
    case 'account':
      return Boolean(der.accountName);
    case 'defaultpw':
      return der.weakPwd;
  }
}

/** Larmprioritet för raden: rött = bekräftat utnyttjande, gult = rapporterad PoC/svag standarduppgift. */
function alarm(der: EntryDerived): 'danger' | 'warn' | null {
  if (der.kevCount > 0 || der.pocStatuses.includes('active_reported')) return 'danger';
  if (der.pocStatuses.includes('poc_reported') || der.weakPwd) return 'warn';
  return null;
}

function Signals({ der }: { der: EntryDerived }) {
  const p = strongestPoc(der.pocStatuses);
  return (
    <span className="flex flex-wrap items-center gap-1">
      {der.kevCount > 0 ? <Badge tone="danger">KEV ×{der.kevCount}</Badge> : null}
      {p === 'active_reported' || p === 'poc_reported' ? <PocBadge status={p} short /> : null}
    </span>
  );
}

function CvssCell({ der }: { der: EntryDerived }) {
  if (!der.cveIds.length) return <span className="text-muted">–</span>;
  const s = der.maxCvss;
  return (
    <span className="num whitespace-nowrap">
      {der.cveIds.length} CVE
      {s !== null ? (
        <span className={s >= 9 ? 'font-semibold text-danger' : 'text-muted'}>
          {' '}
          · max {fmtScore(s)}
        </span>
      ) : null}
    </span>
  );
}

export function CatalogPage() {
  const d = useDataset();
  const [filters, setFilters] = useCatalogFilters();
  const [open, setOpen] = useState<Set<string>>(() => new Set());
  const [allOpen, setAllOpen] = useState(false);
  const [moreFilters, setMoreFilters] = useState(false);
  // Dossiervyn visar en sida i taget; nytt urval börjar om från första sidan.
  const CARD_PAGE = 20;
  const [cardLimit, setCardLimit] = useState(CARD_PAGE);
  const [limitKey, setLimitKey] = useState('');
  const filterKey = serializeFilters(filters).toString();
  if (limitKey !== filterKey) {
    setLimitKey(filterKey);
    setCardLimit(CARD_PAGE);
  }
  const index = useMemo(() => buildSearchIndex(buildSearchDocs(d)), [d]);
  const hits = useMemo(() => searchIds(index, filters.q), [index, filters.q]);
  const rows = useMemo(() => applyFilters(d, d.entries, filters, hits), [d, filters, hits]);
  const derived = useMemo(() => new Map(d.entries.map((e) => [e.id, deriveEntry(d, e)])), [d]);

  const count = <T,>(fn: (e: (typeof d.entries)[number]) => T) => {
    const m = new Map<T, number>();
    for (const e of d.entries) m.set(fn(e), (m.get(fn(e)) ?? 0) + 1);
    return m;
  };
  const vendorCounts = useMemo(
    () => count((e) => (isProduct(e) ? e.vendor_id : '')),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [d],
  );
  const vendorOptions = d.vendors
    .slice()
    .sort((a, b) => a.name.localeCompare(b.name, 'sv'))
    .map((v) => ({ value: v.id, label: v.name, n: vendorCounts.get(v.id) ?? 0 }));
  const categoryOptions = useMemo(() => {
    const counts = new Map<string, number>();
    for (const e of d.entries) counts.set(e.category, (counts.get(e.category) ?? 0) + 1);
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], 'sv'))
      .map(([c, n]) => ({ value: c, label: c, n }));
  }, [d]);
  const regstatusOptions = useMemo(() => {
    const counts = new Map<string, number>();
    for (const e of d.entries) {
      const st = e.register?.source_status_text;
      if (st) counts.set(st, (counts.get(st) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([c, n]) => ({ value: c, label: c, n }));
  }, [d]);
  const actionCounts = count((e) => e.risk.recommended_action);
  const verCounts = count((e) => e.verification_status);
  const flagCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of d.entries) for (const f of e.data_quality_flags) m.set(f, (m.get(f) ?? 0) + 1);
    return m;
  }, [d]);
  const pwdCounts = count((e) => e.credentials?.initial_password_type ?? '');

  const upd = (patch: Partial<CatalogFilters>) => setFilters({ ...filters, ...patch });
  const active = countActiveFilters(filters);
  const advancedActive =
    [
      filters.vendor,
      filters.category,
      filters.flags,
      filters.fix,
      filters.pwdType,
      filters.material,
      filters.regstatus,
    ].filter((l) => l.length).length +
    (filters.poc !== 'any' ? 1 : 0) +
    (filters.docgap !== 'any' ? 1 : 0) +
    (filters.kev !== 'any' ? 1 : 0) +
    (filters.cve ? 1 : 0) +
    (filters.riskType ? 1 : 0);

  const toggleRow = (id: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const isOpen = (id: string) => allOpen || open.has(id);

  const doExport = (fmt: 'csv' | 'json') => {
    const bundle = buildExportBundle(d, rows, filters);
    const stamp = bundle.metadata.exported_at.slice(0, 19).replace(/[:T]/g, '-');
    if (fmt === 'json')
      downloadBlob(
        `ot-iot-katalog-${stamp}.json`,
        JSON.stringify(bundle, null, 2),
        'application/json',
      );
    else downloadBlob(`ot-iot-katalog-${stamp}.csv`, toCsv(bundle), 'text/csv;charset=utf-8');
  };

  const sortBy = (key: CatalogFilters['sort']) =>
    upd(
      filters.sort === key
        ? { dir: filters.dir === 'asc' ? 'desc' : 'asc' }
        : { sort: key, dir: 'asc' },
    );
  const sortTh = (k: CatalogFilters['sort'], children: string, className?: string) => (
    <th
      key={k}
      scope="col"
      className={className}
      aria-sort={
        filters.sort === k ? (filters.dir === 'asc' ? 'ascending' : 'descending') : undefined
      }
    >
      <button
        type="button"
        className="inline-flex items-center gap-1 font-semibold text-muted hover:text-text"
        onClick={() => sortBy(k)}
      >
        {children}
        <span aria-hidden="true" className="text-[10px]">
          {filters.sort === k ? (filters.dir === 'asc' ? '▲' : '▼') : ''}
        </span>
      </button>
    </th>
  );

  return (
    <>
      <PageHeader
        title="Katalog"
        lead={
          <>
            {d.entries.length} produktfamiljer och protokoll. <strong>Tabell</strong> är en tät
            lista där en rad fälls ut. <strong>Detaljtabell</strong> och <strong>Dossier</strong>{' '}
            visar allt per produkt direkt: konto, typ av initiallösenord, sökord, CVE, PoC-underlag,
            setup och åtgärd – som tabell respektive kort. Filtren sparas i adressen och kan delas.
          </>
        }
      />

      <div className="grid grid-cols-1 items-start gap-4 lg:grid-cols-[17rem_minmax(0,1fr)]">
        <form
          className="card space-y-4 p-3 lg:sticky lg:top-16 lg:max-h-[calc(100vh-5rem)] lg:overflow-y-auto"
          role="search"
          aria-label="Filtrera katalogen"
          onSubmit={(e) => e.preventDefault()}
        >
          <div>
            <label htmlFor="q" className="font-cond text-xs font-semibold text-muted">
              Fulltextsökning
            </label>
            <input
              id="q"
              type="search"
              className="input mt-1"
              placeholder="Namn, leverantör, CVE, konto …"
              value={filters.q}
              onChange={(e) => upd({ q: e.target.value })}
            />
          </div>

          <fieldset>
            <legend className="font-cond text-xs font-semibold text-muted">
              Visa endast poster med
            </legend>
            <ul className="mt-1 space-y-px text-sm">
              {HAS_ORDER.map((k) => {
                const n = d.entries.filter((e) => hasMatch(k, derived.get(e.id)!)).length;
                const on = filters.has.includes(k);
                return (
                  <li key={k}>
                    <button
                      type="button"
                      aria-pressed={on}
                      onClick={() =>
                        upd({ has: on ? filters.has.filter((h) => h !== k) : [...filters.has, k] })
                      }
                      className={`flex w-full items-center justify-between gap-2 rounded-[3px] px-2 py-1 text-left ${
                        on ? 'bg-accent text-accent-contrast' : 'hover:bg-surface-2'
                      } ${k === 'kev' ? 'bar-danger' : k === 'poc' || k === 'defaultpw' ? 'bar-warn' : ''}`}
                    >
                      <span>{HAS_LABEL[k]}</span>
                      <span className={`num text-xs ${on ? '' : 'text-muted'}`}>{n}</span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </fieldset>

          <button
            type="button"
            className="btn w-full justify-center lg:hidden"
            aria-expanded={moreFilters}
            aria-controls="filter-more"
            onClick={() => setMoreFilters((v) => !v)}
          >
            {moreFilters ? 'Dölj filter' : 'Fler filter'}
            {active > filters.has.length + (filters.q ? 1 : 0)
              ? ` (${active - filters.has.length - (filters.q ? 1 : 0)} aktiva)`
              : ''}
          </button>
          <div
            id="filter-more"
            className={`${moreFilters ? 'block' : 'hidden'} space-y-4 lg:block`}
          >
            <Segmented
              legend="Typ"
              value={filters.kind}
              onChange={(v) => upd({ kind: v })}
              options={[
                { value: 'all', label: 'Alla' },
                { value: 'product_family', label: 'Produkter' },
                { value: 'protocol_service', label: 'Protokoll' },
              ]}
            />
            <Segmented
              legend="Ursprung"
              value={filters.origin}
              onChange={(v) => upd({ origin: v })}
              options={[
                { value: 'all', label: 'Alla' },
                { value: 'original', label: `Original (${d.manifest.counts.register_original})` },
                { value: 'new', label: `Nya (${d.manifest.counts.register_new})` },
              ]}
            />

            <CheckList
              legend="Rekommenderad åtgärd"
              value={filters.action}
              onChange={(v) => upd({ action: v })}
              options={RecommendedAction.options.map((a) => ({
                value: a,
                label: actionLabel[a],
                n: actionCounts.get(a) ?? 0,
              }))}
            />
            <CheckList
              legend="Verifiering"
              value={filters.verification}
              onChange={(v) => upd({ verification: v })}
              options={VerificationStatus.options
                .filter((s) => (verCounts.get(s) ?? 0) > 0 || filters.verification.includes(s))
                .map((s) => ({ value: s, label: verificationLabel[s], n: verCounts.get(s) ?? 0 }))}
            />
            <CheckList
              legend="Kategori"
              scroll
              value={filters.category}
              onChange={(v) => upd({ category: v })}
              options={categoryOptions}
            />

            <details open={advancedActive > 0}>
              <summary className="cursor-pointer text-sm font-medium">
                Avancerade filter{advancedActive > 0 ? ` (${advancedActive} aktiva)` : ''}
              </summary>
              <div className="mt-3 space-y-4">
                <CheckList
                  legend="Leverantör"
                  scroll
                  value={filters.vendor}
                  onChange={(v) => upd({ vendor: v })}
                  options={vendorOptions}
                />
                <CheckList
                  legend="Typ av initiallösenord"
                  scroll
                  value={filters.pwdType}
                  onChange={(v) => upd({ pwdType: v })}
                  options={InitialPasswordType.options.map((t) => ({
                    value: t,
                    label: pwdTypeLabel[t],
                    n: pwdCounts.get(t) ?? 0,
                  }))}
                />
                <CheckList
                  legend="Luckor i underlaget"
                  scroll
                  value={filters.flags}
                  onChange={(v) => upd({ flags: v })}
                  options={DataQualityFlag.options
                    .filter((f) => (flagCounts.get(f) ?? 0) > 0 || filters.flags.includes(f))
                    .map((f) => ({ value: f, label: flagLabel[f], n: flagCounts.get(f) ?? 0 }))}
                />
                <CheckList
                  legend="Fixstatus"
                  value={filters.fix}
                  onChange={(v) => upd({ fix: v })}
                  options={Object.entries(fixLabel).map(([value, label]) => ({ value, label }))}
                />
                <CheckList
                  legend="PoC-materialtyp"
                  scroll
                  value={filters.material}
                  onChange={(v) => upd({ material: v })}
                  options={MaterialTypeCode.options.map((t) => ({
                    value: t,
                    label: materialTypeLabel[t],
                  }))}
                />
                <CheckList
                  legend="Källstatus i registret"
                  scroll
                  value={filters.regstatus}
                  onChange={(v) => upd({ regstatus: v })}
                  options={regstatusOptions}
                />
                <div>
                  <label htmlFor="f-poc" className="font-cond text-xs font-semibold text-muted">
                    PoC-/exploateringsstatus
                  </label>
                  <select
                    id="f-poc"
                    className="input mt-1"
                    value={filters.poc}
                    onChange={(e) => upd({ poc: e.target.value as CatalogFilters['poc'] })}
                  >
                    <option value="any">Oavsett</option>
                    {PublicPocStatus.options.map((s) => (
                      <option key={s} value={s}>
                        {pocStatusLabel[s]}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label htmlFor="f-kev" className="font-cond text-xs font-semibold text-muted">
                    CISA KEV
                  </label>
                  <select
                    id="f-kev"
                    className="input mt-1"
                    value={filters.kev}
                    onChange={(e) => upd({ kev: e.target.value as CatalogFilters['kev'] })}
                  >
                    <option value="any">Oavsett</option>
                    <option value="yes">Minst en KEV-listad CVE</option>
                    <option value="no">Ingen KEV-listad CVE</option>
                  </select>
                </div>
                <div>
                  <label htmlFor="f-docgap" className="font-cond text-xs font-semibold text-muted">
                    Setupmanual
                  </label>
                  <select
                    id="f-docgap"
                    className="input mt-1"
                    value={filters.docgap}
                    onChange={(e) => upd({ docgap: e.target.value as CatalogFilters['docgap'] })}
                  >
                    <option value="any">Oavsett</option>
                    <option value="verified">Verifierad setupmanual</option>
                    <option value="unverified">Ej verifierad (portal, guide eller saknas)</option>
                  </select>
                </div>
                <div>
                  <label htmlFor="f-cve" className="font-cond text-xs font-semibold text-muted">
                    CVE-id innehåller
                  </label>
                  <input
                    id="f-cve"
                    className="input mt-1"
                    value={filters.cve}
                    onChange={(e) => upd({ cve: e.target.value })}
                    placeholder="CVE-2026-"
                  />
                </div>
                <div>
                  <label htmlFor="f-risk" className="font-cond text-xs font-semibold text-muted">
                    Risktyp innehåller
                  </label>
                  <input
                    id="f-risk"
                    className="input mt-1"
                    value={filters.riskType}
                    onChange={(e) => upd({ riskType: e.target.value })}
                    placeholder="t.ex. autentisering"
                  />
                </div>
              </div>
            </details>
          </div>
        </form>

        <section aria-label="Resultat" className="min-w-0">
          <div className="mb-2 flex flex-wrap items-center gap-2 text-sm">
            <span role="status" aria-live="polite" className="font-medium">
              {rows.length} av {d.entries.length} poster
            </span>
            {active > 0 ? (
              <button type="button" className="btn" onClick={() => setFilters(DEFAULT_FILTERS)}>
                Rensa filter
              </button>
            ) : null}
            <div
              role="group"
              aria-label="Visningsläge"
              className="ml-auto inline-flex overflow-hidden rounded-[3px] border border-border"
            >
              {(
                [
                  ['table', 'Tabell'],
                  ['fields', 'Detaljtabell'],
                  ['cards', 'Dossier'],
                ] as const
              ).map(([v, label]) => (
                <button
                  key={v}
                  type="button"
                  aria-pressed={filters.view === v}
                  onClick={() => upd({ view: v })}
                  className={`px-2.5 py-1 text-sm ${
                    filters.view === v
                      ? 'bg-accent text-accent-contrast'
                      : 'bg-surface text-muted hover:bg-surface-2'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
            <label className="flex items-center gap-2 text-sm">
              <span className="text-muted">Sortera</span>
              <select
                className="input w-auto py-1"
                value={filters.sort}
                onChange={(e) =>
                  upd({ sort: e.target.value as CatalogFilters['sort'], dir: 'asc' })
                }
              >
                <option value="severity">Allvarligast först</option>
                <option value="name">Namn</option>
                <option value="vendor">Leverantör</option>
                <option value="category">Kategori</option>
                <option value="action">Åtgärd</option>
                <option value="verification">Verifiering</option>
              </select>
            </label>
            {filters.view === 'table' ? (
              <button
                type="button"
                className="btn"
                aria-pressed={allOpen}
                onClick={() => {
                  setAllOpen((v) => !v);
                  setOpen(new Set());
                }}
              >
                {allOpen ? 'Fäll ihop alla' : 'Fäll ut alla'}
              </button>
            ) : null}
            <button
              type="button"
              className="btn"
              onClick={() => doExport('csv')}
              disabled={rows.length === 0}
            >
              Exportera CSV
            </button>
            <button
              type="button"
              className="btn"
              onClick={() => doExport('json')}
              disabled={rows.length === 0}
            >
              Exportera JSON
            </button>
          </div>
          <p className="mb-2 text-xs text-muted">{NO_PASSWORD_VALUES_NOTE}</p>

          {rows.length === 0 ? (
            <EmptyState>
              Inga poster matchar filtret. Ta bort ett filter eller{' '}
              <button
                type="button"
                className="underline"
                onClick={() => setFilters(DEFAULT_FILTERS)}
              >
                rensa alla
              </button>
              .
            </EmptyState>
          ) : filters.view === 'fields' ? (
            <DetailTable d={d} rows={rows} derived={derived} />
          ) : filters.view === 'cards' ? (
            <>
              <ul className="grid grid-cols-1 gap-3 2xl:grid-cols-2">
                {rows.slice(0, cardLimit).map((e) => (
                  <li key={e.id}>
                    <ProductCard d={d} e={e} />
                  </li>
                ))}
              </ul>
              {rows.length > cardLimit ? (
                <div className="mt-4 flex flex-wrap items-center justify-center gap-3 text-sm">
                  <span className="text-muted">
                    Visar {cardLimit} av {rows.length}
                  </span>
                  <button
                    type="button"
                    className="btn"
                    onClick={() => setCardLimit((n) => n + CARD_PAGE)}
                  >
                    Visa {Math.min(CARD_PAGE, rows.length - cardLimit)} till
                  </button>
                  <button type="button" className="btn" onClick={() => setCardLimit(rows.length)}>
                    Visa alla
                  </button>
                </div>
              ) : null}
            </>
          ) : (
            <>
              <div className="card hidden md:block">
                <table className="table">
                  <thead>
                    <tr>
                      <th scope="col" className="w-8">
                        <span className="sr-only">Fäll ut</span>
                      </th>
                      {sortTh('name', 'Namn')}
                      {sortTh('category', 'Kategori')}
                      {sortTh('severity', 'CVE')}
                      <th scope="col">Signal</th>
                      <th scope="col">Initiallösenord</th>
                      {sortTh('action', 'Åtgärd')}
                      {sortTh('verification', 'Verifiering', 'hidden 2xl:table-cell')}
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((e) => {
                      const der = derived.get(e.id)!;
                      const expanded = isOpen(e.id);
                      const a = alarm(der);
                      const panelId = `panel-${e.id}`;
                      return (
                        <Fragment key={e.id}>
                          <tr
                            className={`cursor-pointer ${expanded ? '[&>td]:border-b-0 [&>td]:bg-surface-2/60' : ''}`}
                            onClick={(ev) => {
                              if ((ev.target as HTMLElement).closest('a,button')) return;
                              toggleRow(e.id);
                            }}
                          >
                            <td
                              className={
                                a === 'danger' ? 'bar-danger' : a === 'warn' ? 'bar-warn' : ''
                              }
                            >
                              <button
                                type="button"
                                aria-expanded={expanded}
                                aria-controls={panelId}
                                aria-label={`${expanded ? 'Dölj' : 'Visa'} detaljer för ${e.name}`}
                                onClick={() => toggleRow(e.id)}
                                className="grid h-5 w-5 place-items-center rounded-[3px] text-muted hover:bg-surface-2 hover:text-text"
                              >
                                <span
                                  aria-hidden="true"
                                  className={`inline-block transition-transform ${expanded ? 'rotate-90' : ''}`}
                                >
                                  ▸
                                </span>
                              </button>
                            </td>
                            <td className="min-w-[13rem]">
                              <Link
                                to={isProduct(e) ? `/produkt/${e.id}` : `/protokoll/${e.id}`}
                                className="font-medium"
                              >
                                {e.name}
                              </Link>
                              <div className="text-xs text-muted">
                                {der.vendorName ?? 'Protokoll/tjänst'}
                                {e.register ? (
                                  <span className="ml-1.5 font-mono whitespace-nowrap">
                                    {e.register.register_id}
                                  </span>
                                ) : null}
                                {der.origin === 'new' ? (
                                  <span className="ml-1.5">
                                    <OriginBadge origin={der.origin} />
                                  </span>
                                ) : null}
                              </div>
                            </td>
                            <td className="whitespace-nowrap">{e.category}</td>
                            <td>
                              <CvssCell der={der} />
                            </td>
                            <td>
                              <Signals der={der} />
                            </td>
                            <td>
                              {der.pwdType ? (
                                <span className="[&>span]:whitespace-normal">
                                  <PwdTypeBadge type={der.pwdType} />
                                </span>
                              ) : (
                                <span className="text-muted">–</span>
                              )}
                            </td>
                            <td className="text-xs">{actionLabel[e.risk.recommended_action]}</td>
                            <td className="hidden 2xl:table-cell">
                              <VerificationBadge status={e.verification_status} />
                            </td>
                          </tr>
                          {expanded ? (
                            <tr id={panelId}>
                              <td
                                colSpan={8}
                                className={`bg-surface-2/60 px-4 pt-1 pb-4 pl-11 ${a === 'danger' ? 'bar-danger' : a === 'warn' ? 'bar-warn' : ''}`}
                              >
                                <EntryPanel d={d} e={e} />
                              </td>
                            </tr>
                          ) : null}
                        </Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Mobil: kort med utfällbar detalj */}
              <ul className="space-y-2 md:hidden">
                {rows.map((e) => {
                  const der = derived.get(e.id)!;
                  const a = alarm(der);
                  return (
                    <li
                      key={e.id}
                      className={`card p-3 ${a === 'danger' ? 'bar-danger' : a === 'warn' ? 'bar-warn' : ''}`}
                    >
                      <Link
                        to={isProduct(e) ? `/produkt/${e.id}` : `/protokoll/${e.id}`}
                        className="font-medium"
                      >
                        {e.name}
                      </Link>
                      <p className="text-xs text-muted">
                        {der.vendorName ? `${der.vendorName}, ` : ''}
                        {e.category}
                      </p>
                      <div className="mt-1.5 flex flex-wrap items-center gap-1 text-xs">
                        <CvssCell der={der} />
                        <Signals der={der} />
                        {der.pwdType ? <PwdTypeBadge type={der.pwdType} /> : null}
                      </div>
                      <details className="mt-2" open={allOpen}>
                        <summary className="cursor-pointer text-sm text-accent">Detaljer</summary>
                        <div className="mt-2">
                          <EntryPanel d={d} e={e} />
                        </div>
                      </details>
                    </li>
                  );
                })}
              </ul>
            </>
          )}
        </section>
      </div>
    </>
  );
}

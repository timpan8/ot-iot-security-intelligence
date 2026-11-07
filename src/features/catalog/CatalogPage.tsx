import { useMemo } from 'react';
import { Link } from 'react-router';
import { useCatalogFilters } from './useCatalogFilters';
import { useDataset } from '@/data/DatasetContext';
import { isProduct } from '@/data/loader';
import { Badge, VerificationBadge } from '@/components/Badge';
import { EmptyState, PageHeader } from '@/components/ui';
import {
  applyFilters,
  countActiveFilters,
  DEFAULT_FILTERS,
  deriveEntry,
  type CatalogFilters,
} from '@/lib/filters';
import { buildSearchDocs, buildSearchIndex, searchIds } from '@/lib/search';
import { actionLabel, fixLabel, flagLabel, verificationLabel } from '@/lib/labels';
import { buildExportBundle, downloadBlob, toCsv } from '@/lib/export';
import { Category, DataQualityFlag, RecommendedAction, VerificationStatus } from '@schemas/index';

function MultiSelect({
  id,
  label,
  options,
  value,
  onChange,
}: {
  id: string;
  label: string;
  options: Array<{ value: string; label: string }>;
  value: string[];
  onChange: (v: string[]) => void;
}) {
  return (
    <div>
      <label htmlFor={id} className="block text-xs font-medium text-muted">
        {label}
      </label>
      <select
        id={id}
        multiple
        className="input mt-1 h-24 text-sm"
        value={value}
        onChange={(e) => onChange([...e.target.selectedOptions].map((o) => o.value))}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </div>
  );
}

export function CatalogPage() {
  const d = useDataset();
  const [filters, setFilters] = useCatalogFilters();
  const index = useMemo(() => buildSearchIndex(buildSearchDocs(d)), [d]);
  const hits = useMemo(() => searchIds(index, filters.q), [index, filters.q]);
  const rows = useMemo(() => applyFilters(d, d.entries, filters, hits), [d, filters, hits]);

  const vendorOptions = d.vendors
    .slice()
    .sort((a, b) => a.name.localeCompare(b.name, 'sv'))
    .map((v) => ({ value: v.id, label: v.name }));
  const categoryOptions = Category.options.map((c) => ({ value: c, label: c }));
  const verificationOptions = VerificationStatus.options.map((s) => ({
    value: s,
    label: verificationLabel[s],
  }));
  const flagOptions = DataQualityFlag.options.map((f) => ({ value: f, label: flagLabel[f] }));
  const actionOptions = RecommendedAction.options.map((a) => ({ value: a, label: actionLabel[a] }));
  const fixOptions = Object.entries(fixLabel).map(([value, label]) => ({ value, label }));

  const upd = (patch: Partial<CatalogFilters>) => setFilters({ ...filters, ...patch });
  const active = countActiveFilters(filters);

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

  return (
    <>
      <PageHeader
        title="Katalog"
        lead="Sök och filtrera produktfamiljer och protokoll. Filterläget speglas i adressen och kan delas."
      />
      <form
        className="card p-4"
        role="search"
        aria-label="Filtrera katalogen"
        onSubmit={(e) => e.preventDefault()}
      >
        <div className="grid gap-3 md:grid-cols-3">
          <div className="md:col-span-2">
            <label htmlFor="q" className="block text-xs font-medium text-muted">
              Fulltextsökning (namn, leverantör, funktion, risktyp, CVE)
            </label>
            <input
              id="q"
              type="search"
              className="input mt-1"
              placeholder="t.ex. Danfoss, Modbus, CVE-2025-41450"
              value={filters.q}
              onChange={(e) => upd({ q: e.target.value })}
            />
          </div>
          <div>
            <label htmlFor="kind" className="block text-xs font-medium text-muted">
              Typ
            </label>
            <select
              id="kind"
              className="input mt-1"
              value={filters.kind}
              onChange={(e) => upd({ kind: e.target.value as CatalogFilters['kind'] })}
            >
              <option value="all">Alla</option>
              <option value="product_family">Produktfamiljer</option>
              <option value="protocol_service">Protokoll / tjänster</option>
            </select>
          </div>
        </div>
        <details className="mt-3" open={active > 0}>
          <summary className="cursor-pointer text-sm font-medium">
            Fler filter {active > 0 ? `(${active} aktiva)` : ''}
          </summary>
          <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <MultiSelect
              id="f-vendor"
              label="Leverantör"
              options={vendorOptions}
              value={filters.vendor}
              onChange={(v) => upd({ vendor: v })}
            />
            <MultiSelect
              id="f-category"
              label="Kategori"
              options={categoryOptions}
              value={filters.category}
              onChange={(v) => upd({ category: v })}
            />
            <MultiSelect
              id="f-verification"
              label="Verifieringsstatus"
              options={verificationOptions}
              value={filters.verification}
              onChange={(v) => upd({ verification: v })}
            />
            <MultiSelect
              id="f-flags"
              label="Datakvalitetsflagga"
              options={flagOptions}
              value={filters.flags}
              onChange={(v) => upd({ flags: v })}
            />
            <MultiSelect
              id="f-action"
              label="Rekommenderad åtgärd"
              options={actionOptions}
              value={filters.action}
              onChange={(v) => upd({ action: v })}
            />
            <MultiSelect
              id="f-fix"
              label="Fixstatus (matchningar)"
              options={fixOptions}
              value={filters.fix}
              onChange={(v) => upd({ fix: v })}
            />
            <div>
              <label htmlFor="f-cve" className="block text-xs font-medium text-muted">
                CVE-id (delsträng)
              </label>
              <input
                id="f-cve"
                className="input mt-1"
                value={filters.cve}
                onChange={(e) => upd({ cve: e.target.value })}
                placeholder="CVE-2026-"
              />
              <label htmlFor="f-risk" className="mt-2 block text-xs font-medium text-muted">
                Risktyp (text)
              </label>
              <input
                id="f-risk"
                className="input mt-1"
                value={filters.riskType}
                onChange={(e) => upd({ riskType: e.target.value })}
                placeholder="t.ex. autentisering"
              />
            </div>
            <div>
              <label htmlFor="f-kev" className="block text-xs font-medium text-muted">
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
              <label htmlFor="f-sort" className="mt-2 block text-xs font-medium text-muted">
                Sortering
              </label>
              <div className="mt-1 flex gap-2">
                <select
                  id="f-sort"
                  className="input"
                  value={filters.sort}
                  onChange={(e) => upd({ sort: e.target.value as CatalogFilters['sort'] })}
                >
                  <option value="name">Namn</option>
                  <option value="vendor">Leverantör</option>
                  <option value="category">Kategori</option>
                  <option value="verification">Verifiering</option>
                  <option value="action">Åtgärd</option>
                </select>
                <button
                  type="button"
                  className="btn"
                  onClick={() => upd({ dir: filters.dir === 'asc' ? 'desc' : 'asc' })}
                  aria-label="Byt sorteringsriktning"
                >
                  {filters.dir === 'asc' ? '↑' : '↓'}
                </button>
              </div>
            </div>
          </div>
        </details>
        <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
          <span role="status" aria-live="polite">
            {rows.length} av {d.entries.length} poster
          </span>
          <button
            type="button"
            className="btn"
            onClick={() => setFilters(DEFAULT_FILTERS)}
            disabled={active === 0}
          >
            Rensa filter
          </button>
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
      </form>

      {rows.length === 0 ? (
        <div className="mt-4">
          <EmptyState>Inga poster matchar filtret.</EmptyState>
        </div>
      ) : (
        <>
          {/* Desktop-tabell */}
          <div className="mt-4 hidden overflow-x-auto md:block">
            <table className="table card">
              <thead>
                <tr>
                  <th scope="col">Namn</th>
                  <th scope="col">Leverantör</th>
                  <th scope="col">Kategori</th>
                  <th scope="col">Risktyp</th>
                  <th scope="col">CVE</th>
                  <th scope="col">Åtgärd</th>
                  <th scope="col">Verifiering</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => {
                  const der = deriveEntry(d, e);
                  return (
                    <tr key={e.id}>
                      <td>
                        <Link
                          to={isProduct(e) ? `/produkt/${e.id}` : `/protokoll/${e.id}`}
                          className="font-medium"
                        >
                          {e.name}
                        </Link>
                        <div className="text-xs text-muted">{e.function_text}</div>
                      </td>
                      <td>{der.vendorName ?? <span className="text-muted">–</span>}</td>
                      <td>{e.category}</td>
                      <td className="max-w-xs text-xs">
                        {e.risk_summary.type_text ?? (
                          <span className="text-muted">Uppgift saknas</span>
                        )}
                      </td>
                      <td className="text-xs">
                        {der.cveIds.length ? (
                          <>
                            {der.cveIds.slice(0, 3).join(', ')}
                            {der.cveIds.length > 3 ? ` +${der.cveIds.length - 3}` : ''}
                            {der.kevListed ? <Badge tone="danger">KEV</Badge> : null}
                          </>
                        ) : (
                          <span className="text-muted">Ingen verifierad</span>
                        )}
                      </td>
                      <td className="text-xs">{actionLabel[e.risk.recommended_action]}</td>
                      <td>
                        <VerificationBadge status={e.verification_status} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {/* Mobil-kort */}
          <ul className="mt-4 space-y-3 md:hidden">
            {rows.map((e) => {
              const der = deriveEntry(d, e);
              return (
                <li key={e.id} className="card p-3">
                  <Link
                    to={isProduct(e) ? `/produkt/${e.id}` : `/protokoll/${e.id}`}
                    className="font-medium"
                  >
                    {e.name}
                  </Link>
                  <p className="text-xs text-muted">
                    {der.vendorName ? `${der.vendorName} · ` : ''}
                    {e.category} · {e.function_text}
                  </p>
                  <p className="mt-1 text-xs">
                    {e.risk_summary.type_text ?? 'Risktyp: uppgift saknas'}
                  </p>
                  <div className="mt-2 flex flex-wrap gap-1">
                    <VerificationBadge status={e.verification_status} />
                    {der.kevListed ? <Badge tone="danger">KEV</Badge> : null}
                    {der.cveIds.length ? <Badge tone="info">{der.cveIds.length} CVE</Badge> : null}
                    <Badge>{actionLabel[e.risk.recommended_action]}</Badge>
                  </div>
                </li>
              );
            })}
          </ul>
        </>
      )}
    </>
  );
}

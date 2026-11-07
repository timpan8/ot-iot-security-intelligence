import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { useDataset } from '@/data/DatasetContext';
import { Callout, PageHeader, Section } from '@/components/ui';
import { applyFilters, parseFilters, serializeFilters } from '@/lib/filters';
import { buildExportBundle, downloadBlob, toCsv } from '@/lib/export';
import { buildSearchDocs, buildSearchIndex, searchIds } from '@/lib/search';
import { useCatalogFilters } from '@/features/catalog/useCatalogFilters';

export function ExportPage() {
  const d = useDataset();
  const [filters] = useCatalogFilters();
  const [kind, setKind] = useState<'all' | 'product_family' | 'protocol_service'>(filters.kind);
  const effective = useMemo(
    () => parseFilters(serializeFilters({ ...filters, kind })),
    [filters, kind],
  );
  const index = useMemo(() => buildSearchIndex(buildSearchDocs(d)), [d]);
  const rows = useMemo(
    () => applyFilters(d, d.entries, effective, searchIds(index, effective.q)),
    [d, effective, index],
  );

  const run = (fmt: 'csv' | 'json') => {
    const bundle = buildExportBundle(d, rows, effective);
    const stamp = bundle.metadata.exported_at.slice(0, 19).replace(/[:T]/g, '-');
    if (fmt === 'json')
      downloadBlob(
        `ot-iot-export-${stamp}.json`,
        JSON.stringify(bundle, null, 2),
        'application/json',
      );
    else downloadBlob(`ot-iot-export-${stamp}.csv`, toCsv(bundle), 'text/csv;charset=utf-8');
  };

  return (
    <>
      <PageHeader
        title="Export"
        lead="Exportera ett filtrerat urval till CSV eller JSON. Exporten innehåller källdata, exportdatum och metadata om datasetet. Inga fält utanför den publika modellen."
      />
      <div className="space-y-4">
        <Section title="Urval" id="urval">
          <p className="text-sm">
            Aktuellt urval bygger på filtren i adressen (samma parametrar som{' '}
            <Link to={`/katalog?${serializeFilters(effective).toString()}`}>katalogen</Link>).
          </p>
          <label htmlFor="ex-kind" className="mt-3 block text-xs font-medium text-muted">
            Typ
          </label>
          <select
            id="ex-kind"
            className="input mt-1 max-w-xs"
            value={kind}
            onChange={(e) => setKind(e.target.value as typeof kind)}
          >
            <option value="all">Alla</option>
            <option value="product_family">Produktfamiljer</option>
            <option value="protocol_service">Protokoll / tjänster</option>
          </select>
          <p className="mt-3 text-sm" role="status">
            {rows.length} poster i urvalet.
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => run('csv')}
              disabled={rows.length === 0}
            >
              Ladda ned CSV
            </button>
            <button
              type="button"
              className="btn"
              onClick={() => run('json')}
              disabled={rows.length === 0}
            >
              Ladda ned JSON
            </button>
          </div>
        </Section>
        <Section title="Metadata som följer med" id="metadata">
          <ul className="list-disc pl-5 text-sm">
            <li>exported_at – tidpunkt för exporten</li>
            <li>dataset_generated_at – när datasetet genererades ({d.manifest.generated_at})</li>
            <li>
              workbook_sha256 – checksumma för ursprunglig arbetsbok (
              {d.manifest.workbook.sha256.slice(0, 16)}…)
            </li>
            <li>schema_version – {d.manifest.schema_version}</li>
            <li>filter – de aktiva filtren, antal poster och disclaimer</li>
          </ul>
        </Section>
        <Callout tone="info" title="Rådata">
          De validerade JSON-filerna som webbplatsen bygger på finns under <code>data/</code> i
          samma deploy och i repositoryt under <code>public/data/</code>. CSV-celler som börjar med
          formeltecken skyddas mot formelinjektion.
        </Callout>
      </div>
    </>
  );
}

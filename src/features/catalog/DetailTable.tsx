import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Link } from 'react-router';
import { isProduct, type CatalogEntry, type IndexedDataset } from '@/data/loader';
import { Badge, FactorBadge, PocBadge, PwdTypeBadge, VerificationBadge } from '@/components/Badge';
import { SafeLink } from '@/components/SafeLink';
import { fmtScore } from '@/lib/format';
import { actionLabel, flagLabel, orMissing } from '@/lib/labels';
import { strongestPoc, type EntryDerived } from '@/lib/filters';
import { collect, type CveRow, type PocRow } from './collect';

const CVE_PREVIEW = 5;
const STORAGE_KEY = 'otsi-detail-columns';

function host(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return 'länk';
  }
}

function alarm(der: EntryDerived): string {
  if (der.kevCount > 0 || der.pocStatuses.includes('active_reported')) return 'bar-danger';
  if (der.pocStatuses.includes('poc_reported') || der.weakPwd) return 'bar-warn';
  return '';
}

interface Ctx {
  e: CatalogEntry;
  der: EntryDerived;
  cves: CveRow[];
  pocs: PocRow[];
  detail: string;
}

interface Column {
  key: string;
  label: string;
  /** Visas när man inte valt något eget. */
  standard: boolean;
  width: string;
  cell: (c: Ctx) => ReactNode;
}

const Missing = ({ children = 'Uppgift saknas' }: { children?: string }) => (
  <span className="text-xs italic text-muted">{children}</span>
);

/** Valbara kolumner. Produktkolumnen visas alltid och ingår inte här. */
const COLUMNS: Column[] = [
  {
    key: 'konto',
    label: 'Standardkonto och initiallösenord',
    standard: true,
    width: 'min-w-[10rem]',
    cell: ({ e }) => (
      <>
        {e.credentials?.account_name ? (
          <code className="rounded-[3px] bg-surface-2 px-1 py-0.5">
            {e.credentials.account_name}
          </code>
        ) : (
          <Missing>{orMissing(e.credentials?.account_name_text, 'Ej verifierat')}</Missing>
        )}
        {e.credentials ? (
          <div className="mt-1">
            <PwdTypeBadge type={e.credentials.initial_password_type} />
          </div>
        ) : null}
      </>
    ),
  },
  {
    key: 'sokord',
    label: 'Sökord (egen inventering)',
    standard: true,
    width: 'min-w-[8rem]',
    cell: ({ e }) =>
      e.discovery_heuristic.query ? (
        <code className="text-xs [overflow-wrap:anywhere]">{e.discovery_heuristic.query}</code>
      ) : (
        <Missing />
      ),
  },
  {
    key: 'cve',
    label: 'Sårbarheter',
    standard: true,
    width: 'min-w-[11rem]',
    cell: ({ e, cves, detail }) =>
      cves.length === 0 ? (
        <span className="text-xs text-muted">
          {isProduct(e) ? 'Ingen verifierad CVE' : 'Protokoll – inga produkt-CVE'}
        </span>
      ) : (
        <ul className="space-y-0.5 text-xs">
          {cves.slice(0, CVE_PREVIEW).map((r) => (
            <li key={r.cve} className="flex flex-wrap items-center gap-1 whitespace-nowrap">
              <Link to={`/sarbarheter/${r.cve}`} className="font-mono">
                {r.cve}
              </Link>
              {r.score !== null ? (
                <span
                  className={`num ${r.score >= 9 ? 'font-semibold text-danger' : 'text-muted'}`}
                >
                  {fmtScore(r.score)}
                </span>
              ) : null}
              {r.kev ? <Badge tone="danger">KEV</Badge> : null}
            </li>
          ))}
          {cves.length > CVE_PREVIEW ? (
            <li>
              <Link to={detail}>{cves.length - CVE_PREVIEW} till</Link>
            </li>
          ) : null}
        </ul>
      ),
  },
  {
    key: 'poc',
    label: 'PoC-/hotunderlag',
    standard: true,
    width: 'min-w-[11rem]',
    cell: ({ pocs }) =>
      pocs.length === 0 ? (
        <span className="text-xs text-muted">–</span>
      ) : (
        <ul className="space-y-1 text-xs">
          {pocs.map((p) => (
            <li key={p.url}>
              <span className="font-mono">{p.cve}</span>
              <span className="block text-muted">{p.material}</span>
              <SafeLink href={p.url} className="underline">
                {host(p.url)}
              </SafeLink>
            </li>
          ))}
        </ul>
      ),
  },
  {
    key: 'setup',
    label: 'Setup och dokumentation',
    standard: true,
    width: 'min-w-[10rem]',
    cell: ({ e }) => {
      const s = e.setup_documentation;
      return (
        <span className="text-xs">
          {s?.url ? (
            <SafeLink href={s.url} className="underline [overflow-wrap:anywhere]">
              {s.title ?? 'Installationsdokument'}
            </SafeLink>
          ) : (
            <Missing />
          )}
          {s && !s.is_verified_setup_manual ? (
            <span className="block text-warn">Ej verifierad manual</span>
          ) : null}
        </span>
      );
    },
  },
  {
    key: 'atgard',
    label: 'Rekommenderad åtgärd',
    standard: false,
    width: 'min-w-[9rem]',
    cell: ({ e }) => <span className="text-xs">{actionLabel[e.risk.recommended_action]}</span>,
  },
  {
    key: 'cvss',
    label: 'Högsta CVSS',
    standard: false,
    width: 'min-w-[5rem]',
    cell: ({ der }) =>
      der.maxCvss === null ? (
        <span className="text-xs text-muted">–</span>
      ) : (
        <span className={`num ${der.maxCvss >= 9 ? 'font-semibold text-danger' : ''}`}>
          {fmtScore(der.maxCvss)}
        </span>
      ),
  },
  {
    key: 'risk',
    label: 'Riskfaktorer',
    standard: false,
    width: 'min-w-[9rem]',
    cell: ({ e }) => (
      <dl className="grid grid-cols-[auto_auto] items-center justify-start gap-x-2 gap-y-0.5 text-xs">
        <dt className="text-muted">Hot</dt>
        <dd>
          <FactorBadge level={e.risk.threat.level} />
        </dd>
        <dt className="text-muted">Allvarlighet</dt>
        <dd>
          <FactorBadge level={e.risk.severity.level} />
        </dd>
        <dt className="text-muted">OT-konsekvens</dt>
        <dd>
          <FactorBadge level={e.risk.ot_impact.level} />
        </dd>
        <dt className="text-muted">Exponering</dt>
        <dd>
          <FactorBadge level={e.risk.exposure.level} />
        </dd>
      </dl>
    ),
  },
  {
    key: 'risktyp',
    label: 'Risktyp',
    standard: false,
    width: 'min-w-[12rem]',
    cell: ({ e }) =>
      e.risk_summary.type_text ? (
        <span className="clamp-2 text-xs" title={e.risk_summary.type_text}>
          {e.risk_summary.type_text}
        </span>
      ) : (
        <Missing />
      ),
  },
  {
    key: 'verifiering',
    label: 'Verifiering',
    standard: false,
    width: 'min-w-[8rem]',
    cell: ({ e }) => <VerificationBadge status={e.verification_status} />,
  },
  {
    key: 'luckor',
    label: 'Luckor i underlaget',
    standard: false,
    width: 'min-w-[12rem]',
    cell: ({ e }) =>
      e.data_quality_flags.length ? (
        <span className="text-xs text-muted">
          {e.data_quality_flags.map((f) => flagLabel[f] ?? f).join(', ')}
        </span>
      ) : (
        <span className="text-xs text-muted">–</span>
      ),
  },
  {
    key: 'register',
    label: 'Register-ID',
    standard: false,
    width: 'min-w-[8rem]',
    cell: ({ e }) =>
      e.register ? (
        <span className="text-xs">
          <span className="font-mono whitespace-nowrap">{e.register.register_id}</span>
          <span className="block text-muted">
            {e.register.origin === 'new' ? 'Ny i registret' : 'Original'}
          </span>
        </span>
      ) : (
        <span className="text-xs text-muted">–</span>
      ),
  },
];

const STANDARD = COLUMNS.filter((c) => c.standard).map((c) => c.key);
const KNOWN = new Set(COLUMNS.map((c) => c.key));

function readColumns(): string[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return STANDARD;
    const v = JSON.parse(raw) as unknown;
    if (!Array.isArray(v)) return STANDARD;
    return v.filter((k): k is string => typeof k === 'string' && KNOWN.has(k));
  } catch {
    return STANDARD;
  }
}

function storeColumns(cols: string[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(cols));
  } catch {
    /* lagring kan vara blockerad – valet gäller då bara denna visning */
  }
}

function ColumnPicker({
  shown,
  onChange,
}: {
  shown: string[];
  onChange: (next: string[]) => void;
}) {
  const ref = useRef<HTMLDetailsElement>(null);
  // Stäng listan vid klick utanför eller Escape
  useEffect(() => {
    const close = (ev: MouseEvent | KeyboardEvent) => {
      const el = ref.current;
      if (!el?.open) return;
      if (ev instanceof KeyboardEvent ? ev.key === 'Escape' : !el.contains(ev.target as Node))
        el.open = false;
    };
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', close);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('keydown', close);
    };
  }, []);

  const toggle = (k: string) =>
    onChange(shown.includes(k) ? shown.filter((x) => x !== k) : [...shown, k]);
  const isStandard = shown.length === STANDARD.length && STANDARD.every((k) => shown.includes(k));

  return (
    <details ref={ref} className="relative">
      <summary className="btn cursor-pointer">
        Kolumner ({shown.length + 1} av {COLUMNS.length + 1})
      </summary>
      <div className="card absolute right-0 z-30 mt-1 w-72 p-3 shadow-lg">
        <p className="font-cond text-xs font-semibold text-muted">Visa i tabellen</p>
        <ul className="mt-1 space-y-px text-sm">
          <li>
            <label className="flex items-center gap-2 px-1 py-0.5 text-muted">
              <input type="checkbox" checked disabled />
              Produkt (visas alltid)
            </label>
          </li>
          {COLUMNS.map((c) => (
            <li key={c.key}>
              <label className="flex cursor-pointer items-center gap-2 rounded-[3px] px-1 py-0.5 hover:bg-surface-2">
                <input
                  type="checkbox"
                  className="accent-[var(--accent)]"
                  checked={shown.includes(c.key)}
                  onChange={() => toggle(c.key)}
                />
                {c.label}
              </label>
            </li>
          ))}
        </ul>
        <div className="mt-3 flex flex-wrap gap-2 border-t border-rule pt-3">
          <button
            type="button"
            className="btn"
            onClick={() => onChange(STANDARD)}
            disabled={isStandard}
          >
            Återställ standard
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => onChange(COLUMNS.map((c) => c.key))}
            disabled={shown.length === COLUMNS.length}
          >
            Visa alla
          </button>
        </div>
      </div>
    </details>
  );
}

/**
 * Samma fält som dossiervyn, en rad per produkt: konto och lösenordstyp
 * (aldrig värde), sökord för egen inventering, CVE, PoC-underlag och setup.
 * Kolumnerna är valbara; valet sparas i webbläsaren.
 */
export function DetailTable({
  d,
  rows,
  derived,
}: {
  d: IndexedDataset;
  rows: CatalogEntry[];
  derived: Map<string, EntryDerived>;
}) {
  const [shown, setShown] = useState<string[]>(readColumns);
  const update = (next: string[]) => {
    setShown(next);
    storeColumns(next);
  };
  const cols = COLUMNS.filter((c) => shown.includes(c.key));
  const showActionUnderName = !shown.includes('atgard');

  return (
    <>
      <div className="mb-2 flex justify-end">
        <ColumnPicker shown={shown} onChange={update} />
      </div>
      <div className="card overflow-x-auto">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Produkt</th>
              {cols.map((c) => (
                <th key={c.key} scope="col">
                  {c.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => {
              const der = derived.get(e.id)!;
              const { cves, pocs } = collect(d, e);
              const detail = isProduct(e) ? `/produkt/${e.id}` : `/protokoll/${e.id}`;
              const poc = strongestPoc(der.pocStatuses);
              const ctx: Ctx = { e, der, cves, pocs, detail };
              return (
                <tr key={e.id}>
                  <td className={`min-w-[11rem] ${alarm(der)}`}>
                    <Link to={detail} className="font-medium">
                      {e.name}
                    </Link>
                    <div className="text-xs text-muted">
                      {der.vendorName ?? 'Protokoll/tjänst'}, {e.category}
                    </div>
                    {showActionUnderName ? (
                      <div className="mt-1 text-xs">{actionLabel[e.risk.recommended_action]}</div>
                    ) : null}
                    <div className="mt-1 flex flex-wrap gap-1">
                      {der.kevCount > 0 ? <Badge tone="danger">KEV ×{der.kevCount}</Badge> : null}
                      {poc === 'active_reported' || poc === 'poc_reported' ? (
                        <PocBadge status={poc} short />
                      ) : null}
                    </div>
                  </td>
                  {cols.map((c) => (
                    <td key={c.key} className={c.width}>
                      {c.cell(ctx)}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

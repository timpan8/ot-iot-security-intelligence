import { Link } from 'react-router';
import { isProduct, type CatalogEntry, type IndexedDataset } from '@/data/loader';
import { Badge, OriginBadge, PocBadge, VerificationBadge } from '@/components/Badge';
import { fmtScore } from '@/lib/format';
import { deriveEntry, strongestPoc, type EntryDerived } from '@/lib/filters';
import { EntryPanel } from './EntryPanel';

/** Larmprioritet: rött = bekräftat utnyttjande, gult = rapporterad PoC/svag standarduppgift. */
function alarm(der: EntryDerived): 'danger' | 'warn' | null {
  if (der.kevCount > 0 || der.pocStatuses.includes('active_reported')) return 'danger';
  if (der.pocStatuses.includes('poc_reported') || der.weakPwd) return 'warn';
  return null;
}

/**
 * En produkt som en dossier: namn, leverantör och de signaler som avgör
 * brådskan högst upp, allt dokumenterat under. Gjord för att läsas, inte klickas.
 */
export function ProductCard({ d, e }: { d: IndexedDataset; e: CatalogEntry }) {
  const der = deriveEntry(d, e);
  const a = alarm(der);
  const poc = strongestPoc(der.pocStatuses);
  const detail = isProduct(e) ? `/produkt/${e.id}` : `/protokoll/${e.id}`;

  return (
    <article
      className={`card overflow-hidden ${a === 'danger' ? 'bar-danger' : a === 'warn' ? 'bar-warn' : ''}`}
    >
      <header className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 border-b border-rule bg-surface-2/50 px-4 py-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <Link to={detail} className="text-lg leading-tight font-semibold">
              {e.name}
            </Link>
            {der.origin === 'new' ? <OriginBadge origin={der.origin} /> : null}
          </div>
          <p className="mt-0.5 text-sm text-muted">
            {der.vendorName ?? 'Protokoll/tjänst'} · {e.category}
            {e.register ? (
              <>
                {' '}
                · <span className="font-mono">{e.register.register_id}</span>
              </>
            ) : null}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {der.kevCount > 0 ? <Badge tone="danger">KEV ×{der.kevCount}</Badge> : null}
          {poc === 'active_reported' || poc === 'poc_reported' ? (
            <PocBadge status={poc} short />
          ) : null}
          {der.maxCvss !== null ? (
            <span
              className={`num rounded-[3px] border px-1.5 py-0.5 text-xs ${
                der.maxCvss >= 9
                  ? 'border-danger/40 bg-danger-bg text-danger'
                  : der.maxCvss >= 7
                    ? 'border-warn/40 bg-warn-bg text-warn'
                    : 'border-border text-muted'
              }`}
            >
              CVSS {fmtScore(der.maxCvss)}
            </span>
          ) : null}
          <VerificationBadge status={e.verification_status} />
        </div>
      </header>
      <div className="px-4 py-3">
        <EntryPanel d={d} e={e} hideVerification />
      </div>
    </article>
  );
}

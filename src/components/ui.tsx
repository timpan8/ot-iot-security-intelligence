import type { ReactNode } from 'react';
import { MISSING } from '@/lib/labels';

export function Section({
  title,
  children,
  id,
  description,
}: {
  title: string;
  children: ReactNode;
  id?: string;
  description?: string;
}) {
  return (
    <section id={id} aria-labelledby={id ? `${id}-h` : undefined} className="card p-4">
      <h2 id={id ? `${id}-h` : undefined} className="text-base font-semibold">
        {title}
      </h2>
      {description ? <p className="mt-1 text-sm text-muted">{description}</p> : null}
      <div className="mt-3">{children}</div>
    </section>
  );
}

export function Unknown({ children = MISSING }: { children?: ReactNode }) {
  return <span className="italic text-muted">{children}</span>;
}

export function Value({
  value,
  fallback,
}: {
  value: string | null | undefined;
  fallback?: string;
}) {
  if (value === null || value === undefined || value === '') return <Unknown>{fallback}</Unknown>;
  return <>{value}</>;
}

export function DefList({ items }: { items: Array<[string, ReactNode]> }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-[minmax(10rem,14rem)_1fr]">
      {items.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="font-medium text-muted">{k}</dt>
          <dd className="break-words">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Callout({
  tone,
  title,
  children,
}: {
  tone: 'warn' | 'info' | 'danger' | 'ok';
  title: string;
  children: ReactNode;
}) {
  const cls = {
    warn: 'bg-warn-bg text-warn border-warn/40',
    info: 'bg-info-bg text-info border-info/40',
    danger: 'bg-danger-bg text-danger border-danger/40',
    ok: 'bg-ok-bg text-ok border-ok/40',
  }[tone];
  return (
    <div role="note" className={`rounded-[4px] border p-3 text-sm ${cls}`}>
      <p className="font-semibold">{title}</p>
      <div className="mt-1">{children}</div>
    </div>
  );
}

export function StatTile({
  label,
  value,
  hint,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
}) {
  return (
    <div className="card p-3">
      <p className="text-sm text-muted">{label}</p>
      <p className="num mt-0.5 text-2xl font-semibold">{value}</p>
      {hint ? <p className="mt-1 text-xs text-muted">{hint}</p> : null}
    </div>
  );
}

export function PageHeader({ title, lead }: { title: string; lead?: ReactNode }) {
  return (
    <header className="mb-4">
      <h1 className="text-2xl font-semibold sm:text-[1.75rem]">{title}</h1>
      {lead ? <div className="mt-1 max-w-3xl text-sm text-muted">{lead}</div> : null}
    </header>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <p className="rounded-[4px] border border-dashed border-border p-4 text-sm text-muted">
      {children}
    </p>
  );
}

import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { useDataset } from '@/data/DatasetContext';
import { isProduct } from '@/data/loader';
import { Badge, OriginBadge, PwdTypeBadge, VerificationBadge } from '@/components/Badge';
import { SafeLink } from '@/components/SafeLink';
import { Callout, EmptyState, PageHeader, StatTile } from '@/components/ui';
import { NO_PASSWORD_VALUES_NOTE, pwdTypeLabel } from '@/lib/labels';
import { accountsToCsv, buildAccountBundle, downloadBlob } from '@/lib/export';
import { InitialPasswordType, type InitialPasswordType as TPwd } from '@schemas/index';

/**
 * Sammanställning av dokumenterade kontonamn och typ av initiallösenord per post.
 * Underlaget innehåller inga lösenordsvärden – bara typ, status och bytekrav.
 */
export function AccountsPage() {
  const d = useDataset();
  const [params, setParams] = useSearchParams();
  const pwdType = params.get('pwdType') ?? 'all';
  const named = params.get('named') === '1';
  const [q, setQ] = useState('');

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return d.credentialEntries.filter((e) => {
      const c = e.credentials!;
      if (pwdType !== 'all' && c.initial_password_type !== pwdType) return false;
      if (named && !c.account_name) return false;
      if (needle) {
        const hay =
          `${e.name} ${e.register?.register_id ?? ''} ${c.account_name ?? ''} ${c.account_status_text ?? ''}`.toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
  }, [d, pwdType, named, q]);

  const counts = useMemo(() => {
    const m = new Map<TPwd, number>();
    for (const e of d.credentialEntries)
      m.set(
        e.credentials!.initial_password_type,
        (m.get(e.credentials!.initial_password_type) ?? 0) + 1,
      );
    return m;
  }, [d]);
  const namedCount = d.credentialEntries.filter((e) => e.credentials!.account_name).length;
  const dangerous = d.credentialEntries.filter(
    (e) =>
      e.credentials!.initial_password_type === 'hardcoded_in_affected_version' ||
      e.credentials!.initial_password_type === 'predictable_builtin_mechanism',
  ).length;
  const shared = d.credentialEntries.filter(
    (e) => e.credentials!.initial_password_type === 'shared_default_documented',
  ).length;

  const setParam = (k: string, v: string | null) => {
    const next = new URLSearchParams(params);
    if (v === null || v === '' || v === 'all' || v === '0') next.delete(k);
    else next.set(k, v);
    setParams(next, { replace: true });
  };

  const doExport = (fmt: 'csv' | 'json') => {
    const bundle = buildAccountBundle(d, rows, Object.fromEntries(params.entries()));
    const stamp = bundle.metadata.exported_at.slice(0, 19).replace(/[:T]/g, '-');
    if (fmt === 'json')
      downloadBlob(
        `ot-iot-konton-${stamp}.json`,
        JSON.stringify(bundle, null, 2),
        'application/json',
      );
    else
      downloadBlob(`ot-iot-konton-${stamp}.csv`, accountsToCsv(bundle), 'text/csv;charset=utf-8');
  };

  return (
    <>
      <PageHeader
        title="Konton och initiallösenord"
        lead="Sammanställning per post av dokumenterat kontonamn, typ av initialt/fabrikslösenord, bytekrav och källor, enligt 125-postregistret. Inga lösenordsvärden finns i underlaget."
      />
      <Callout tone="info" title="Så läses tabellen">
        <ul className="list-disc pl-5">
          <li>{NO_PASSWORD_VALUES_NOTE}</li>
          <li>
            Ett <strong>gemensamt standardlösenord</strong> skiljer sig från ett{' '}
            <strong>enhetsunikt initiallösenord</strong> och från ett lösenord som{' '}
            <strong>installatören själv skapar</strong>.
          </li>
          <li>
            <strong>Hårdkodade eller förutsägbara</strong> autentiseringsmekanismer kan kräva
            firmwareåtgärd eller utbyte – inte bara lösenordsbyte.
          </li>
          <li>Ett dokumenterat kontonamn bevisar inte att ett standardlösenord finns.</li>
        </ul>
      </Callout>

      <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatTile label="Poster med konto-/lösenordsstatus" value={d.credentialEntries.length} />
        <StatTile
          label="Namngivna konton"
          value={namedCount}
          hint="Kontonamn dokumenterat i källa"
        />
        <StatTile
          label="Gemensamt standardlösenord dokumenterat"
          value={shared}
          hint="Byt före skyddad drift"
        />
        <StatTile
          label="Hårdkodad / förutsägbar mekanism"
          value={dangerous}
          hint="Kräver firmwareåtgärd eller utbyte"
        />
      </div>

      <form
        className="card mt-4 grid gap-3 p-4 md:grid-cols-3"
        role="search"
        aria-label="Filtrera konton"
        onSubmit={(e) => e.preventDefault()}
      >
        <div>
          <label htmlFor="aq" className="block text-xs font-medium text-muted">
            Sök (namn, register-ID, kontonamn)
          </label>
          <input
            id="aq"
            type="search"
            className="input mt-1"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <div>
          <label htmlFor="apwd" className="block text-xs font-medium text-muted">
            Typ av initiallösenord
          </label>
          <select
            id="apwd"
            className="input mt-1"
            value={pwdType}
            onChange={(e) => setParam('pwdType', e.target.value)}
          >
            <option value="all">Alla typer</option>
            {InitialPasswordType.options.map((t) => (
              <option key={t} value={t}>
                {pwdTypeLabel[t]} ({counts.get(t) ?? 0})
              </option>
            ))}
          </select>
        </div>
        <div className="flex flex-col justify-end gap-2">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={named}
              onChange={(e) => setParam('named', e.target.checked ? '1' : null)}
            />
            Endast namngivna konton
          </label>
          <div className="flex flex-wrap gap-2 text-sm">
            <span role="status" aria-live="polite">
              {rows.length} av {d.credentialEntries.length} poster
            </span>
            <button
              type="button"
              className="btn"
              onClick={() => doExport('csv')}
              disabled={!rows.length}
            >
              Exportera CSV
            </button>
            <button
              type="button"
              className="btn"
              onClick={() => doExport('json')}
              disabled={!rows.length}
            >
              Exportera JSON
            </button>
          </div>
        </div>
      </form>

      {rows.length === 0 ? (
        <div className="mt-4">
          <EmptyState>Inga poster matchar.</EmptyState>
        </div>
      ) : (
        <div className="mt-4 overflow-x-auto">
          <table className="table card">
            <thead>
              <tr>
                <th scope="col">Post</th>
                <th scope="col">Kontonamn</th>
                <th scope="col">Typ av initiallösenord</th>
                <th scope="col">Byte / initial kontokonfiguration</th>
                <th scope="col">Källor</th>
                <th scope="col">Verifiering</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => {
                const c = e.credentials!;
                const srcs = [c.account_source_id, c.password_status_source_id]
                  .map((id) => (id ? d.sourceById.get(id) : undefined))
                  .filter((s): s is NonNullable<typeof s> => Boolean(s));
                return (
                  <tr key={e.id}>
                    <td className="text-sm">
                      <Link
                        to={isProduct(e) ? `/produkt/${e.id}#konton` : `/protokoll/${e.id}#konton`}
                        className="font-medium"
                      >
                        {e.name}
                      </Link>
                      <div className="mt-1 flex flex-wrap items-center gap-1 text-xs text-muted">
                        {e.register ? (
                          <>
                            <OriginBadge origin={e.register.origin} />
                            <span className="font-mono">{e.register.register_id}</span>
                          </>
                        ) : null}
                        <span>{e.category}</span>
                      </div>
                    </td>
                    <td className="text-sm">
                      {c.account_name ? (
                        <code>{c.account_name}</code>
                      ) : (
                        <span className="italic text-muted">
                          {c.account_name_text ?? 'Ej verifierat'}
                        </span>
                      )}
                      {c.account_scope_text ? (
                        <div className="max-w-[14rem] text-xs text-muted">
                          {c.account_scope_text}
                        </div>
                      ) : null}
                    </td>
                    <td>
                      <PwdTypeBadge type={c.initial_password_type} />
                    </td>
                    <td className="max-w-sm text-xs">
                      {c.change_requirement_text ?? (
                        <span className="text-muted">Uppgift saknas</span>
                      )}
                    </td>
                    <td className="text-xs">
                      {srcs.length ? (
                        <ul className="space-y-0.5">
                          {[...new Map(srcs.map((s) => [s.id, s])).values()].map((s) => (
                            <li key={s.id}>
                              <SafeLink href={s.url}>{s.title}</SafeLink>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <span className="text-muted">Ingen källa</span>
                      )}
                    </td>
                    <td>
                      <VerificationBadge status={c.verification_status} />
                      {c.initial_password_type === 'unknown_unverified' ? (
                        <div className="mt-1">
                          <Badge>Okänt ≠ säkert</Badge>
                        </div>
                      ) : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

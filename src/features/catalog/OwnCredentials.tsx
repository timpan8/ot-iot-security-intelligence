import { useState } from 'react';
import { readOwnCreds, writeOwnCreds, type OwnCreds } from './own-creds-store';

export function OwnCredentialsCell({ id, name }: { id: string; name: string }) {
  const [creds, setCreds] = useState<OwnCreds | null>(() => readOwnCreds(id));
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<OwnCreds>({ u: '', p: '' });

  const startEdit = () => {
    setDraft(creds ?? { u: '', p: '' });
    setEditing(true);
  };
  const save = () => {
    const next: OwnCreds = { u: draft.u.trim(), p: draft.p };
    const stored = next.u || next.p ? next : null;
    writeOwnCreds(id, stored);
    setCreds(stored);
    setEditing(false);
  };
  const remove = () => {
    writeOwnCreds(id, null);
    setCreds(null);
    setEditing(false);
  };

  if (editing) {
    return (
      <form
        className="space-y-1"
        onSubmit={(e) => {
          e.preventDefault();
          save();
        }}
      >
        <label className="block">
          <span className="sr-only">Användarnamn för {name}</span>
          <input
            className="input py-1 text-xs"
            placeholder="Användarnamn"
            autoComplete="off"
            value={draft.u}
            onChange={(e) => setDraft((d) => ({ ...d, u: e.target.value }))}
          />
        </label>
        <label className="block">
          <span className="sr-only">Lösenord för {name}</span>
          <input
            className="input py-1 text-xs"
            placeholder="Lösenord"
            autoComplete="off"
            value={draft.p}
            onChange={(e) => setDraft((d) => ({ ...d, p: e.target.value }))}
          />
        </label>
        <div className="flex flex-wrap gap-1">
          <button type="submit" className="btn btn-primary px-2 py-0.5 text-xs">
            Spara
          </button>
          <button
            type="button"
            className="btn px-2 py-0.5 text-xs"
            onClick={() => setEditing(false)}
          >
            Avbryt
          </button>
          {creds ? (
            <button type="button" className="btn px-2 py-0.5 text-xs" onClick={remove}>
              Ta bort
            </button>
          ) : null}
        </div>
      </form>
    );
  }

  if (!creds) {
    return (
      <button
        type="button"
        className="text-xs text-accent hover:underline"
        onClick={startEdit}
        aria-label={`Lägg till egna inloggningsuppgifter för ${name}`}
      >
        + Lägg till
      </button>
    );
  }

  return (
    <div className="flex items-start justify-between gap-2">
      <dl className="min-w-0 text-xs">
        {creds.u ? (
          <div className="flex gap-1">
            <dt className="text-muted">Användare:</dt>
            <dd className="[overflow-wrap:anywhere]">
              <code>{creds.u}</code>
            </dd>
          </div>
        ) : null}
        {creds.p ? (
          <div className="flex gap-1">
            <dt className="text-muted">Lösenord:</dt>
            <dd className="[overflow-wrap:anywhere]">
              <code>{creds.p}</code>
            </dd>
          </div>
        ) : null}
      </dl>
      <button
        type="button"
        className="shrink-0 text-xs text-accent hover:underline"
        onClick={startEdit}
        aria-label={`Redigera egna inloggningsuppgifter för ${name}`}
      >
        Ändra
      </button>
    </div>
  );
}

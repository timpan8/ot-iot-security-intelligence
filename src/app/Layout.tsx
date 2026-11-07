import { useEffect, useState } from 'react';
import { NavLink, Outlet } from 'react-router';
import { applyTheme, readStoredTheme, storeTheme, systemTheme, type Theme } from './theme';
import { useDatasetState } from '@/data/DatasetContext';

/** Menyn är grupperad efter uppgift: hitta → bedöma → underlag. */
const NAV: Array<Array<{ to: string; label: string }>> = [
  [
    { to: '/', label: 'Översikt' },
    { to: '/katalog', label: 'Katalog' },
    { to: '/sarbarheter', label: 'Sårbarheter' },
    { to: '/bulletiner', label: 'Bulletiner' },
  ],
  [
    { to: '/prioritering', label: 'Prioritering' },
    { to: '/konton', label: 'Konton' },
    { to: '/atgarder', label: 'Åtgärder' },
  ],
  [
    { to: '/datakvalitet', label: 'Datakvalitet' },
    { to: '/export', label: 'Export' },
    { to: '/om', label: 'Om' },
  ],
];

export function Layout() {
  const [theme, setTheme] = useState<Theme>(() => readStoredTheme() ?? systemTheme());
  const [menuOpen, setMenuOpen] = useState(false);
  const ds = useDatasetState();

  useEffect(() => applyTheme(theme), [theme]);

  const toggle = () => {
    const next: Theme = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    storeTheme(next);
  };

  return (
    <div className="min-h-screen flex flex-col">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-accent focus:px-3 focus:py-2 focus:text-accent-contrast"
      >
        Hoppa till innehåll
      </a>
      <header className="sticky top-0 z-20 border-b border-border bg-surface">
        <div className="mx-auto flex max-w-[90rem] items-center gap-4 px-4 py-2">
          <NavLink to="/" className="flex shrink-0 items-center gap-2 text-text no-underline">
            <span
              aria-hidden="true"
              className="grid h-6 w-6 place-items-center rounded-[3px] bg-accent font-cond text-[11px] font-semibold text-accent-contrast"
            >
              OT
            </span>
            <span className="font-cond text-[15px] font-semibold leading-tight">
              OT/IoT Security Intelligence
            </span>
          </NavLink>
          <nav
            id="primary-nav"
            aria-label="Huvudnavigation"
            className={`${menuOpen ? 'block' : 'hidden'} absolute inset-x-0 top-full border-b border-border bg-surface lg:static lg:block lg:border-0 lg:bg-transparent`}
          >
            <ul className="flex flex-col gap-0.5 px-2 py-2 lg:flex-row lg:items-center lg:p-0">
              {NAV.map((group, gi) => (
                <li
                  key={gi}
                  className={
                    gi > 0
                      ? 'mt-1 border-t border-rule pt-1 lg:mt-0 lg:ml-2 lg:border-t-0 lg:border-l lg:pt-0 lg:pl-2'
                      : ''
                  }
                >
                  <ul className="flex flex-col gap-0.5 lg:flex-row">
                    {group.map((n) => (
                      <li key={n.to}>
                        <NavLink
                          to={n.to}
                          end={n.to === '/'}
                          onClick={() => setMenuOpen(false)}
                          className={({ isActive }) =>
                            `block rounded-[3px] px-2.5 py-1 text-sm no-underline ${
                              isActive
                                ? 'bg-accent text-accent-contrast'
                                : 'text-text hover:bg-surface-2'
                            }`
                          }
                        >
                          {n.label}
                        </NavLink>
                      </li>
                    ))}
                  </ul>
                </li>
              ))}
            </ul>
          </nav>
          <div className="ml-auto flex items-center gap-2">
            <button
              type="button"
              className="btn"
              onClick={toggle}
              aria-pressed={theme === 'dark'}
              title={theme === 'dark' ? 'Byt till ljust tema' : 'Byt till mörkt tema'}
            >
              {theme === 'dark' ? 'Ljust' : 'Mörkt'}
            </button>
            <button
              type="button"
              className="btn lg:hidden"
              aria-expanded={menuOpen}
              aria-controls="primary-nav"
              onClick={() => setMenuOpen((o) => !o)}
            >
              Meny
            </button>
          </div>
        </div>
      </header>
      <main id="main" className="mx-auto w-full max-w-[90rem] flex-1 px-4 py-5">
        <Outlet />
      </main>
      <footer className="border-t border-border bg-surface">
        <div className="mx-auto max-w-[90rem] px-4 py-4 text-xs text-muted">
          <p>
            Publik produkt- och hotkunskapsbas. Innehåller inga anläggningsunika uppgifter. Frånvaro
            av CVE är inte bevis för frånvaro av sårbarheter. Ingen exploateringsvägledning.
          </p>
          {ds.status === 'ready' ? (
            <p className="mt-1">
              Data genererad {ds.data.manifest.generated_at.slice(0, 16).replace('T', ' ')} UTC ·
              arbetsbok sha256 {ds.data.manifest.workbook.sha256.slice(0, 12)}… · schema{' '}
              {ds.data.manifest.schema_version}
            </p>
          ) : null}
        </div>
      </footer>
    </div>
  );
}

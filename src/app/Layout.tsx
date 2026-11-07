import { useEffect, useState } from 'react';
import { NavLink, Outlet } from 'react-router';
import { applyTheme, readStoredTheme, storeTheme, systemTheme, type Theme } from './theme';
import { useDatasetState } from '@/data/DatasetContext';

const NAV: Array<{ to: string; label: string }> = [
  { to: '/', label: 'Översikt' },
  { to: '/katalog', label: 'Katalog' },
  { to: '/sarbarheter', label: 'Sårbarheter' },
  { to: '/bulletiner', label: 'Bulletiner' },
  { to: '/prioritering', label: 'Prioritering' },
  { to: '/atgarder', label: 'Åtgärder' },
  { to: '/datakvalitet', label: 'Datakvalitet' },
  { to: '/export', label: 'Export' },
  { to: '/om', label: 'Om / metodik' },
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
      <header className="border-b border-border bg-surface">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-3 px-4 py-3">
          <NavLink to="/" className="flex items-center gap-2 no-underline text-text">
            <span aria-hidden="true" className="inline-block h-7 w-7 rounded-md bg-accent" />
            <span className="font-semibold leading-tight">
              OT/IoT Security Intelligence
              <span className="block text-xs font-normal text-muted">
                Publik kunskapsbas · defensiv
              </span>
            </span>
          </NavLink>
          <div className="flex items-center gap-2">
            <button type="button" className="btn" onClick={toggle} aria-pressed={theme === 'dark'}>
              {theme === 'dark' ? 'Ljust tema' : 'Mörkt tema'}
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
        <nav
          id="primary-nav"
          aria-label="Huvudnavigation"
          className={`${menuOpen ? 'block' : 'hidden'} border-t border-border lg:block`}
        >
          <ul className="mx-auto flex max-w-7xl flex-col gap-1 px-2 py-2 lg:flex-row lg:flex-wrap lg:px-4">
            {NAV.map((n) => (
              <li key={n.to}>
                <NavLink
                  to={n.to}
                  end={n.to === '/'}
                  onClick={() => setMenuOpen(false)}
                  className={({ isActive }) =>
                    `block rounded-md px-3 py-1.5 text-sm no-underline ${
                      isActive ? 'bg-accent text-accent-contrast' : 'text-text hover:bg-surface-2'
                    }`
                  }
                >
                  {n.label}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
      </header>
      <main id="main" className="mx-auto w-full max-w-7xl flex-1 px-4 py-6">
        <Outlet />
      </main>
      <footer className="border-t border-border bg-surface">
        <div className="mx-auto max-w-7xl px-4 py-4 text-xs text-muted">
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

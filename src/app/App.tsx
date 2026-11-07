import {
  createHashRouter,
  RouterProvider,
  useRouteError,
  isRouteErrorResponse,
  Link,
  Navigate,
  useLocation,
} from 'react-router';
import { DatasetProvider, useDatasetState } from '@/data/DatasetContext';
import { Layout } from './Layout';
import { DashboardPage } from '@/features/dashboard/DashboardPage';
import { CatalogPage } from '@/features/catalog/CatalogPage';
import { ProductPage } from '@/features/detail/ProductPage';
import { ProtocolPage } from '@/features/detail/ProtocolPage';
import { VulnerabilitiesPage } from '@/features/vulnerabilities/VulnerabilitiesPage';
import { VulnerabilityPage } from '@/features/vulnerabilities/VulnerabilityPage';
import { AdvisoriesPage } from '@/features/advisories/AdvisoriesPage';
import { AdvisoryPage } from '@/features/advisories/AdvisoryPage';
import { DataQualityPage } from '@/features/data-quality/DataQualityPage';
import { ControlsPage } from '@/features/controls/ControlsPage';
import { AboutPage } from '@/features/about/AboutPage';
import { PrioritizationPage } from '@/features/prioritization/PrioritizationPage';
import { ExportPage } from '@/features/export/ExportPage';
import { AccountsPage } from '@/features/accounts/AccountsPage';
import { Callout } from '@/components/ui';

function DataGate({ children }: { children: React.ReactNode }) {
  const s = useDatasetState();
  if (s.status === 'loading') {
    return (
      <p role="status" className="text-sm text-muted">
        Läser in kunskapsbasen …
      </p>
    );
  }
  if (s.status === 'error') {
    return (
      <Callout tone="danger" title="Kunskapsbasen kunde inte läsas in">
        <p>{s.message}</p>
        <p className="mt-2">
          Datafilerna genereras av <code>npm run data:all</code> och valideras mot schemat innan
          publicering. Kontrollera att <code>public/data/</code> finns och är giltig.
        </p>
      </Callout>
    );
  }
  return <>{children}</>;
}

function RouteError() {
  const err = useRouteError();
  const msg = isRouteErrorResponse(err)
    ? `${err.status} ${err.statusText}`
    : err instanceof Error
      ? err.message
      : 'Okänt fel';
  return (
    <div className="space-y-3">
      <Callout tone="danger" title="Sidan kunde inte visas">
        <p>{msg}</p>
      </Callout>
      <Link to="/">Till översikten</Link>
    </div>
  );
}

function NotFound() {
  return (
    <div className="space-y-3">
      <Callout tone="warn" title="Sidan finns inte">
        <p>Adressen matchar ingen vy i kunskapsbasen.</p>
      </Callout>
      <Link to="/">Till översikten</Link>
    </div>
  );
}

/**
 * Snabböversikten är sammanslagen med katalogen (utfällbara rader).
 * Gamla länkar (#/oversikt?scope=…&has=…&sort=…) översätts till katalogens filter.
 */
function OverviewRedirect() {
  const { search } = useLocation();
  const old = new URLSearchParams(search);
  const next = new URLSearchParams();
  const scope = old.get('scope');
  if (scope === 'products') next.set('kind', 'product_family');
  if (scope === 'protocols') next.set('kind', 'protocol_service');
  const origin = old.get('origin');
  if (origin === 'original' || origin === 'new') next.set('origin', origin);
  const has = old.get('has');
  if (has) next.set('has', has);
  next.set('sort', old.get('sort') === 'name' ? 'name' : 'severity');
  next.set('view', 'cards');
  return <Navigate to={`/katalog?${next.toString()}`} replace />;
}

const gate = (el: React.ReactNode) => <DataGate>{el}</DataGate>;

const router = createHashRouter([
  {
    path: '/',
    element: <Layout />,
    errorElement: <RouteError />,
    children: [
      { index: true, element: gate(<DashboardPage />) },
      { path: 'katalog', element: gate(<CatalogPage />) },
      { path: 'produkt/:id', element: gate(<ProductPage />) },
      { path: 'protokoll/:id', element: gate(<ProtocolPage />) },
      { path: 'sarbarheter', element: gate(<VulnerabilitiesPage />) },
      { path: 'sarbarheter/:cveId', element: gate(<VulnerabilityPage />) },
      { path: 'bulletiner', element: gate(<AdvisoriesPage />) },
      { path: 'bulletiner/:id', element: gate(<AdvisoryPage />) },
      { path: 'prioritering', element: gate(<PrioritizationPage />) },
      { path: 'atgarder', element: gate(<ControlsPage />) },
      { path: 'datakvalitet', element: gate(<DataQualityPage />) },
      { path: 'export', element: gate(<ExportPage />) },
      { path: 'konton', element: gate(<AccountsPage />) },
      { path: 'oversikt', element: <OverviewRedirect /> },
      { path: 'om', element: <AboutPage /> },
      { path: '*', element: <NotFound /> },
    ],
  },
]);

export function App() {
  return (
    <DatasetProvider>
      <RouterProvider router={router} />
    </DatasetProvider>
  );
}

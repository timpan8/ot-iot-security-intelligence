import { isProduct, type CatalogEntry, type IndexedDataset } from '@/data/loader';
import { materialTypeLabel } from '@/lib/labels';
import type { PublicPocStatus } from '@schemas/index';

export interface CveRow {
  cve: string;
  score: number | null;
  kev: boolean;
  poc: PublicPocStatus | null;
}

export interface PocRow {
  cve: string;
  url: string;
  material: string;
  note: string | null;
}

export function collect(d: IndexedDataset, e: CatalogEntry): { cves: CveRow[]; pocs: PocRow[] } {
  const matches = isProduct(e) ? (d.matchesByProduct.get(e.id) ?? []) : [];
  const cves = new Map<string, CveRow>();
  const pocs = new Map<string, PocRow>();
  for (const m of matches) {
    const v = m.vulnerability_id ? d.vulnerabilityById.get(m.vulnerability_id) : undefined;
    if (!v) continue;
    if (!cves.has(v.cve_id))
      cves.set(v.cve_id, {
        cve: v.cve_id,
        score: v.cvss.length ? Math.max(...v.cvss.map((c) => c.base_score)) : null,
        kev: v.kev.listed,
        poc: v.threat_intel?.public_poc_status ?? null,
      });
    const ti = v.threat_intel;
    if (ti?.poc_url && !pocs.has(ti.poc_url))
      pocs.set(ti.poc_url, {
        cve: v.cve_id,
        url: ti.poc_url,
        material: materialTypeLabel[ti.material_type_code] ?? ti.material_type_text ?? 'okänd typ',
        note: ti.source_critical_note,
      });
  }
  const sorted = [...cves.values()].sort(
    (a, b) => Number(b.kev) - Number(a.kev) || (b.score ?? -1) - (a.score ?? -1),
  );
  return { cves: sorted, pocs: [...pocs.values()] };
}

export interface PortGroup {
  service: string;
  serviceId: string;
  ports: Array<{ port: number; transport: string; note: string | null }>;
}

/** Standardportar via postens protokoll (för ett protokoll: dess egna portar). */
export function portsFor(d: IndexedDataset, e: CatalogEntry): PortGroup[] {
  const services = isProduct(e)
    ? e.protocol_service_ids
        .map((id) => d.protocolById.get(id))
        .filter((x): x is NonNullable<typeof x> => Boolean(x))
    : [e];
  return services
    .filter((svc) => svc.default_ports.length > 0)
    .map((svc) => ({
      service: svc.name,
      serviceId: svc.id,
      ports: svc.default_ports.map((p) => ({
        port: p.port,
        transport: p.transport,
        note: p.note ?? null,
      })),
    }));
}

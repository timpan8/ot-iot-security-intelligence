# Källor och källhierarki

Plattformen skiljer på **primära** och **sekundära** källor och lagrar varje källa som en `Source`-post med `verification_status`-relaterade fält (`last_checked_at`, `last_verified_at`, `availability`, `supports_claims`). Ingen uppgift accepteras enbart för att den förekommer i arbetsboken eller i genererad text.

## Hierarki

1. **Tillverkarens PSIRT/bulletin (helst CSAF)** – t.ex. Siemens ProductCERT CSAF, Danfoss Security Advisories.
2. **Myndighets-CERT** – CISA ICS Advisories (CSAF via `cisagov/CSAF`), CISA KEV, CERT@VDE, CERT-SE/NCSC.
3. **NVD** – CVE-poster från CNA (CVSS, CWE, CPE, status). Räknas som primär databaspost; beskrivningstext är inte auktoritativ för berörd/ej berörd när CSAF finns.
4. **Standarder** – NIST SP 800-82r3 (fastställd), IEC 62443, OPC Foundation, IANA.
5. **Sekundär forskning** – t.ex. Armis Frostbyte10, Dragos. Märks `secondary_research`; kan vara CNA för CVE:er men rapporten själv är sekundär.
6. **Arbetsboken** – `internal_workbook`; ursprunglig inventering, aldrig i sig bevis.

## Maskinläsbara feeds som används

| Feed            | Endpoint                                                                                    | Användning                                | Villkor                                                       |
| --------------- | ------------------------------------------------------------------------------------------- | ----------------------------------------- | ------------------------------------------------------------- |
| NVD CVE API 2.0 | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=`                                   | CVE-status, CVSS, CWE, CPE, referenser    | 5 anrop/30 s utan nyckel (6,5 s paus), `apiKey`-header valfri |
| FIRST EPSS      | `https://api.first.org/data/v1/epss?cve=`                                                   | Sannolikhetsindikator + percentil + datum | Batch ≤100                                                    |
| CISA KEV        | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`       | Bekräftat utnyttjande                     | Hela katalogen, filtreras lokalt                              |
| Siemens CSAF    | `https://cert-portal.siemens.com/productcert/csaf/<id>.json`                                | product_status, remediations              | –                                                             |
| CISA CSAF       | `https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/<år>/<id>.json` | ICS-advisories maskinläsbart              | –                                                             |

Tillgänglighet 2026-11-07 från byggmiljön: NVD, EPSS, KEV, Siemens CSAF och CISA CSAF (GitHub) nåddes. `www.danfoss.com` och `www.cisa.gov` (webbsidor) svarade 403 för automatiserad hämtning och är markerade `blocked` – innehållet måste läsas manuellt.

## Hur källor kopplas till påståenden

- Varje `vulnerability`, `advisory`, `match`, `claim` och `observation` har `source_ids`.
- `Source.supports_claims` listar vilka entiteter/fält källan stödjer.
- `check-links.ts` uppdaterar `availability`/`http_status` i `sources/link-report.json` utan att fälla bygget.

## Primära referenser (projektunderlag)

- GitHub Pages HTTPS: https://docs.github.com/en/pages/getting-started-with-github-pages/securing-your-github-pages-site-with-https
- GitHub Actions säker användning: https://docs.github.com/en/actions/reference/security/secure-use
- actions/deploy-pages: https://github.com/actions/deploy-pages
- NIST SP 800-82 Rev. 3 (fastställd): https://csrc.nist.gov/pubs/sp/800/82/r3/final
- NIST SP 800-82 Rev. 4 (utkast, IPD): https://csrc.nist.gov/pubs/sp/800/82/r4/ipd
- NVD CVE API 2.0: https://nvd.nist.gov/developers/vulnerabilities
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FIRST EPSS: https://api.first.org/epss/
- CISA CSAF: https://github.com/cisagov/CSAF
- CISA SSVC-guide: https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf
- Danfoss DSA-2025-03-01 och DSA-2025-08-01 (se `sources/curated/advisories.json`)
- Siemens SSA-330084: https://cert-portal.siemens.com/productcert/html/ssa-330084.html
- NCSC – cybersäkerhetslagen: https://www.ncsc.se/sv/radgivning-och-stod/cybersakerhetslagen-nis2/sakerhetsatgarder-enligt-cybersakerhetslagen/

Alla källor med status och koppling finns i `public/data/sources.json` och i datakvalitetsvyn.

# Källor och källhierarki

Plattformen skiljer på **primära** och **sekundära** källor och lagrar varje källa som en `Source`-post med `verification_status`-relaterade fält (`last_checked_at`, `last_verified_at`, `availability`, `supports_claims`). Ingen uppgift accepteras enbart för att den förekommer i arbetsboken eller i genererad text.

## Hierarki

1. **Tillverkarens PSIRT/bulletin (helst CSAF)** – t.ex. Siemens ProductCERT CSAF, Danfoss Security Advisories.
2. **Myndighets-CERT** – CISA ICS Advisories (CSAF via `cisagov/CSAF`), CISA KEV, CERT@VDE, CERT-SE/NCSC.
3. **NVD** – CVE-poster från CNA (CVSS, CWE, CPE, status). Räknas som primär databaspost; beskrivningstext är inte auktoritativ för berörd/ej berörd när CSAF finns.
4. **Standarder** – NIST SP 800-82r3 (fastställd), IEC 62443, OPC Foundation, IANA.
5. **Sekundär forskning** – t.ex. Armis Frostbyte10, Dragos. Märks `secondary_research`; kan vara CNA för CVE:er men rapporten själv är sekundär.
6. **Arbetsböckerna** – `internal_workbook`; 66-postsinventeringen (`src-workbook`) och
   125-postregistret (`src-register-workbook`). Registrets egna verifieringar (Källmanifest,
   Länkkontroll, Hotkällor) är dokumenterade med SHA-256 men räknas som sekundära för projektet
   tills de omverifierats maskinellt eller manuellt.

## Maskinläsbara feeds som används

| Feed            | Endpoint                                                                                    | Användning                                | Villkor                                                       |
| --------------- | ------------------------------------------------------------------------------------------- | ----------------------------------------- | ------------------------------------------------------------- |
| NVD CVE API 2.0 | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=`                                   | CVE-status, CVSS, CWE, CPE, referenser    | 5 anrop/30 s utan nyckel (6,5 s paus), `apiKey`-header valfri |
| FIRST EPSS      | `https://api.first.org/data/v1/epss?cve=`                                                   | Sannolikhetsindikator + percentil + datum | Batch ≤100                                                    |
| CISA KEV        | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`       | Bekräftat utnyttjande                     | Hela katalogen, filtreras lokalt                              |
| Siemens CSAF    | `https://cert-portal.siemens.com/productcert/csaf/<id>.json`                                | product_status, remediations              | –                                                             |
| CISA CSAF       | `https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/<år>/<id>.json` | ICS-advisories maskinläsbart              | –                                                             |

| cveawg (CVE Program) | `https://cveawg.mitre.org/api/cve/<CVE>` | Registrets Hotkällor: CNA + CISA ADP (SSVC Exploitation, bedömningsdatum) med SHA-256 | Hämtat av registrets upphovsman 2026-11-07; projektet lagrar URL + hash som `Source` |

### Registrets källblad (import 2)

- **Källmanifest** (214 rader): Käll-ID (`ICSA-…`, `ICSMA-…`, `SETUP-…`, `CVE-…`), utgivare/format
  (CISA CSAF 60, CVE/CNA 21, CISA KEV 1, officiell leverantörsdokumentation 132), URL, SHA-256 av
  hämtat dokument, källdatum, hämtningsdatum och vad som verifierats. Varje rad blir en `Source`
  (`src-reg-<käll-id>`) med `document_sha256`, `fetched_at` och `register_source_key`; URL:er som
  redan finns i projektet dedupliceras och får hash/nyckel påförd.
- **Hotkällor** (344 rader): cveawg-URL per CVE med SHA-256 och postens uppdateringsdatum →
  `Source` (`src-cverecord-<cve>`) som `record_source_id` i `threat_intel`.
- **Länkkontroll** (210 rader): HTTP-status (200: 148, 403: 35, SSL-fel: 20, övrigt 7), slutlig
  URL, SHA-256 av svar, tolkning och datum → `LinkCheck` (`link_checks.json`) och
  `Source.availability` (`ok`/`redirected`/`blocked`/`broken`). Två URL:er är `http://` och lagras
  som ren text, aldrig som klickbar länk. ”Nåbar länk” betyder inte verifierat innehåll.
- **Övriga URL:er** i Register, Setup och konton, Sårbarheter, Radgranskning och Hotunderlag blir
  auto-källor (`src-reg-url-<värd>-<hash>`) med `availability: unchecked`.

### CSAF-verifiering av registrets relationer

`npm run data:enrich:csaf-register` hämtar CSAF-dokumenten för registrets 60 CISA-bulletiner
från `raw.githubusercontent.com/cisagov/CSAF`. `verifyRelationAgainstCsaf` i
`scripts/normalize-register.ts` kontrollerar per rad i Sårbarheter att CVE:t finns i bulletinen
och att produktnamnet (eller affected-källtexten) matchar `known_affected` i produktträdet.
Utfall: `verified_primary` vid träff, `corroborated_secondary` när bulletin saknas i cache eller
källan är en CVE-post utan CSAF, `needs_review` när CVE:t eller produkten inte återfinns.
Resultatet står i varje matchnings `register_verification_note`. Vid importen 2026-11-07 blev 347
av 349 relationer `verified_primary` och 2 `corroborated_secondary`.

Tillgänglighet 2026-11-07 från byggmiljön: NVD, EPSS, KEV, Siemens CSAF och CISA CSAF (GitHub) nåddes. `www.danfoss.com` och `www.cisa.gov` (webbsidor) svarade 403 för automatiserad hämtning och är markerade `blocked` – innehållet måste läsas manuellt.

## Hur källor kopplas till påståenden

- Varje `vulnerability`, `advisory`, `match`, `claim` och `observation` har `source_ids`.
- `Source.supports_claims` listar vilka entiteter/fält källan stödjer.
- `check-links.ts` uppdaterar `availability`/`http_status` i `sources/link-report.json` utan att fälla bygget.
- Registrets Länkkontroll ger `availability`/`http_status`/`final_url`/`interpretation_text` på källor med samma URL samt egna `LinkCheck`-poster.
- `credentials.account_source_id`/`password_status_source_id`, `setup_documentation.source_id`, `review_findings[].source_ids` och `threat_intel.assessment_source_id`/`record_source_id` pekar på källor så att konto-, setup- och hotuppgifter kan spåras per post och CVE.

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

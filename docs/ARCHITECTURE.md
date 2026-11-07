# Arkitektur

Detta dokument beskriver hur OT/IoT Security Intelligence Platform är uppbyggd, vilka tekniska
beslut som fattats och varför. Det ska räcka för att en annan utvecklare ska kunna fortsätta
arbetet utan tillgång till tidigare konversationer.

## Översikt

```mermaid
flowchart LR
  subgraph Sources["Källdata (repo)"]
    XLSX[sources/original/*.xlsx – två arbetsböcker]
    RAW[sources/raw/workbook.json]
    RAWREG[sources/raw/register/*.json]
    CUR[sources/curated/*.json]
    ENR[sources/enrichment/ NVD · EPSS · KEV · CSAF]
  end

  subgraph Pipeline["Datapipeline (scripts/, tsx)"]
    IMP[import-xlsx.ts]
    IMPREG[import-register.ts]
    NORMREG[normalize-register.ts]
    NORM[normalize.ts]
    VAL[validate.ts]
    SCH[emit-json-schemas.ts]
    ART[check-artifact.ts]
  end

  subgraph Contracts["Datakontrakt"]
    ZOD[schemas/*.ts – Zod]
    JSONS[schemas/json/*.schema.json]
  end

  subgraph Public["Publik artefakt"]
    DATA[public/data/*.json + manifest.json]
    APP[src/ React + TS + Vite]
    DIST[dist/ → GitHub Pages]
  end

  subgraph Automation["GitHub Actions"]
    CI[ci.yml]
    DEP[deploy.yml]
    UPD[data-update.yml]
    CQL[codeql.yml]
  end

  XLSX --> IMP --> RAW
  RAW --> NORM
  CUR --> NORM
  ENR --> NORM
  NORM --> DATA
  ZOD --> NORM
  ZOD --> VAL
  ZOD --> SCH --> JSONS
  DATA --> VAL
  DATA --> APP --> DIST --> ART
  UPD -->|fetch| ENR
  UPD -->|pull request, needs_review| CUR
  CI --> VAL
  DEP --> DIST
```

Kontrollera faktiska filnamn i `scripts/`, `scripts/enrich/` och `.github/workflows/`; diagrammet
visar den planerade strukturen.

## Dataflöde i detalj

0. **Två importer, en pipeline.** `import-xlsx.ts` läser 66-postsinventeringen och
   `import-register.ts` det utökade 125-postregistret; `normalize.ts` slår ihop båda med
   kuraterad data och cache. Flödet är `data:import → data:import:register → data:build →
data:validate → data:schemas` (`npm run data:all`).
1. **Import** (`scripts/import-xlsx.ts`, `scripts/lib/xlsx.ts`). Arbetsboken läses i sin helhet:
   alla blad, alla celler. Varje cell sparas verbatim med blad, rad, kolumn och rubrik i
   `sources/raw/workbook.json`. `import-report.json` räknar null-värden per kolumn, kategorier,
   dubbletter och listar antaganden. Importen fallerar om rubrikerna avviker eller om antalet
   dataposter inte är 66.
   1b. **Registerimport** (`scripts/import-register.ts`). Rubrikbaserad kolumnupplösning per blad
   via kartan `SHEETS` (Register, Sårbarheter, Radgranskning, Riskkontroller, Källmanifest,
   Länkkontroll, Hotunderlag, Hotkällor, Setup och konton); saknad rubrik stoppar importen, extra
   rubriker rapporteras. Datumceller normaliseras till `YYYY-MM-DD`, allt annat bevaras verbatim.
   Skriver `sources/raw/register/<blad>.json`, `import-report.json` (kontrolltal jämförda mot
   bladet Granskningsrapport, avvikelser, `id_map.created/unchanged/conflicted`,
   `password_values_present: false`), `conflicts.json` (skillnader mot kuraterat) och
   `review_report.json`. Idempotent: deterministiskt utdata och `register_id_map.json` som bara
   får nya nycklar. Cellinnehåll är data – inga formler eller makron körs.
   1c. **Registertransformationer** (`scripts/normalize-register.ts`). Rena funktioner: källor ur
   Källmanifest/Hotkällor (med SHA-256) och auto-källor för övriga URL:er, `LinkCheck` ur
   Länkkontroll, `RegisterInfo`, `Credentials`, `SetupDocumentation`, `ReviewFinding`,
   `ThreatIntel`, CSAF-index och `verifyRelationAgainstCsaf` (CVE i bulletin + produkt i
   `known_affected`), samt bulletiner ur manifestet (`buildRegisterAdvisories`).
2. **Kuratering** (`sources/curated/`). Mänskligt granskad data: leverantörer, bulletiner,
   produkt–CVE–versionsmatchningar, åtgärder, källor, observationer och radvisa overrides (alias,
   livscykel, OT-roll, protokollkopplingar, parsade CVE-ID:n, oexpanderade CVE-intervall). Varje
   uppgift bär `verification_status` och `source_ids`.
3. **Enrichment-cache** (`sources/enrichment/`). Råsvar från NVD CVE API 2.0, FIRST EPSS, CISA KEV
   (filtrerad delmängd) och CSAF-dokument från Siemens ProductCERT och CISA. Cachen är
   versionshanterad så att varje bygge är reproducerbart och varje ändring syns i en diff.
4. **Normalisering** (`scripts/normalize.ts`). Slår ihop rådata från båda importerna, kuratering
   och cache till de publika entiteterna. För registret: 59 nya poster byggs med
   `category_profiles.json` (kategori är fri text) och `register_vendors.json`; alla 125 får
   `register`-, `credentials`-, `setup_documentation`- och `review_findings`-block; registrets
   349 produkt–CVE-relationer läggs till som matchningar – befintliga kuraterade matchningar
   vinner och annoteras (`register_relation: true`), nya får `match-reg-<register-id>-<cve>`,
   `version_rule.type = 'source_text'` och status från CSAF-verifieringen; CVE utan NVD-cache
   byggs från registrets CVSS med `nvd_status: 'unknown'`; konflikter blir `disputed`-claims.
   Normaliseringen härleder riskfaktorer enligt `docs/RISK_METHOD.md`, bygger sökindex och
   skriver `public/data/*.json` samt `manifest.json` (genereringstid, arbetsbokens SHA-256,
   räkningar, schema-version).
5. **Validering** (`scripts/validate.ts`). Zod-parse av varje fil, unika ID:n, referensintegritet,
   räkningar mot importrapporterna (`loadExpectedCounts`, inte konstanter), bevarade
   originalposter, registerposter/relationer/länkkontroller/hotunderlag, protokoll utan
   CVE-matchningar, `link_checks` undantagna från https-kravet (URL lagras som text), endast https-länkar och rekursiv
   kontroll mot `FORBIDDEN_PUBLIC_KEYS`. Körs som `prebuild` och i CI.
6. **Bygge och artefaktkontroll**. `tsc -b && vite build`, därefter `scripts/check-artifact.ts`
   som skannar `dist/` efter förbjudna nycklar och efter `.xlsx`-filer.
7. **Frontend** (`src/`). Läser `public/data/*.json` via `fetch`, validerar med samma Zod-scheman
   och bygger vyer. Ingen backend, inga API-nycklar.

## Tekniska beslut

| Beslut                                              | Motivering                                                                                                                                                                                                                                                                                    |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Vite + React 19 + TypeScript**                    | Snabb utveckling, välkänt, statisk utdata som passar GitHub Pages. `base` styrs av `VITE_BASE_PATH`.                                                                                                                                                                                          |
| **Tailwind CSS 4** via `@tailwindcss/vite`          | Konsekvent design, mörkt/ljust tema med `prefers-color-scheme`, liten beroendekedja.                                                                                                                                                                                                          |
| **react-router 7 i HashRouter-läge**                | GitHub Pages saknar server-side rewrite. Hash-routing ger fungerande djuplänkar och URL-baserad filterstatus utan 404-fallback.                                                                                                                                                               |
| **Zod 4 som enda schema-sanning**                   | Samma scheman används i skript, tester och webbläsare. JSON Schema exporteras med Zods inbyggda `toJSONSchema` till `schemas/json/` för maskinläsbara kontrakt. Alla objekt är `strictObject`.                                                                                                |
| **Egen xlsx-läsare (`fflate` + `fast-xml-parser`)** | Arbetsboken använder namnrymdsprefix (`x:`) i OOXML, vilket `exceljs` inte klarar (`Cannot read properties of undefined (reading 'sheets')`). SheetJS npm-paket är inaktuellt. Den egna läsaren är ~150 rader, hanterar sharedStrings, inlineStr, str, n, b och d, och har två små beroenden. |
| **minisearch för klientsökning**                    | Litet, utan server. Index byggs i webbläsaren från `public/data`.                                                                                                                                                                                                                             |
| **Statisk JSON i repot**                            | Full spårbarhet via git, inga databaser, ingen nyckel i webbläsaren. Nya data bearbetas i GitHub Actions före bygget.                                                                                                                                                                         |
| **Versionshanterad enrichment-cache**               | Varje externt svar är granskbart i PR-diffar. Externa uppgifter kan aldrig tyst skriva över kuraterade uppgifter.                                                                                                                                                                             |
| **Separat privat schema utan data**                 | Skyddsgränsen i masterprompten. `schemas/private/` importeras aldrig av `src/`, och `FORBIDDEN_PUBLIC_KEYS` blockerar fälten i publik data.                                                                                                                                                   |
| **tsx för skript**                                  | Samma TypeScript-kod i skript och tester utan extra byggsteg.                                                                                                                                                                                                                                 |
| **Playwright med förinstallerad Chromium**          | Röktest mot `vite preview`. `PW_CHROMIUM_PATH` kan peka på en systeminstallerad binär.                                                                                                                                                                                                        |

## Frontendstruktur (planerad)

```text
src/
  app/          router (HashRouter), layout, tema, felgränser
  data/         loader som hämtar public/data/*.json och parsar med Zod; typer från schemas/
  features/     dashboard, catalog, product-detail, protocol-detail, vulnerabilities,
                advisories, data-quality, controls-guides, export, about, prioritization
  components/   tabell, filterchips, badges för verification_status, SafeLink, UnknownValue
  lib/          sök (minisearch), URL-state för filter, CSV/JSON-export med metadata
  styles/       Tailwind-ingång och tokens
```

Kontrollera faktiska katalognamn i `src/` när frontendarbetet är klart.

## Uppdaterings- och granskningspipeline

`scripts/enrich/` innehåller planerat `http.ts` (timeout, retry med backoff, rate limiting,
User-Agent, allowlist av värdar), `cve-list.ts` (vilka CVE-ID:n som ska hämtas, härledda ur
matchningar och bulletiner), `nvd.ts`, `epss.ts`, `kev.ts`, `csaf.ts`, `run.ts` (orkestrering) och
`diff.ts` (rapport över nya, ändrade, avvisade eller omklassade CVE:er, versionsändringar och
konflikter mot kuraterad data). `data-update.yml` kör pipelinen schemalagt och via
`workflow_dispatch`, skriver cachen och öppnar en pull request med etiketten `needs_review`.
Källkritiska ändringar kräver mänskligt godkännande före publicering.

## Säkerhetsgränser i arkitekturen

- Ingen kod i webbläsaren talar med externa API:er. Endast `public/data` och statiska tillgångar
  hämtas.
- Inget skript öppnar förbindelser till styrsystem eller andra interna nät; allowlisten i
  `scripts/enrich/http.ts` begränsar trafiken till dokumenterade feed-värdar.
- Se `docs/SECURITY.md` för CSP, Actions-härdning och skyddsgränstester.

## Förberedelser för fas 2

- `claims` och `history` i entiteterna ger grund för ändringsnotiser och trendsnapshots.
- `framework_refs` på kontroller förbereder IEC 62443/NIST CSF 2.0-mappning.
- `Advisory.history` och `Vulnerability.enrichment` ger underlag för tillverkarbevakning och RSS.
- Språkväxling: UI-texter samlas i komponenterna med svenska som standard; en i18n-lösning kan
  införas utan att datamodellen ändras.
- Den privata asset-modulen kräver separat autentiserad hosting och får inte aktiveras i Pages.

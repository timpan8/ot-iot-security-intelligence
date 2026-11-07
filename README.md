# OT/IoT Security Intelligence Platform

Publik, källkritisk och **defensiv** kunskapsbas för produktfamiljer och protokoll inom
OT/IoT/ICS/BMS/SCADA. Plattformen migrerar Excel-inventeringar till versionshanterad, validerad
JSON med ett React-gränssnitt som publiceras på GitHub Pages:

- **Import 1:** `OT_IoT_sarbarhetsoversikt_66_system_2026-11-07.xlsx` – 66 poster (55
  produktfamiljer, 11 protokoll/tjänster, 18 kategorier).
- **Import 2:** `OT_IoT_125_poster_losenordsstatus.xlsx` – det utökade registret med 125 poster
  (de 66 originalen + 59 nya produktfamiljer, 46 kategorier), 344 unika CVE i 349 produkt–CVE-
  relationer, hotunderlag (PoC/SSVC), konto- och lösenordsstatus utan lösenordsvärden,
  setupdokumentation, källmanifest med SHA-256 och länkkontroll.

> **Viktigt.** Katalogen beskriver _produktfamiljer_ och _protokoll_, inte installerade enheter.
> Inget i den publika datan säger något om en viss anläggnings exponering, versioner eller
> sårbarhet. Frånvaro av CVE-referens är inte bevis för frånvaro av sårbarheter.

## Skyddsgräns

Projektet har två strikt åtskilda datanivåer:

| Nivå                                   | Innehåll                                                                                                                                                                         | Status i detta repo                                                                                                                                                                             |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Publik produkt- och hotkunskapsbas** | Produktfamiljer, protokoll, leverantörsbulletiner, CVE-referenser, verifierade versionsintervall, defensiva åtgärder, officiella dokumentationslänkar, generella riskbedömningar | **Detta repo.** Publiceras på GitHub Pages.                                                                                                                                                     |
| **Privat anläggningsinventering**      | Verkliga enheter, IP-adresser, nätsegment, byggnader, ägare, kontakter, serienummer, scanningresultat, åtgärdsärenden                                                            | **Ingår inte.** Endast ett datakontrakt finns i `schemas/private/assets.ts`. Inga poster lagras, och frontend får inte importera schemat. Kräver separat autentiserad arkitektur utanför Pages. |

Skyddsgränsen kontrolleras maskinellt: `scripts/validate.ts` och `scripts/check-artifact.ts`
fallerar bygget om någon nyckel i `FORBIDDEN_PUBLIC_KEYS` (`schemas/common.ts`) förekommer i
`public/data/` eller `dist/`.

## Snabbstart

Kräver Node.js 22 eller senare.

```bash
npm ci
```

```bash
npm run data:all
```

```bash
npm run dev
```

Övriga kommandon:

| Kommando                                                      | Vad det gör                                                                                                                                                                                                                                                              |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `npm run data:import`                                         | Läser 66-postsarbetsboken i `sources/original/` → `sources/raw/workbook.json` + `import-report.json`. Fallerar om antalet poster ≠ 66 eller rubrikerna avviker.                                                                                                          |
| `npm run data:import:register`                                | Läser det utökade registret (`--file sources/original/OT_IoT_125_poster_losenordsstatus.xlsx`) → `sources/raw/register/<blad>.json`, `import-report.json`, `conflicts.json`, `review_report.json`. Rubrikbaserad kolumnupplösning; idempotent (se nedan).                |
| `npm run data:enrich:csaf-register`                           | Hämtar CSAF-dokument för registrets 60 CISA-bulletiner (ur Källmanifest) till `sources/enrichment/csaf/`. Används för maskinell verifiering av registrets produkt–CVE-relationer.                                                                                        |
| `npm run data:build`                                          | Normaliserar rådata (båda importerna) + kuraterad data + enrichment-cache → `public/data/*.json` + `manifest.json`.                                                                                                                                                      |
| `npm run data:validate`                                       | Zod-validering, referensintegritet, räkningar mot importrapporterna (inte hårdkodade tal), https-krav, förbjudna nycklar (inkl. lösenordsnycklar). Körs automatiskt före `build`.                                                                                        |
| `npm run data:schemas`                                        | Exporterar JSON Schema till `schemas/json/`.                                                                                                                                                                                                                             |
| `npm run data:enrich`                                         | Hämtar NVD/EPSS/KEV/CSAF till `sources/enrichment/` (används i GitHub Actions, kan köras lokalt). Bakom en HTTPS-proxy: sätt `NODE_USE_ENV_PROXY=1` (Node ≥ 22.21) och vid behov `NODE_EXTRA_CA_CERTS`, eftersom Node:s inbyggda `fetch` annars ignorerar `HTTPS_PROXY`. |
| `npm run data:diff`                                           | Skapar diff-rapport mellan enrichment-cache och kuraterad data.                                                                                                                                                                                                          |
| `npm run data:check-links`                                    | Kontrollerar källänkar och skriver `sources/link-report.json` (nätberoende, fallerar inte bygget).                                                                                                                                                                       |
| `npm run build`                                               | Typkontroll + Vite-bygge till `dist/`, följt av artefaktkontroll av skyddsgränsen.                                                                                                                                                                                       |
| `npm test`                                                    | Enhets- och datatester (Vitest).                                                                                                                                                                                                                                         |
| `npm run test:e2e`                                            | Röktest i Chromium (Playwright) mot `vite preview`.                                                                                                                                                                                                                      |
| `npm run lint` / `npm run typecheck` / `npm run format:check` | Kodkvalitet.                                                                                                                                                                                                                                                             |

`npm run data:all` kör import → import:register → build → validate → schemas i rätt ordning.

### Importera en uppdaterad registerversion

```bash
cp <ny fil>.xlsx sources/original/OT_IoT_125_poster_losenordsstatus.xlsx
```

```bash
npm run data:import:register -- --file sources/original/OT_IoT_125_poster_losenordsstatus.xlsx
```

```bash
npm run data:build && npm run data:validate && npm test
```

- **Rubriker, inte kolumnbokstäver.** Kolumner identifieras via rubriktexten per blad (kartan
  `SHEETS` i `scripts/import-register.ts`). Saknas en obligatorisk rubrik stoppar importen; extra
  rubriker rapporteras som avvikelse.
- **Idempotent.** Samma fil ger identiska rådata och oförändrad `sources/curated/register_id_map.json`
  (register-ID `OT-…` → projekt-ID `pf-…`/`svc-…`). Nya register-ID:n får nya projekt-ID:n;
  befintliga ändras aldrig. Importrapporten anger `id_map.created/unchanged/conflicted`.
- **Konflikter skrivs inte över.** Avvikelser mot projektets kuraterade uppgifter (namn, alias,
  CVE-mängd) listas i `sources/raw/register/conflicts.json` och blir `disputed`-påståenden i
  datakvalitetsvyn. Projektets manuella bedömningar behålls; registrets relationer läggs till som
  `register_relation`.
- **Kontrolltal.** Arbetsbokens egna tal i bladet Granskningsrapport jämförs med beräknade värden
  (`workbook_control_totals` i importrapporten); avvikelser rapporteras i stället för att användas
  som hårdkodade applikationsvärden.
- **Lösenord.** Registret innehåller inga lösenordsvärden – endast kontonamn, typ av
  initiallösenord och bytekrav. Nycklarna `password`, `password_value`, `passwd`, `secret`,
  `api_key`, `credential_value` är förbjudna i publik data och stoppar bygget om de dyker upp.
- **Säker hantering.** Cellinnehåll behandlas som data: inga formler, makron eller externa länkar
  körs (xlsx-läsaren läser bara cachade cellvärden).

`.npmrc` sätter `legacy-peer-deps=true`. Orsak: npm 10 kraschar (`Cannot read properties of null
(reading 'edgesOut')`) vid peer-upplösning mellan Vitest 4 och `@playwright/test`. Lockfilen är
skapad med den inställningen och `npm ci` fungerar därmed reproducerbart.

## Katalogstruktur

```text
.github/workflows/    ci.yml, deploy.yml, data-update.yml, codeql.yml (se avsnittet om Actions)
.github/dependabot.yml
schemas/              Zod-scheman = datakontraktets sanning; schemas/json/ = exporterad JSON Schema
schemas/private/      ENDAST kontrakt för framtida privat asset-modul (ingen data, importeras aldrig av src/)
scripts/              import-xlsx, import-register, normalize, normalize-register, validate, check-artifact, emit-json-schemas, check-links
scripts/enrich/       NVD/EPSS/KEV/CSAF-hämtning och diff (http, nvd, epss, kev, csaf, csaf-register, run, diff)
scripts/lib/          xlsx-läsare, filhjälpare
sources/original/     Arbetsböckerna + SHA-256 (ingår aldrig i dist/)
sources/raw/          Genererad verbatim-dump av 66-postsarbetsboken + importrapport
sources/raw/register/ Genererad dump per blad av 125-postregistret + import-report, conflicts, review_report
sources/curated/      Handkuraterad, källgranskad data (vendors, advisories, matches, controls, sources, observations, overrides,
                      register_id_map, register_vendors, category_profiles)
sources/enrichment/   Versionshanterad cache av NVD-, EPSS-, KEV- och CSAF-svar
public/data/          Genererad, validerad, ENBART publik JSON som frontend läser
src/                  React + TypeScript (app/, components/, data/, features/, lib/)
tests/unit/           Vitest; tests/e2e/ Playwright; tests/fixtures/ testdata
docs/                 ARCHITECTURE, DATA_MODEL, SOURCES, SECURITY, RISK_METHOD, MIGRATION_REPORT, BACKLOG, CONTRIBUTING
```

Kontrollera faktiska filnamn under `src/`, `scripts/enrich/` och `.github/workflows/` i trädet;
denna README beskriver den planerade strukturen.

## Datapipeline

```text
66-xlsx  ──import-xlsx─────▶ sources/raw/workbook.json ──────┐
125-xlsx ──import-register─▶ sources/raw/register/*.json ────┤
                                                              ├─normalize──▶ public/data/*.json ──validate──▶ build
sources/curated/*.json (mänskligt granskat) ──────────────────┤
sources/enrichment/*  (NVD/EPSS/KEV/CSAF-cache) ──────────────┘
```

1. **Import** läser alla blad och celler verbatim. Varje post får `provenance` (blad, rad, kolumn,
   rubrik) och `original.values` så att varje uppgift kan spåras tillbaka till Excel.
2. **Kuratering** i `sources/curated/` lägger till leverantörer, bulletiner, explicita
   produkt–CVE–versionsmatchningar, åtgärder, källor och korrigeringar. Här skiljs t.ex. Danfoss
   DSA-2025-03-01 (CVE-2025-41450) från DSA-2025-08-01 (CVE-2025-41451/41452), och Siemens
   SSA-330084 kopplas endast till de Desigo CC-klientvarianter som bulletinen anger.
3. **Registerimport** (`scripts/import-register.ts` + `scripts/normalize-register.ts`) kopplar
   bladen via produkt-ID, CVE-ID och kontroll-ID, bygger de 59 nya posterna, lägger
   `register`-, `credentials`-, `setup_documentation`- och `review_findings`-block på alla 125,
   skapar produkt–CVE-relationer (många-till-många) med exakt affected-/fixed-källtext,
   hotunderlag per CVE, källor med dokumenthash och länkkontroller. Relationer verifieras
   maskinellt mot hämtade CSAF-dokument (`verified_primary` när CVE finns i bulletinen och
   produkten bland `known_affected`, annars `corroborated_secondary`/`needs_review`).
4. **Normalisering** bygger de publika JSON-filerna, härleder riskfaktorer enligt
   `docs/RISK_METHOD.md` och sätter `verification_status` per uppgift.
5. **Validering** stoppar bygget vid ogiltiga ID:n, brutna relationer, dubbletter, protokoll med
   CVE-matchning, http-länkar i URL-fält, räkningar som avviker från importrapporterna eller
   förbjudna nycklar.
6. **Uppdatering** sker via `data-update.yml`, som hämtar externa feeds och öppnar en pull request
   märkt `needs_review`. Extern data skriver aldrig över mänskligt verifierade uppgifter; konflikter
   markeras `disputed`.

## Vyer och filter för registerdata

Katalogen kan filtreras på ursprung (original/ny), PoC-/exploateringsstatus, materialtyp, typ av
initiallösenord, dokumentationsluckor (setupmanual verifierad eller ej) och registrets källstatus.
Produkt- och protokollsidorna har sektionerna _Registeruppgifter och granskning_, _Konton och
initiallösenord_ och _Setup och installation_; CVE-sidan visar hotunderlaget som fyra separata
signaler (offentlig PoC, daterat SSVC-råvärde, aktiv exploatering, materialtyp). Vyn `/konton`
sammanställer kontonamn och lösenordstyp per post. Datakvalitetsvyn listar länkkontroller och
registerkonflikter. Kontrollera faktiska filnamn under `src/features/`.

Katalogen (`/katalog`) har en filterkolumn och en tät tabell. Klicka på en rad för att fälla ut
allt dokumenterat om posten utan att lämna listan: verifierade CVE-kopplingar med KEV-/PoC-status,
dokumenterat standardkonto och typ av initiallösenord (aldrig lösenordsvärden),
setupdokumentation, upptäcktsheuristik (för egen auktoriserad inventering), PoC-/hotunderlag som
evidensnivå och rekommenderad åtgärd. Växla mellan **Tabell** (tät lista,
utfällbara rader) och **Dossier** (ett kort per produkt med allt samlat) via knapparna i resultatlistan;
valet speglas som `view=cards` i adressen. Snabbfiltret `has=` (`kev`, `poc`, `cve`, `defaultpw`,
`account`) och `sort=severity` (KEV först, sedan högsta CVSS) speglas i adressen. Den tidigare
vyn `/oversikt` är sammanslagen med katalogen; gamla länkar omdirigeras dit med motsvarande filter.

Formspråket följer ISA-101 (”high-performance HMI”): grå neutral bas, färg endast för avvikelser
(rött för KEV/aktiv exploatering och hårdkodade uppgifter, gult för rapporterad PoC och svaga
standarduppgifter). Typsnitten (IBM Plex) är självhostade eftersom CSP:n bara tillåter `'self'`.

## Publicering på GitHub Pages

Sajten publiceras på `https://timpan8.github.io/ot-iot-security-intelligence/`.

1. Gå till **Settings → Pages → Build and deployment** och välj **Source: GitHub Actions**.
   Välj inte "Deploy from a branch".
2. Kontrollera att `.github/workflows/deploy.yml` finns på `main`. Den bygger i ett jobb
   (`actions/configure-pages`, `actions/upload-pages-artifact`) och publicerar i ett separat jobb
   (`actions/deploy-pages`) med behörigheterna `pages: write` och `id-token: write` i miljön
   `github-pages`.
3. Första publiceringen sker när en commit når `main`, eller manuellt via **Actions → Deploy →
   Run workflow** (`workflow_dispatch`).
4. Verifiera att sidan laddar och att `public/data/manifest.json` svarar under bas-sökvägen.

Bas-sökvägen sätts i `vite.config.ts` via miljövariabeln `VITE_BASE_PATH` (standard
`/ot-iot-security-intelligence/`). Byter du repo-namn eller använder egen domän, sätt
`VITE_BASE_PATH=/` (eller `/nytt-namn/`) i deploy-workflowen och i `playwright.config.ts`.
Appen använder hash-routing, så djuplänkar fungerar utan 404-fallback på Pages.

### Rekommenderade repo-inställningar

- **Branch protection / ruleset för `main`:** kräv pull request, minst en granskare, status checks
  från `ci.yml` (lint, typecheck, test, validate, build) och blockera force push.
- **Security → Code security:** aktivera **Dependency graph** (krävs för CI-jobbet Dependency
  review, som annars rapporterar fel men inte blockerar), Dependabot alerts och security updates.
  Använd CodeQL default setup eller `codeql.yml` i repot, inte båda.
- **Actions → General → Workflow permissions:** välj **Read repository contents and packages
  permissions** och kryssa i **Allow GitHub Actions to create and approve pull requests**. Det
  sista krävs för att `data-update.yml` ska kunna öppna granskningsbara pull requests.
- **Secrets:** `NVD_API_KEY` är valfri (höjer NVD:s rate limit). Den används endast i Actions,
  aldrig i webbläsaren eller i publik JSON.
- **Environment `github-pages`:** begränsa till `main`.

## Rapportera fel

Fel i data, trasiga länkar eller felaktiga källkopplingar rapporteras som GitHub Issues i detta
repo. Ange post-ID (t.ex. `pf-danfoss-ak-sm-800a`), vilken uppgift som är fel och en primärkälla.
Detta repo är **inte** en kanal för att rapportera nya sårbarheter till tillverkare; använd
respektive PSIRT eller CERT-SE.

## Begränsningar och ansvar

- Innehållet är en sammanställning av publikt tillgängliga uppgifter och innehåller inga
  exploateringsinstruktioner.
- Verifieringsstatus (`verified_primary`, `corroborated_secondary`, `needs_review`, `unknown`,
  `disputed`) visas för varje betydelsefull uppgift. Uppgifter med `needs_review` eller `unknown`
  ska kontrolleras mot tillverkaren innan beslut fattas.
- Riskbedömningen är SSVC-inspirerad men inte officiell SSVC, och den redovisar faktorer separat i
  stället för en universell siffra. Exponering är alltid `unknown` utan auktoriserad inventering.
- Referenser till NIST SP 800-82 Rev. 3 avser fastställd vägledning; Rev. 4 är per 2026-11-07 ett
  offentligt utkast. Hänvisningar till IEC 62443, NIST CSF 2.0 och cybersäkerhetslagen är
  mappningsreferenser, inte påståenden om efterlevnad eller juridiska slutsatser.
- Inget i plattformen skickar kommandon till eller ändrar konfiguration på styrsystem.

Se vidare `docs/ARCHITECTURE.md`, `docs/DATA_MODEL.md`, `docs/RISK_METHOD.md`,
`docs/SECURITY.md`, `docs/SOURCES.md`, `docs/MIGRATION_REPORT.md` och `docs/BACKLOG.md`.

## Licens

MIT, se `LICENSE`. Externa källor och bulletiner omfattas av respektive utgivares villkor.

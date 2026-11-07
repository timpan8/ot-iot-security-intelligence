# Säkerhet

Detta dokument beskriver hotmodellen för den publika plattformen, de skyddsåtgärder som är
inbyggda i kod och pipeline, samt hur fel rapporteras. Repots `SECURITY.md`-funktion på GitHub
pekar hit.

## Hotmodell för en statisk GitHub Pages-sajt

| Hot                                                                | Konsekvens                                                        | Skydd                                                                                                                                                    |
| ------------------------------------------------------------------ | ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Oavsiktlig publicering av anläggningsunika uppgifter               | Kartläggning av verkliga OT-miljöer                               | Skyddsgräns: `FORBIDDEN_PUBLIC_KEYS`, `validate.ts`, `check-artifact.ts`, enhetstester, privat schema utan data                                          |
| XSS via importerad text (bulletiner, NVD-sammanfattningar, URL:er) | Kodkörning i besökarens webbläsare                                | React-escaping, förbud mot `dangerouslySetInnerHTML` (ESLint-regel), `SafeLink` som bara renderar `https://`, Zod-validering av alla strängar och URL:er |
| Skadlig eller felaktig extern feed                                 | Felaktiga sårbarhetspåståenden, överskrivna verifierade uppgifter | Enrichment-cache i PR med `needs_review`, aldrig överskrivning av `verified_primary`, `disputed` vid konflikt                                            |
| Komprometterad beroendekedja (npm, Actions)                        | Bakdörr i bygget                                                  | Lockfile, Dependabot, dependency review, SHA-pinnade actions, minsta `GITHUB_TOKEN`, CodeQL                                                              |
| Läckta hemligheter                                                 | Missbruk av API-nycklar                                           | Inga hemligheter i frontend, JSON eller loggar; `.env.example` har bara platshållare; `NVD_API_KEY` endast som Actions-secret                            |
| Missbruk av Shodan-heuristik                                       | Icke auktoriserad kartläggning                                    | Söksträngar visas med varning, markeras `authorized_inventory_only`, ingen funktion kör sökningar                                                        |
| Felanvändning som exploateringsguide                               | Skada på styrsystem                                               | Endast defensiva åtgärder; inga exploateringssteg lagras eller visas                                                                                     |

## Webbapplikationen

### Content Security Policy

Pages kan inte sätta egna HTTP-headers. Policyn levereras därför som `<meta http-equiv="Content-Security-Policy">` i `index.html`. Avsedd policy:

```text
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
font-src 'self';
connect-src 'self';
object-src 'none';
base-uri 'self';
form-action 'none';
upgrade-insecure-requests
```

Begränsningar: `frame-ancestors`, `report-uri`/`report-to` och `sandbox` har ingen effekt i en
meta-tag. `style-src 'unsafe-inline'` behövs för Tailwinds runtime-fria CSS om inline-stilar
förekommer; ta bort det om bygget inte kräver det. Kontrollera den faktiska policyn i
`index.html`.

### HTTPS och cache

- `*.github.io` serveras över HTTPS med HSTS. Aktivera **Enforce HTTPS** under Settings → Pages
  (standard för github.io-domäner). Egen domän kräver att HTTPS tvingas manuellt.
- Vite ger tillgångar i `dist/assets/` hash-baserade filnamn, vilket gör dem säkra att cacha
  länge. `index.html` och `public/data/*.json` har inga hashar; Pages sätter korta cache-tider för
  dem. Manifestets `generated_at` gör det möjligt att se vilken datagenerering som visas.

### XSS och innehållssäkerhet

- All text renderas via React, som escapar som standard. ESLint-regeln `no-restricted-syntax`
  förbjuder `dangerouslySetInnerHTML`; `no-eval`, `no-implied-eval` och `no-new-func` är fel.
- Externa länkar renderas av `SafeLink` (kontrollera filnamn i `src/components/`) som kräver
  `https://`, sätter `rel="noopener noreferrer"` och `target="_blank"`, och visar värdnamnet.
- Importerad data parsas med `JSON.parse` och valideras med Zod. Ingen `eval`, ingen dynamisk
  kodladdning, ingen HTML i datafiler.
- Sökindexet byggs av validerade strängar; sökfrågor tolkas aldrig som kod eller reguljära uttryck.

## Datapipeline och skyddsgräns

- `scripts/validate.ts` kör Zod på varje publik fil, kontrollerar referensintegritet, räkningar
  (66/55/11/18), https-krav, protokoll utan CVE och rekursivt alla nycklar mot
  `FORBIDDEN_PUBLIC_KEYS`. Icke-noll exit stoppar bygget (`prebuild`).
- `scripts/check-artifact.ts` skannar `dist/` efter förbjudna nycklar och efter `.xlsx`-filer.
  Originalarbetsboken ligger i `sources/original/` och kopieras aldrig till `public/`.
- `schemas/private/assets.ts` ingår inte i `tsconfig.app.json` och får inte importeras från `src/`;
  ett enhetstest bör söka efter sådana importer.
- Observationer är aggregerade, har `representative: false` och inga värdlistor.

## Externa feeds

- `scripts/enrich/http.ts` (kontrollera filnamn) ska ha en allowlist av värdar
  (`services.nvd.nist.gov`, `api.first.org`, `www.cisa.gov`, `raw.githubusercontent.com` för
  CISA CSAF, `cert-portal.siemens.com`, …), timeout, återförsök med backoff, rate limiting (NVD:
  högst 5 anrop per 30 s utan nyckel) och en identifierande `User-Agent`.
- Hämtade svar sparas i `sources/enrichment/` och granskas i pull request. Externa uppgifter blir
  `needs_review`; konflikter mot `verified_primary` blir `disputed`.
- Avvisade CVE:er, omklassningar och feedfel hanteras i diff-rapporten och kräver mänskligt beslut.
- **Inga uppdateringar triggar kommandon mot styrsystem eller ändrar deras konfiguration.**
  Pipelinen läser endast publika feeds.

## GitHub Actions

- `permissions:` sätts explicit per workflow till minsta nödvändiga: `ci.yml` `contents: read`;
  `deploy.yml` `pages: write`, `id-token: write` i deploy-jobbet; `data-update.yml`
  `contents: write`, `pull-requests: write`.
- Tredjepartsactions pinnas till commit-SHA med versionskommentar. Officiella `actions/*` pinnas
  också där det är rimligt.
- Build och deploy är separata jobb; deploy använder miljön `github-pages` med skydd till `main`.
- Dependabot bevakar npm och GitHub Actions. Dependency review körs på pull requests. CodeQL via
  default setup eller `codeql.yml` (inte båda).
- Hemligheter: `NVD_API_KEY` är valfri och används bara av enrichment-jobbet. Loggar får inte
  skriva ut headers eller nycklar.
- Skyddad `main`: kräv pull request, granskning och gröna status checks.

## Secrets-policy

- `.env.example` innehåller endast platshållare. `.env*` är gitignorerat.
- Inga nycklar, tokens eller interna värdnamn i frontend, `public/data`, källkod, CI-loggar,
  tester eller fixtures.
- Hittas en hemlighet i historiken: rotera den först, rensa historiken sedan.

## Ansvarsfull användning

- Plattformen är defensiv och beskriver risktyper och åtgärder, inte exploateringssteg.
- Shodan-heuristik ska endast användas för egen eller auktoriserad inventering, kompletterad med
  `net:` för egna IP-intervall, och träffar är aldrig bevis för en viss produkt eller sårbarhet.
- Detta repo är inte en kanal för att rapportera nya sårbarheter i tillverkares produkter.
  Sådana rapporter går till respektive PSIRT (länkar i `vendors.json`) eller CERT-SE.

## Rapportera fel i repot eller datan

1. Fel i data (felaktig CVE-koppling, fel version, trasig länk): öppna ett GitHub Issue med
   post-ID, fält, föreslagen rättelse och primärkälla.
2. Säkerhetsbrist i själva webbappen eller pipelinen (t.ex. XSS, läckt uppgift): öppna ett
   privat säkerhetsärende via **Security → Report a vulnerability** om funktionen är aktiverad,
   annars ett Issue utan tekniska detaljer med begäran om kontakt.
3. Uppgifter som kan vara anläggningsunika och hamnat i publik data behandlas som incident:
   rapportera omedelbart, posten tas bort och historiken rensas.

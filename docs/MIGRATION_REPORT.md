# Migrations- och datakvalitetsrapport

**Datum:** 2026-11-07 · **Källa:** `OT_IoT_sarbarhetsoversikt_66_system_2026-11-07.xlsx` (sha256 `1a09ad42eb3590bdb6be2f79b61a84b617657228e2ff678d2e932ca8a3242d0d`) · **Schema:** 1.0.0

Rapporten sammanfattar vad som migrerades, vad som verifierades mot primärkällor, vad som är okänt och vad som kräver mänsklig granskning. Siffrorna är hämtade ur `public/data/` efter `npm run data:all`.

## 1. Omfattning och utfall

| Mått                                          | Värde                                                                                                                   |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Blad lästa                                    | 3 (`66 system och tjänster`, `Läs först`, `Sammanställning`)                                                            |
| Dataposter                                    | 66 (rad 2–67), inga dubbletter, 15 kolumner                                                                             |
| Produktfamiljer / protokoll                   | 55 / 11                                                                                                                 |
| Kategorier                                    | 18 (stämmer med bladet `Sammanställning`)                                                                               |
| Poster med CVE/bulletin-fält i arbetsboken    | 8                                                                                                                       |
| Poster med käll-URL i arbetsboken             | 10                                                                                                                      |
| Leverantörer                                  | 40                                                                                                                      |
| CVE-poster (alla verifierade mot NVD API 2.0) | 43 (varav 22 från ICSA-26-057-10 utöver arbetsbokens 1)                                                                 |
| Bulletiner                                    | 11                                                                                                                      |
| Produkt–sårbarhetsmatchningar                 | 51 (44 berörda, 4 ej berörda, 3 under utredning)                                                                        |
| Kontroller                                    | 20                                                                                                                      |
| Källor                                        | 118 (114 klassade primära, 51 kontrollerade OK, 3 blockerade, 64 okontrollerade)                                        |
| Påståenden (claims)                           | 37 (1 verifierat, 33 behöver granskning – varav 23 gäller XWEB Pro:s overifierade fixversion – 2 okända, 1 motstridigt) |

Alla 66 poster bevarar samtliga 15 originalvärden (`original.values`) och spårbarhet per cell (`provenance`: blad, rad, kolumn, rubrik). Ingen post har tagits bort eller slagits ihop.

## 2. Verifieringsgrad

| Status per katalogpost | Antal |
| ---------------------- | ----- |
| verified_primary       | 6     |
| corroborated_secondary | 41    |
| needs_review           | 19    |
| unknown / disputed     | 0     |

Tolkning: _verified_primary_ kräver att alla CVE-matchningar för posten är bekräftade i primärkälla (tillverkarens CSAF, NVD-post från CNA eller CISA CSAF). _corroborated_secondary_ ges poster utan CVE-koppling men med produktspecifik tillverkardokumentation. _needs_review_ gäller poster som bara stöds av branschguide/arbetsbok eller som har ogranskade påståenden.

## 3. Bekräftat mot primärkälla (2026-11-07)

| Påstående                                                                                       | Källa                                                      | Resultat                                                               |
| ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------- |
| CVE-2025-41450 gäller AK-SM 8xxA före 4.2                                                       | NVD (CNA Danfoss), referens till DSA-2025-03-01            | Bekräftat                                                              |
| CVE-2025-41451/41452 gäller AK-SM 8xxA före 4.3.1                                               | NVD (CNA Danfoss)                                          | Bekräftat (CVE); bulletinkoppling DSA-2025-08-01 ej läsbar, se §5      |
| CVE-2026-34223 berör Desigo CC ClickOnce Client V6/V7 och Installed Client V6/V7, ej V8/V9/Flex | Siemens SSA-330084 CSAF (interim, v1 2026-09-08)           | Bekräftat. Ingen fix (`none_available`). PXC nämns inte                |
| SSA-568427 = CVE-2022-38465; S7-1200 < V4.5.0, S7-1500 < V2.9.2                                 | Siemens CSAF (final, 2022-10-11)                           | Bekräftat; arbetsboken saknade CVE-ID                                  |
| CVE-2026-21718 och övriga 22 CVE i ICSA-26-057-10 berör XWEB 300D/500D/500B PRO ≤ 1.12.1        | CISA ICSA-26-057-10 CSAF + NVD (CNA CISA, status Analyzed) | Bekräftat; alla 23 CVE importerade som matchningar                     |
| CVE-2025-6519 och CVE-2025-52543…52550 berör E3 Site Supervisor < 2.31F01                       | NVD (CNA Armis, status Analyzed, CPE)                      | Bekräftat; intervallet expanderat först efter att varje ID verifierats |
| CVE-2025-52551 (E2)                                                                             | NVD (CNA Armis, Deferred)                                  | CVE bekräftat; ingen versionsavgränsning                               |
| CVE-2023-6448 i CISA KEV sedan 2023-12-11                                                       | KEV-katalog 2026.11.06                                     | Bekräftat; enda KEV-träffen bland 43 CVE                               |
| CVE-2024-1480, CVE-2025-2595, CVE-2025-41659, CVE-2025-41691 finns                              | NVD                                                        | Bekräftat som CVE; produktmappning se §5                               |
| EPSS för 43 CVE                                                                                 | FIRST EPSS API (datum 2026-11-07)                          | Hämtat (högst: CVE-2025-41451 0,045 / percentil 0,91)                  |

## 4. Okänt (unknown)

- **Patchningsgrad**: 65/66 ”Uppgift saknas”. Danfoss-observationen (58 % av 50) är lagrad som icke-representativ observation med okänd metod och okänt datum.
- **Exponering**: alltid `unknown` – katalogen har ingen asset-data.
- **Livscykel**: 35 produktfamiljer har okänd livscykelstatus; 4 anges EOL av arbetsboken utan verifierat datum.
- **Hot/allvarlighet**: 58 poster har `unknown` eftersom de saknar verifierad CVE-koppling. Detta är inte ”låg risk”.
- **PSIRT-portaler**: 30 av 40 leverantörer saknar verifierad säkerhetsportal-URL.

## 5. Kräver mänsklig granskning (needs_review / disputed)

| Post                             | Fråga                                                                                          | Status              |
| -------------------------------- | ---------------------------------------------------------------------------------------------- | ------------------- |
| Danfoss AK-SM 800A               | Omfattar DSA-2025-08-01 verkligen CVE-2025-41451 och 41452? Sidan gav HTTP 403 (bot-skydd).    | needs_review        |
| Danfoss AK-SM 800A               | ”Senast angiven 5.3.x (okt 2026)” – ej verifierat mot nedladdningssidan.                       | needs_review        |
| Copeland XWEB Pro                | ”Åtgärdad version 1.13” – CISA anger fix utan versionssiffra.                                  | needs_review        |
| Copeland E2                      | EOL oktober 2024 och berörda versioner ej verifierade mot Copeland.                            | needs_review        |
| ABB AC500 V3                     | Tre CODESYS-CVE:er; ABB:s mappning och gränsen ”< 3.9.0” ej verifierad.                        | under_investigation |
| Unitronics Vision                | Berörda modeller/versioner för CVE-2024-1480 (ICSA-24-109-01 ej läst).                         | needs_review        |
| Siemens Desigo CC                | NVD-beskrivningen nämner V8/V9/Flex som berörda; CSAF säger ej berörda. Projektet följer CSAF. | **disputed**        |
| CAREL pCOWeb                     | ”Tidigare rapporterade CVE gäller OEM-konfigurationer” – inga ID:n i arbetsboken.              | unknown             |
| Fronius Datamanager, PTC Kepware | Tillverkarpåståenden återgivna i arbetsboken men inte omlästa.                                 | needs_review        |
| 4 EOL-produkter                  | EOL-datum saknas/ej verifierat.                                                                | needs_review        |

## 6. Identifierade motstridiga eller felaktiga uppgifter i arbetsboken

1. **Desigo CC (rad 22)**: ”ClickOnce Client V6: alla versioner” är ofullständigt – bulletinen omfattar även ClickOnce V7 och Installed Client V6/V7, och anger uttryckligen V8/V9 och Flex Client som ej berörda. Rättat med 8 separata matchningar.
2. **S7-1500 (rad 47)**: bulletin-ID stod i CVE-kolumnen. Rättat: bulletin som `advisory`, CVE-2022-38465 som `vulnerability`.
3. **S7-1200 (rad 12)**: käll-URL till SSA-568427 men tomt CVE-fält. Matchning tillagd från CSAF.
4. **Danfoss (rad 3)**: riskförklaringen använder trunkerade ID:n (”CVE-41450”). Originaltext bevarad; fullständiga ID:n i matchningar.
5. **Copeland E3 (rad 8)**: intervall ”CVE-2025-52543–52550” – varje ID verifierat separat innan expansion.
6. **XWEB Pro (rad 5)**: arbetsboken listar 1 av 23 CVE i bulletinen; övriga 22 importerade från CSAF/NVD (svensk sammanfattning saknas); fixversion overifierad.
7. **Prioritet (kolumn O)**: identisk för alla 66 → lagrad som `legacy_priority_text` och flagga `conditional_priority_only`, används inte som risknivå.
8. **Dokumentation (kolumn L)**: 12 rader pekar på NIST SP 800-82r3 i stället för produktdokumentation → `industry_guide_only`.

## 7. Tekniska säkerhetsbeslut

- Två datanivåer: publik katalog i `public/data`; privat asset-modul finns bara som schema (`schemas/private/assets.ts`) och blockeras av validate/check-artifact/tester (FORBIDDEN_PUBLIC_KEYS).
- Zod strict + referensintegritet + antalskontroll körs före varje build (`prebuild`); artefaktkontroll efter (`postbuild`).
- Ingen HTML-rendering av data, https-only-länkar, CSP via meta, inga API-nycklar i webbläsaren.
- Externa feeds (NVD/EPSS/KEV/CSAF) hämtas med host-allowlist, rate limiting, ETag-cache och skapar PR med `needs_review`; `verified_primary` skrivs aldrig över automatiskt – konflikter listas i diff-rapporten.
- GitHub Actions: minsta `GITHUB_TOKEN`, SHA-pinnade actions, separata build/deploy-jobb, Dependabot, CodeQL, dependency review.
- Egen xlsx-läsare (fflate + fast-xml-parser) eftersom exceljs inte kunde läsa arbetsbokens `x:`-namnrymd och SheetJS npm-paket är inaktuellt.

## 8. Prioriterad backlog

Se `docs/BACKLOG.md`. Högst prioritet: (1) manuell läsning av Danfoss DSA-sidorna, (2) verifiera XWEB-fixversion och E2-EOL hos Copeland, (3) ABB-bulletin för AC500 V3/CODESYS, (4) PSIRT-URL:er för 30 leverantörer, (5) länkkontroll i CI (`data:check-links`), (6) svenska sammanfattningar för de 22 XWEB-CVE:erna.

---

# Import 2 – 125-postregistret (`OT_IoT_125_poster_losenordsstatus.xlsx`)

**Datum:** 2026-11-07 · **Fil-SHA-256:** `2e017d3c9f1c28ea82aa05b474c9388f39db8d7350df00d2b2103741238469f1` · **Importversion:** `register-import-1.0.0` · **Kommando:** `npm run data:import:register` (ingår i `npm run data:all`)

## 1. Struktur och kontrolltal

Alla 13 blad lästes; kolumner identifierades via rubriktext (karta i `scripts/import-register.ts`, `SHEETS`). Bladet _Granskningsrapport_ innehåller arbetsbokens egna kontrolltal i kolumn B; de jämförs maskinellt med beräknade tal (`workbook_control_totals` i `sources/raw/register/import-report.json`). Samtliga stämmer:

| Kontrolltal                                    | Arbetsboken  | Beräknat                         |
| ---------------------------------------------- | ------------ | -------------------------------- |
| Totalt i Register / produkter / tjänster       | 125 / – / –  | 125 / 114 / 11                   |
| Originalposter (produkter / tjänster)          | 66 (55 / 11) | 66 (55 / 11)                     |
| Nya produktfamiljer                            | 59           | 59                               |
| Unika CVE i verifierat urval                   | 344          | 344                              |
| CVE-/produktrelationer                         | 349          | 349                              |
| Unika CVE med KEV-träff                        | 2            | 2 (CVE-2023-6448, CVE-2025-0994) |
| Kontrollerade CVE (Hotunderlag)                | 344          | 344                              |
| Poster i dokumentöversikten (Setup och konton) | 125          | 125                              |

Strukturavvikelser (rapporterade, inte tolkade): Källdatum är fritext för 65 Register-rader och datum för 60 (bevaras verbatim); Register-kolumnen ”CVE – verifierat urval” är trunkerad (”ytterligare N – se Sårbarheter”) för 6 poster, varför relationerna tas från bladet Sårbarheter; Hotunderlag har en rad per CVE medan 5 CVE är kopplade till flera produkter i Sårbarheter (hotunderlaget kopplas därför per CVE); Länkkontroll innehåller 2 `http://`-URL:er som lagras som text i `link_checks` och aldrig renderas som länk. Lösenordskolumnerna i Register och Setup och konton är identiska (125/125).

## 2. Importutfall (idempotent)

| Mått                                                            | Värde                                                                                                       |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Register-ID skapade / uppdaterade / oförändrade                 | 125 skapade vid första körningen; omkörning: 0 skapade, 125 oförändrade                                     |
| Konfliktmarkerade poster                                        | 1 (OT-041 ABB AC500 V3)                                                                                     |
| Original-rader kopplade till befintliga projekt-ID (rad + namn) | 66 av 66, inga namnavvikelser                                                                               |
| Nya katalogposter                                               | 59 (ID `pf-<leverantör>-<slug>`, mappning i `sources/curated/register_id_map.json`)                         |
| Nya leverantörer                                                | 29 (totalt 69), samtliga `verification_status: unknown` för PSIRT-portal                                    |
| Kategorier                                                      | 46 (fri text) med profil i `sources/curated/category_profiles.json`; ingen kategori saknar profil           |
| Kontroller                                                      | K1–K7 mappade till 21 kontroller (`register_code`, `verification_method`); K7 ny kontroll för medicinteknik |

Omkörning av importen ger identiska bladfiler och identisk ID-mappning (verifierat med `diff -r`; endast rapportens `imported_at` skiljer).

## 3. Relationer, verifiering och hotunderlag

| Mått                                                                               | Värde                                                                                                                                                                                     |
| ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Produkt–CVE-relationer från registret                                              | 349 (många-till-många; 5 CVE i flera produkter)                                                                                                                                           |
| … varav annoterade på befintliga kuraterade matchningar                            | 41 (projektets manuella bedömning behålls, registrets källtext läggs till)                                                                                                                |
| … varav nya matchningar (`match-reg-…`)                                            | 308                                                                                                                                                                                       |
| Verifiering mot hämtade CSAF-dokument (60 bulletiner, `data:enrich:csaf-register`) | 347 `verified_primary` (CVE i bulletinen och produktnamn i `known_affected`), 2 `corroborated_secondary` (cve.org-källor utan bulletin), 0 `needs_review`                                 |
| Fixtillgänglighet för nya matchningar (ur CSAF `remediations`)                     | 198 vendor_fix, 99 mitigation/workaround, 11 none_available/no_fix_planned                                                                                                                |
| Versionsregel                                                                      | `source_text` med exakt källtext (ingen tolkning av versionsgränser)                                                                                                                      |
| CVE-poster                                                                         | 347 (344 register + 3 projektets CODESYS-CVE); alla med NVD-post (`data:enrich`), EPSS (2026-11-07) och KEV-kontroll (katalog 2026.11.06)                                                 |
| Hotunderlag per CVE                                                                | 344: SSVC `none` 301, `missing` 22, `poc` 19, `active` 2; materialtyp: 332 utan direktlänk, 3 emulator/rekonstruerad PoC, 1 publikt exploitarkiv, 1 publicerad komponentexploit, 7 övriga |
| Bulletiner                                                                         | 70 (11 tidigare + 59 CISA ICSA/ICSMA 2025; 61 final, 1 interim, 8 okänd status)                                                                                                           |
| Källor                                                                             | 1 332 (509 med dokumenthash från Källmanifest/Hotkällor; 487 ok, 37 blockerade, 24 trasiga, 11 omdirigerade, 773 okontrollerade)                                                          |
| Länkkontroller                                                                     | 210 (148 × 200, 35 × 403, 20 SSL-fel, 7 övriga)                                                                                                                                           |

Evidensnivåerna hålls isär i modellen (`threat_intel`): offentlig PoC enligt CISA SSVC (daterad), SSVC-råvärde, aktiv exploatering (KEV) och materialtyp (emulator, detektionsverktyg, komponentexploit …) är separata fält. SSVC `none` lagras med bedömningsdatum och presenteras som ”ingen PoC uppgiven vid bedömningen”, inte som frånvarobevis. Riskmetoden låter PoC-status höja hotnivån till högst _medium_; endast KEV ger _high_.

## 4. Konton, lösenord och setupdokumentation

Arbetsboken innehåller **inga lösenordsvärden** (kolumnerna är ”utan värden”); importen lagrar kontonamn, lösenordstyp, bytekrav och källor. Förbjudna nycklar (`password`, `password_value`, `passwd`, `secret`, `api_key`, `credential_value`) stoppar bygget.

| Lösenordstyp (initial-/fabrikslösenord)                                                                           | Antal poster |
| ----------------------------------------------------------------------------------------------------------------- | ------------ |
| Okänt – typ ej verifierad                                                                                         | 90           |
| Ej tillämpligt – implementation styr (protokoll)                                                                  | 11           |
| Gemensamt standardlösenord dokumenterat                                                                           | 7            |
| Lösenord väljs/skapas vid driftsättning                                                                           | 6            |
| Hårdkodade uppgifter i berörd version                                                                             | 4            |
| Modell-/versions-/batchberoende                                                                                   | 2            |
| Förutsägbar inbyggd mekanism / versionsberoende / enhetsunikt (dok.) / enhetsunikt (leverans) / typ ej fastställd | 1 vardera    |

Namngivna konton: 16 (t.ex. `Supervisor`, `admin`, `root`, `apc`, `pi`, `Liebert`), varav 3 poster beskriver användarskapat konto vid driftsättning (räknas inte som kontonamn). Setupdokument: 97 med kontrollerad dokumentidentitet, 57 direkta manualer/handböcker, 17 där exakt setupmanual saknas (flagga `setup_manual_unverified`); dokumentportal eller säkerhetsguide räknas inte som verifierad installationsmanual.

## 5. Bevarade manuella bedömningar och konflikter

- Alla 66 originalposter behåller kuraterade matchningar, claims, observationer och källor; registrets fält läggs till som `register`-block.
- **OT-041 ABB AC500 V3:** registret saknar projektets tre CODESYS-CVE (CVE-2025-2595, -41659, -41691). Projektets `under_investigation`-matchningar behålls; konflikten är redovisad i `sources/raw/register/conflicts.json`, som `disputed`-claim och flagga `register_conflict`. Registret bekräftar bedömningen ”komponent-CVE utan verifierad ABB-koppling”.
- Registrets **Radgranskning** (status ”Öppen – lokal inventering återstår” för alla 125) visas per post men påverkar inte verifieringsstatus eller risknivå.
- Registrets prioritet (”P1 – verifiera omgående” 2, ”P2 – snar verifiering” 123) lagras som `priority_text` och är villkorlig vid _konstaterad_ exponering; observerad exponering är ”Ej undersökt” för alla rader och publik exponeringsfaktor förblir `unknown`.

## 6. Verifiering (faktiskt utfall)

| Kontroll                                                                   | Resultat                                                                                                                       |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `npm run data:all` (import → import:register → build → validate → schemas) | OK: 125/114/11, 347 CVE, 359 matchningar, 1 332 källor, 210 länkkontroller                                                     |
| Idempotens (två körningar)                                                 | Identiska bladfiler och ID-mappning                                                                                            |
| `npm run lint` / `npm run typecheck` / `npm run format:check`              | 0 fel (2 kända react-refresh-varningar)                                                                                        |
| `npm test` (Vitest)                                                        | 95 tester gröna (import, idempotens, bevarade bedömningar, konflikter, kodmappningar, UI, export, enrich)                      |
| `npm run build`                                                            | OK, artefaktkontroll: inga interna nycklar, data identisk med `public/data`                                                    |
| `npm run test:e2e` (Playwright)                                            | 9 tester gröna (filter origin=new ⇒ 59 av 125, ABB ASPECT-sektioner, `/konton`, Danfoss DSA-länkar, CVE-2025-41450 ”Emulator”) |
| `npm run data:diff`                                                        | 0 konflikter mot kuraterade uppgifter                                                                                          |

## 7. Kvarstående begränsningar (inte verifierade uppgifter)

- Svenska sammanfattningar (`summary_sv`) saknas för de nya CVE:erna; NVD-texten visas.
- PSIRT-/säkerhetsportaler för de 29 nya leverantörerna är inte verifierade.
- CSAF-verifieringen matchar produktnamn mot `known_affected` med tokenjämförelse; installerad enhet, hårdvarurevision och firmware är inte bedömda.
- Fixtillgänglighet ur CSAF anger att en åtgärd finns, inte vilken version som är installerad eller att åtgärden är tillämpbar i en viss anläggning.
- Länkkontroll och dokumenthashar återspeglar arbetsbokens kontroll 2026-11-07; länkarna är inte omkontrollerade i projektet (`data:check-links` kan köras separat).
- Hotunderlagets PoC-länkar har inte öppnats eller körts; materialtyp och källkritisk kommentar är registrets bedömning.

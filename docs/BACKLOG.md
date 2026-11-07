# Backlog

Prioriterad lista över vidareutveckling och tekniska skulder. Prioritet: **P1** bör göras före
nästa datauppdatering, **P2** inom fas 2, **P3** när behov uppstår.

## P1 – Datakvalitet och källor

### Efter registerimporten (import 2, 2026-11-07)

- [ ] **Svenska sammanfattningar (`summary_sv`)** för de ~300 nya CVE-posterna från registret;
      i dag visas NVD:s engelska text eller registrets CWE-text.
- [ ] **PSIRT-/säkerhetsportaler för de 29 nya leverantörerna** i `vendors.json` (Nedap, mySCADA,
      Hitachi Energy, B&R, Western Telematic, AutomationDirect, Trimble, ORing, OutBack Power,
      Dingtian, Subnet Solutions, Lantronix, ALBEDO, Vestel, Nice, Planet, KUNBUS, Optigo,
      Milesight, Vertiv, Consilium, CyberData, Dover, ControlID, Samsung, Honeywell, Orthanc,
      INFINITT, Nihon Kohden). Endast verifierade länkar.
- [ ] **Manuell granskning av registerrelationer som inte blev `verified_primary`** (2
      `corroborated_secondary`) och av `needs_review`-poster i `credentials` (källa saknas).
- [ ] **Hotunderlag per produkt för de 5 CVE som berör flera produkter.** Registret knyter varje
      CVE till en produkt (`subject_product_family_id`); bedöm om övriga produkter behöver egna
      källkritiska kommentarer.
- [ ] **Registerkonflikt OT-041 (ABB AC500 V3).** Registret saknar projektets tre CODESYS-CVE;
      behålls som `under_investigation` + `disputed`-claim tills ABB-bulletin hittats.
- [ ] **Vulnerabilities utan NVD-post** (`nvd_status: 'unknown'`): kör `data:enrich` tills alla
      347 CVE har cache; posterna byggs tills dess från registrets CVSS med `needs_review`.
- [ ] **Kontrollera registrets setupdokument** där `is_verified_setup_manual=false` (17 poster) och
      där direkt hämtning gav 403/SSL-fel – manuell läsning krävs.
- [ ] **Kategoriprofiler**: granska `ot_impact`-default för de 28 nya kategorierna i
      `category_profiles.json` med verksamhetsexpert.
- [ ] **Länkkontroll i CI** även för registrets 210 URL:er (`data:check-links`), så att
      `availability` uppdateras utan att fälla bygget.

### Tidigare

- [x] **Hämta övriga 22 CVE i CISA ICSA-26-057-10** (Copeland XWEB Pro). Klart 2026-11-07: bulletinens
      23 CVE är importerade som verifierade matchningar (CSAF product_status + NVD). Kvar: svensk
      sammanfattning (`summary_sv`) för de 22 nya posterna.
- [ ] **Manuell verifiering av Danfoss DSA-2025-03-01 och DSA-2025-08-01.** Sidorna ligger bakom
      bot-skydd (HTTP 403 för automatiserade hämtningar). CVE-uppgifterna är bekräftade via NVD-
      poster från CNA Danfoss; själva bulletinsidorna, revisionshistorik och uppgiften om
      ”5.3.x (okt 2026)” behöver kontrolleras manuellt.
- [ ] **Fixversion XWEB Pro ”1.13”.** CISA/CSAF anger ”uppdatera till senaste version” utan
      versionsnummer. Verifiera mot Copelands uppdateringssida eller behåll `needs_review`.
- [ ] **ABB AC500 V3 och CODESYS-CVE:er.** CVE-2025-2595, -41659, -41691 är CODESYS-komponent-
      sårbarheter (CERT@VDE). ABB-specifik berörd version (”< 3.9.0”) saknar primärkälla; hitta ABB:s
      bulletin eller behåll `under_investigation`.
- [ ] **PSIRT-/säkerhetsportaler för leverantörer utan känd URL** i `vendors.json`. Lägg till endast
      verifierade länkar.
- [ ] **Länkkontroll i CI** (`data:check-links`) som skriver `sources/link-report.json` och
      flaggar `broken_link` utan att fälla bygget.
- [ ] **Svenska sammanfattningar (`summary_sv`)** för alla CVE-poster, granskade mot originaltext.

## P2 – Fas 2 enligt masterprompten

- [ ] **Trendkurvor** via versionerade snapshots av `manifest.counts` och KEV/EPSS per CVE.
- [ ] **Tillverkarbevakning**: CSAF-provider-metadata och RSS/Atom från PSIRT:er i enrich-pipelinen.
- [ ] **TLP-märkning och hantering av bulletiner** (allt publikt är TLP:CLEAR; fält för framtida
      privat modul).
- [ ] **MITRE ATT&CK for ICS-koppling** när belagd i primärkälla (t.ex. CISA-bulletiner).
- [ ] **IEC 62443 / NIST CSF 2.0-kontrollmappning** i `controls.framework_refs`, fortfarande
      märkt `mapped_reference`, aldrig som efterlevnad.
- [ ] **Ändringsnotiser** från `claims.history` och diff-rapporter; **RSS-feed** för godkända
      uppdateringar genererad vid bygge.
- [ ] **Språkväxling** (sv/en) med i18n-lager utan ändring av datamodell.
- [ ] **Cybersäkerhetslagen-fält** (riskhantering, tillgångsinventering, incidenthantering,
      leveranskedja, kontinuitet) som generella referenser i åtgärdsguiderna.
- [ ] **Automatisk hantering av avvisade/omklassade CVE:er** i diff-rapporten (REJECTED-status,
      ändrad CPE-räckvidd).

## P3 – Plattform och drift

- [ ] **Privat asset-modul** med autentisering och separat hosting (inte GitHub Pages), som
      implementerar `schemas/private/assets.ts`, riskacceptans och åtgärdsstatus.
- [ ] **Lighthouse/tillgänglighetstest** i CI (axe) utöver jsx-a11y-lint.
- [ ] **Visuell regressionstest** för kärnvyer.
- [ ] **Export till CSAF/OpenVEX** av matchningar för maskinläsbar utväxling.
- [ ] **Ersätt `legacy-peer-deps`** i `.npmrc` när npm/Vitest/Playwright-peer-konflikten är löst.
- [ ] **Uppgradera ESLint till v10** när `typescript-eslint` och pluginerna stödjer det.

## Kända begränsningar som inte är buggar

- Exponering är alltid `unknown` i publik data (avsiktligt).
- 58 av 66 poster saknar CVE-referens i källan; det speglas, inte fylls i.
- Patchningsgrad är ”Uppgift saknas” för 65 poster; Danfoss-observationen (58 % av 50 värdar) är
  märkt icke-representativ med okänd metod och okänt observationsdatum.

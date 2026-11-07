# Bidra

Tack för att du vill förbättra kunskapsbasen. Det viktigaste kravet är **källkritik**: ingen
siffra, sårbarhetsmatchning eller fixversion får läggas till utan källa, och ingen uppgift får
gissas.

## Grundregler för data

1. **Fabricera aldrig.** Saknas uppgiften: `null` + `verification_status: 'unknown'`. Finns ett
   påstående utan primärkälla: `needs_review`. Motsäger källor varandra: `disputed` med
   `conflict_note`.
2. **Primärkälla först.** Tillverkarens PSIRT/CSAF, CERT (CISA, CERT-SE, CERT@VDE) eller NVD-post
   från ansvarig CNA ger `verified_primary`. Forskningsrapporter och media ger högst
   `corroborated_secondary` och ska märkas som sekundära.
3. **Varje påstående har källor.** Lägg till källan i `sources/curated/sources.json` med
   `supports_claims` och referera `source_ids` från posten.
4. **Protokoll får inga CVE-matchningar.** En CVE som rör en implementation hör till den
   produktfamiljen, inte till protokollet.
5. **Expandera inte CVE-intervall** förrän varje ID är verifierat i NVD och finns i
   `vulnerabilities`.
6. **Skriv inte över `verified_primary`** med extern data. Redovisa konflikten i stället.
7. **Inga anläggningsunika uppgifter.** Inga IP-adresser, värdnamn, serienummer, byggnader, ägare,
   kontakter, nätzoner eller scanningresultat. Validatorn fäller bygget, men låt det inte gå så
   långt.
8. **Inga exploateringsinstruktioner.** Beskriv risktyp och defensiv åtgärd.

## Lägga till eller ändra kuraterad data

| Vad                   | Fil                                                                  | Kommentar                                                                                                                       |
| --------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Leverantör            | `sources/curated/vendors.json`                                       | PSIRT-länk endast om verifierad                                                                                                 |
| Bulletin              | `sources/curated/advisories.json`                                    | Ange `advisory_id`, `url`, gärna `csaf_url`, `cve_ids`, `status`                                                                |
| CVE-annotering        | `sources/curated/vulnerability_overrides.json` (kontrollera filnamn) | `summary_sv`, `advisory_ids`, `exploitation_evidence`, granskningsnoter. Själva CVE-fakta kommer från `sources/enrichment/nvd/` |
| Produkt–CVE–version   | `sources/curated/matches.json`                                       | En post per komponent och CVE; ange `status`, `version_rule`, `fix`, `evidence`, `source_ids`                                   |
| Åtgärd                | `sources/curated/controls.json`                                      | `order_hint`, `limitations`, `requires_operational_approval`                                                                    |
| Radvisa korrigeringar | `sources/curated/overrides.json`                                     | Alias, leverantör, livscykel, OT-roll, protokoll, parsade CVE-ID:n, oexpanderade intervall, riskoverrides med motivering        |
| Observation           | `sources/curated/observations.json`                                  | Endast aggregerat, `representative: false`, metod/period/urval                                                                  |

Kontrollera faktiska filnamn i `sources/curated/`.

Arbetsgång:

```bash
npm run data:build
```

```bash
npm run data:validate
```

```bash
npm test
```

Starta sedan `npm run dev` och kontrollera posten i detaljvyn och i datakvalitetsvyn.

## Uppdatera externa uppgifter

Kör `npm run data:enrich` (lokalt eller via `data-update.yml`) och granska diffen i
`sources/enrichment/` samt rapporten från `npm run data:diff`. Flytta uppgifter till kuraterad
data medvetet; markera `needs_review` tills någon granskat dem.

## Kod

- TypeScript strikt, ESLint och Prettier (`npm run lint`, `npm run format`).
- Inga nya beroenden utan motivering i PR:en. Föredra små, underhållna paket.
- Ingen `dangerouslySetInnerHTML`, ingen `eval`, inga externa anrop från webbläsaren.
- Nya vyer ska fungera på mobil, ha tillgängliga komponenter och visa `verification_status`
  där det är relevant.

## PR-checklista

- [ ] `npm run lint`, `npm run typecheck`, `npm test`, `npm run build` gröna lokalt
- [ ] `npm run data:validate` grönt; räkningar fortfarande 66/55/11/18
- [ ] Varje ny/ändrad uppgift har `source_ids` och rimlig `verification_status`
- [ ] Inga anläggningsunika uppgifter, inga hemligheter, inga exploateringssteg
- [ ] `docs/SOURCES.md` och/eller `docs/MIGRATION_REPORT.md` uppdaterade om källor eller
      korrigeringar ändrats
- [ ] Ändringar i workflows: actions pinnade till SHA, `permissions:` minsta möjliga

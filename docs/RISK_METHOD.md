# Riskmetod

Plattformen använder en transparent, OT-anpassad prioriteringsmetod som redovisar **separata
faktorer** i stället för en summerad risksiffra. Metoden är inspirerad av CISA:s
Stakeholder-Specific Vulnerability Categorization (SSVC) men är **inte officiell SSVC**: faktorer,
nivåer och beslutsregler är anpassade för en publik produktkatalog utan asset-data och ska inte
presenteras som ett SSVC-beslut.

Schemat finns i `schemas/risk.ts` (`RiskAssessment`, `method_version: 'risk-method-1.0'`).
Härledningsreglerna nedan beskriver hur `scripts/normalize.ts` är avsett att sätta faktorerna;
kontrollera implementationen i skriptet och i `sources/curated/overrides.json` för eventuella
manuella avvikelser.

## Varför ingen universell risksiffra

- Arbetsboken ger alla 66 poster samma prioritet, ”P1 vid publik åtkomst”. Det är en **villkorlig
  inventeringssignal**, inte en individuell risknivå och inte en uppgift om faktisk exponering.
- En siffra döljer vad som är känt och okänt. I OT är ”okänd firmware” och ”okänd exponering”
  de vanligaste tillstånden, och de måste synas.
- CVSS mäter teknisk allvarlighet, EPSS statistisk sannolikhet för exploatering i allmänhet, KEV
  observerat utnyttjande. Ingen av dem modellerar OT-konsekvens (kylkedja, personsäkerhet,
  energiförsörjning, passage) eller genomförbarhet (underhållsfönster, EOL).

## Faktorer

Varje faktor har `level` (`high`, `medium`, `low`, `unknown`), `basis` (kort förklaring av
underlaget) och `source_ids`.

| Faktor                   | Vad den uttrycker                    | Avsedd härledning                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------ | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `threat`                 | Hot/sannolikhet                      | `high` om någon kopplad CVE är listad i CISA KEV. `medium` om det finns en verifierad (`verified_primary`) `affected`-matchning utan KEV. `low` om bekräftade matchningar saknas men produkten har primärkällor som inte anger kända CVE. `unknown` annars. EPSS anges i `basis` med datum men styr inte nivån ensam.                                                                |
| `severity`               | Teknisk allvarlighet                 | Högsta CVSS-grundpoäng bland bekräftade `affected`-matchningar: ≥ 7.0 → `high`, ≥ 4.0 → `medium`, < 4.0 → `low`. Saknas CVSS → `unknown`. CVSS v3.1 från NVD (Primary) föredras; v4.0 från CNA anges i `basis`.                                                                                                                                                                      |
| `relevance`              | Faktisk relevans för produktfamiljen | `high` vid `verified_primary` `affected`-matchning med explicit versionsregel. `medium` vid `needs_review`/`corroborated_secondary` eller `under_investigation`. `unknown` när versionsuppgift saknas eller matchning saknas.                                                                                                                                                        |
| `exposure`               | Exponering                           | **Alltid `unknown`** i den publika katalogen. Endast en auktoriserad inventering kan fastställa publik eller intern åtkomst. `basis` förklarar detta.                                                                                                                                                                                                                                |
| `ot_impact`              | Potentiell OT-konsekvens             | Kategori-default (tabell nedan), överstyrbar per post i `overrides.json` med motivering.                                                                                                                                                                                                                                                                                             |
| `mitigation_feasibility` | Skydd och genomförbarhet             | `high` om verifierad leverantörsfix finns för bekräftade matchningar. `medium` om endast kompensatoriska kontroller finns, eller fix finns men är overifierad. `low` vid EOL eller ”ingen fix”. `unknown` annars.                                                                                                                                                                    |
| `data_quality`           | Hur väl underbyggd bedömningen är    | `high` om minst en primärkälla och inga allvarliga flaggor. `medium` om primär dokumentation finns men CVE-/versionsuppgifter saknas eller är `needs_review`. `low` om enbart branschguide (`industry_guide_only`) och `missing_primary_source`. Låg datakvalitet sänker säkerheten i bedömningen och leder till `verify_model_and_version`, **aldrig** automatiskt till ”låg risk”. |

### Kategori-default för `ot_impact`

| Kategori                                | Default          | Motivering                                                                                         |
| --------------------------------------- | ---------------- | -------------------------------------------------------------------------------------------------- |
| Kyla                                    | high             | Kylkedja, livsmedels- och läkemedelssäkerhet, ekonomisk skada vid stopp                            |
| PLC, PLC/HMI, DCS, RTU, SCADA, HMI, OPC | high             | Direkt eller indirekt processpåverkan, personsäkerhet                                              |
| Passer                                  | high             | Fysisk säkerhet, dörrar, utrymning                                                                 |
| Kraft, Energi                           | high / medium    | UPS-styrning kan slå ut last; solcells- och värmepumpsgränssnitt främst drift- och integritetsrisk |
| BMS, Ventilation                        | medium           | Inomhusklimat, börvärden, indirekt påverkan på andra system                                        |
| Gateway                                 | medium           | Pivotering in i OT-nät, fjärrservicetunnlar                                                        |
| Kamera, NAS, IoT                        | medium / low     | Integritet, backup/återställning, lateral rörelse                                                  |
| Tjänst                                  | depends → medium | Protokollets konsekvens beror på vad som talar det; redovisas per post                             |

Faktiska värden per post finns i `public/data/product_families.json` och
`protocol_services.json` under `risk.ot_impact.basis`.

## Rekommenderad åtgärd

`recommended_action` väljs i prioritetsordning:

1. `replace_or_isolate_eol` – livscykelstatus `eol` eller `eol_announced` med verifierat eller
   starkt indikerat underlag.
2. `mitigate_if_exposed` – bekräftad `affected`-matchning utan tillgänglig fix, eller KEV-listad
   CVE: vid bekräftad exponering ska kompensatoriska skydd införas omedelbart.
3. `apply_vendor_fix` – bekräftad `affected`-matchning med verifierad fixversion.
4. `harden_configuration` – protokoll/tjänster och produkter där risken främst är
   konfigurationsberoende.
5. `verify_model_and_version` – versions- eller modellberoende uppgifter som inte kan bedömas utan
   inventering (vanligaste fallet i arbetsboken).
6. `monitor` – inga kända kopplingar; bevaka tillverkarens bulletiner.

`rationale` i varje post förklarar valet i klartext. Åtgärderna i `controls` har `order_hint` och
`depends_on_control_ids` för rekommenderad ordning.

## Tolkning av ”P1 vid publik åtkomst”

Originalvärdet bevaras i `risk_summary.legacy_priority_text` och flaggas
`conditional_priority_only`. Det ska läsas som: _om_ en sådan tjänst konstateras publikt nåbar i
en auktoriserad inventering är det en prioriterad avvikelse, oavsett om en specifik CVE finns.
Det säger inget om att systemet är exploaterbart eller faktiskt exponerat.

## Begränsningar hos CVSS, EPSS och KEV i OT-kontext

- **CVSS** värderar inte fysiska konsekvenser, redundans, säkerhetsinstrumenterade system eller
  att ”tillgänglighet” kan betyda kylkedjebrott. Leverantörens CNA-poäng och NVD:s kan skilja;
  båda visas.
- **EPSS** är en modell över sannolikhet för exploateringsförsök på internet i stort. Den säger
  inget om ett isolerat OT-nät och är inte bevis för exploatering. Värdet visas alltid med datum.
- **KEV** betyder observerat utnyttjande i verkliga angrepp, men frånvaro i KEV betyder inte att
  exploatering saknas. Publika PoC:er är en separat signal (`exploitation_evidence`).
- **Frånvaro av CVE** i katalogen (58 av 66 poster) är inte frånvaro av sårbarheter; det är
  frånvaro av uppgift i arbetsboken.

## Framtida privat modul

En separat autentiserad asset-modul (kontrakt i `schemas/private/assets.ts`) kan tillföra:
faktisk `installed_version` (gör `relevance` avgörbar), bekräftad `exposure`, kritikalitet per
anläggning, underhållsfönster, backup/återställning och `risk_acceptance` med giltighetstid. Först
då kan en per-tillgång-prioritering göras. Den publika katalogen ska aldrig påstå faktisk
exponering eller faktiskt antal sårbara installationer.

## Referenser

- CISA SSVC Guide (referens för beslutsfaktorer, inte implementerad som sådan)
- NIST SP 800-82 Rev. 3 (fastställd); Rev. 4 är per 2026-11-07 ett offentligt utkast
- FIRST EPSS, CISA KEV, NVD CVE API 2.0 (se `docs/SOURCES.md`)

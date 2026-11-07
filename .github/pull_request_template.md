## Sammanfattning

<!-- Vad ändras och varför? -->

## Checklista (källkritik och skyddsgräns)

- [ ] Alla nya/ändrade sakuppgifter (CVE, versioner, fixar, exploateringsstatus) har `source_ids` som pekar på primärkällor, eller är märkta `needs_review`/`unknown`
- [ ] Inga fabricerade CVE:er, patchnivåer eller exponeringssiffror
- [ ] Inga anläggningsunika/interna uppgifter (IP, nätzoner, serienummer, ägare, kontakter, scanningresultat) i `public/`, `sources/` eller `src/`
- [ ] Protokoll/tjänster har inte tilldelats produkt-CVE:er
- [ ] `npm run data:validate`, `npm run lint`, `npm run typecheck`, `npm test` och `npm run build` är gröna lokalt
- [ ] Vid automatisk datauppdatering: diff-rapportens konflikter är avgjorda och dokumenterade i `sources/curated/`

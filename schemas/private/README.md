# Privat asset-modul – ENDAST SCHEMA

Denna katalog innehåller **enbart datakontrakt** för en framtida, separat
autentiserad anläggningsinventering. Inga data lagras här och inget i denna katalog
får importeras av frontend eller hamna i `public/` eller `dist/`.

Skyddsgränsen (masterprompt avsnitt 1) verifieras av `scripts/validate.ts`,
`scripts/check-artifact.ts` och enhetstester som skannar efter förbjudna nycklar.

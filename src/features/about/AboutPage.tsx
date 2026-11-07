import { SafeLink } from '@/components/SafeLink';
import { Callout, PageHeader, Section } from '@/components/ui';

const REPO =
  import.meta.env.VITE_REPO_URL ?? 'https://github.com/timpan8/ot-iot-security-intelligence';

export function AboutPage() {
  return (
    <>
      <PageHeader
        title="Om projektet och metodik"
        lead="OT/IoT Security Intelligence Platform är en publik, källkritisk och defensiv kunskapsbas för produktfamiljer och protokoll inom OT/IoT/ICS/BMS/SCADA."
      />
      <div className="space-y-4 prose-sm">
        <Section title="Urval" id="urval">
          <p>
            Katalogen utgår från en inventeringsarbetsbok daterad 2026-11-07 med 66 poster: 55
            produktfamiljer och 11 protokoll/tjänster fördelade på 18 kategorier. Posterna är
            produktfamiljer och protokoll som är vanliga i svenska fastigheter, industri och
            samhällsviktig verksamhet – inte 66 verifierat installerade enheter. Samtliga
            ursprungliga fält bevaras och är spårbara till blad, rad och kolumn.
          </p>
        </Section>
        <Section title="Utökat register (125 poster)" id="register">
          <p>
            I november 2026 importerades ett utökat register med <strong>125 poster</strong> (66
            original och 59 nya produktfamiljer från CISA:s ICS-bulletiner),{' '}
            <strong>344 unika CVE</strong> i 349 produkt–CVE-relationer, ett källmanifest med
            SHA-256 för hämtade dokument, länkkontroll, radgranskning, hotunderlag och
            konto-/lösenordsstatus. Produkt-ID:n (OT-…) bevaras som stabila identifierare och
            importen är idempotent. Registrets uppgifter läggs till vid sidan av projektets manuella
            bedömningar; avvikelser redovisas som konflikter i stället för att skrivas över.
          </p>
          <ul className="list-disc pl-5">
            <li>
              <strong>Lösenordsstatus utan värden:</strong> underlaget innehåller kontonamn, typ av
              initialt/fabrikslösenord och bytekrav – aldrig lösenord. Ett gemensamt
              standardlösenord, ett enhetsunikt initiallösenord och ett lösenord som installatören
              skapar är olika uppgifter; hårdkodade eller förutsägbara mekanismer kan kräva
              firmwareåtgärd eller utbyte.
            </li>
            <li>
              <strong>Evidensnivåer för PoC:</strong> offentlig PoC, emulatordemonstration,
              detektionsverktyg och aktiv exploatering är olika uppgifter. CISA:s daterade
              SSVC-värde <code>none</code> bevisar inte att offentlig kod eller exploatering saknas
              i dag, och en komponent-PoC bevisar inte att en viss OT-produkt kan fjärrexploateras.
              Ingen länkad kod har körts.
            </li>
            <li>
              <strong>Dokumentation:</strong> en dokumentportal eller säkerhetsguide är inte
              automatiskt en verifierad installationsmanual; detta visas per post.
            </li>
            <li>
              <strong>Exponering:</strong> ”Observerad internetexponering” är ”Ej undersökt” för
              samtliga poster och registrets prioritet (P1/P2) gäller vid <em>konstaterad</em>{' '}
              exponering. Dokumenterad risk är inte bevis på faktisk exponering eller
              kompromettering.
            </li>
          </ul>
        </Section>
        <Section title="Källhierarki" id="kallor">
          <ol className="list-decimal pl-5">
            <li>
              <strong>Primärkällor:</strong> tillverkarens PSIRT/bulletin (helst maskinläsbar CSAF),
              CISA ICS-advisories, CERT-poster samt NVD-poster där CNA är tillverkaren eller en
              myndighet.
            </li>
            <li>
              <strong>Databaser/signaler:</strong> NVD (CVSS, CPE, status), CISA KEV (bekräftat
              utnyttjande), FIRST EPSS (statistisk sannolikhet). Dessa ersätter inte en
              OT-konsekvensbedömning.
            </li>
            <li>
              <strong>Sekundärkällor:</strong> säkerhetsforskning och media. Märks alltid som
              sekundära och ger högst statusen ”stödd av sekundärkälla”.
            </li>
          </ol>
          <p>
            Varje påstående som kan bli fel över tid bär en verifieringsstatus: verifierad
            (primärkälla), stödd av sekundärkälla, behöver granskning, okänt eller motstridiga
            uppgifter. Automatisk datainhämtning skriver aldrig över mänskligt verifierade uppgifter
            utan konfliktredovisning; nya uppgifter får status ”behöver granskning” tills en
            människa godkänt dem.
          </p>
        </Section>
        <Section title="Riskmetod" id="riskmetod">
          <p>
            Prioriteringen är <strong>inspirerad av CISA SSVC</strong> (Stakeholder-Specific
            Vulnerability Categorization) men är inte officiell SSVC och gör inte anspråk på att
            vara det. Sju faktorer redovisas var för sig: hot/sannolikhet, teknisk allvarlighet,
            faktisk relevans (versionsmatchning), exponering, OT-konsekvens, skydd/genomförbarhet
            och datakvalitet. Ingen sammanvägd risksiffra beräknas. Exponering kan bara fastställas
            för behörigt inventerade tillgångar och är därför alltid ”okänd” i den publika
            katalogen. Otillräckliga belägg sänker säkerheten i bedömningen och leder till
            rekommendationen ”fastställ modell och version”, aldrig automatiskt till ”låg risk”.
            Metoden och dess regler dokumenteras i <code>docs/RISK_METHOD.md</code>.
          </p>
        </Section>
        <Section title="Referensramverk" id="ramverk">
          <ul className="list-disc pl-5">
            <li>
              <strong>NIST SP 800-82 Rev. 3</strong> är fastställd OT-vägledning.{' '}
              <strong>Rev. 4</strong> är per 2026-11-07 ett offentligt utkast (Initial Public Draft)
              och behandlas som utkast, inte som fastställd standard.
            </li>
            <li>
              <strong>NIST CSF 2.0</strong> och <strong>IEC 62443</strong> används som
              kartläggningsreferenser för åtgärder. Inga påståenden om certifiering eller full
              efterlevnad görs.
            </li>
            <li>
              Den svenska <strong>cybersäkerhetslagen</strong> (genomförandet av NIS2) trädde i
              kraft 2026-01-15. Kunskapsbasen innehåller generella fält för riskhantering,
              tillgångsinventering, incidenthantering, leveranskedja och kontinuitet, men ger inga
              juridiska slutsatser om en viss organisation; det kräver en verksamhetsbedömning.
            </li>
          </ul>
        </Section>
        <Section title="Skyddsgräns och disclaimer" id="disclaimer">
          <Callout tone="warn" title="Vad kunskapsbasen inte är">
            <ul className="list-disc pl-5">
              <li>
                Den innehåller inga anläggningsunika uppgifter: inga IP-adresser, nätsegment,
                byggnader, ägare, kontakter, serienummer, scanningresultat eller ärenden. En privat
                anläggningsinventering kräver separat autentiserad arkitektur och ingår inte i den
                publika webbplatsen.
              </li>
              <li>
                Den ger inga exploateringsinstruktioner. Risktexterna beskriver risktyper och
                defensiva åtgärder.
              </li>
              <li>
                Frånvaro av CVE eller bulletin är inte bevis för frånvaro av sårbarheter.
                Sökheuristiker (t.ex. Shodan-sökord) är avsedda för egen/auktoriserad inventering
                och kan ge både missar och falska träffar.
              </li>
              <li>
                Uppgifter kan bli inaktuella. Kontrollera alltid tillverkarens senaste bulletiner
                för exakt modell, komponent och firmware innan beslut.
              </li>
            </ul>
          </Callout>
        </Section>
        <Section title="Ansvar, datum och felrapportering" id="fel">
          <p>
            Materialet tillhandahålls i befintligt skick utan garantier. Datum för datagenerering
            och arbetsbokens checksumma visas i sidfoten och i varje export. Fel, inaktuella
            uppgifter eller förslag på nya källor rapporteras via GitHub Issues i projektets
            repository: <SafeLink href={REPO}>{REPO}</SafeLink>. Ange gärna primärkälla för det du
            rapporterar.
          </p>
        </Section>
      </div>
    </>
  );
}

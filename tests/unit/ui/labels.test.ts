import { describe, expect, it } from 'vitest';
import {
  CveStatus,
  DataQualityFlag,
  ExploitationEvidence,
  InitialPasswordType,
  MaterialTypeCode,
  OtSuitability,
  PublicPocStatus,
} from '@schemas/index';
import {
  cveStatusLabel,
  evidenceTypeLabel,
  fieldLabel,
  flagLabel,
  materialTypeLabel,
  otSuitabilityLabel,
  pocStatusLabel,
  pocStatusShort,
  pwdTypeDescription,
  pwdTypeLabel,
} from '@/lib/labels';

describe('Etiketter täcker alla enum-koder', () => {
  it('alla 11 lösenordstyper har etikett och beskrivning', () => {
    expect(InitialPasswordType.options).toHaveLength(11);
    for (const t of InitialPasswordType.options) {
      expect(pwdTypeLabel[t]).toBeTruthy();
      expect(pwdTypeDescription[t]).toBeTruthy();
    }
    // Inga etiketter får innehålla något som liknar ett lösenordsvärde
    for (const t of InitialPasswordType.options)
      expect(pwdTypeLabel[t]).not.toMatch(/:\s*\S+\d\S*$/);
  });
  it('PoC-status och materialtyp har etiketter', () => {
    for (const s of PublicPocStatus.options) {
      expect(pocStatusLabel[s]).toBeTruthy();
      expect(pocStatusShort[s]).toBeTruthy();
    }
    for (const m of MaterialTypeCode.options) expect(materialTypeLabel[m]).toBeTruthy();
  });
  it('alla datakvalitetsflaggor har etikett', () => {
    for (const f of DataQualityFlag.options) expect(flagLabel[f]).toBeTruthy();
  });
});

describe('Inga interna koder i gränssnittet', () => {
  it('översätter kända fältsökvägar och matchningsfält', () => {
    expect(fieldLabel('risk_summary.fix_text')).toBe('fixuppgift');
    expect(fieldLabel('*')).toBe('hela posten');
    expect(fieldLabel('matches.match-copeland-xweb-pro-cve-2026-21718.fix')).toBe(
      'fixstatus för CVE-2026-21718',
    );
    // Okända sökvägar visas läsbart, aldrig med punkter/understreck
    expect(fieldLabel('some_new.field')).toBe('some new field');
  });
  it('har etiketter för OT-lämplighet, CVE-status och beläggstyp', () => {
    for (const v of OtSuitability.options) expect(otSuitabilityLabel[v]).toBeTruthy();
    for (const v of CveStatus.options) expect(cveStatusLabel[v]).toBeTruthy();
    for (const v of ExploitationEvidence.shape.type.options)
      expect(evidenceTypeLabel[v]).toBeTruthy();
  });
});

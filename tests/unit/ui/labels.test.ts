import { describe, expect, it } from 'vitest';
import {
  DataQualityFlag,
  InitialPasswordType,
  MaterialTypeCode,
  PublicPocStatus,
} from '@schemas/index';
import {
  flagLabel,
  materialTypeLabel,
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

import { expect, test } from '@playwright/test';

test.describe('Röktest – publik kunskapsbas', () => {
  test('översikten laddar verklig data', async ({ page }) => {
    await page.goto('#/');
    await expect(page.getByRole('heading', { level: 1, name: 'Översikt' })).toBeVisible();
    await expect(page.getByText('Katalogposter', { exact: true })).toBeVisible();
    await expect(page.getByText(/Varför visas inte antal/)).toBeVisible();
  });

  test('katalogen kan sökas och filtret speglas i URL', async ({ page }) => {
    await page.goto('#/katalog');
    await page.getByLabel(/Fulltextsökning/).fill('Danfoss');
    await expect(page).toHaveURL(/q=Danfoss/);
    await expect(page.getByRole('link', { name: 'Danfoss AK-SM 800A' }).first()).toBeVisible();
  });

  test('detaljsidan för Danfoss AK-SM 800A visar båda DSA-bulletinerna', async ({ page }) => {
    await page.goto('#/produkt/pf-danfoss-ak-sm-800a');
    await expect(page.getByRole('heading', { level: 1, name: 'Danfoss AK-SM 800A' })).toBeVisible();
    await expect(page.getByText('DSA-2025-03-01').first()).toBeVisible();
    await expect(page.getByText('DSA-2025-08-01').first()).toBeVisible();
    await expect(
      page.getByRole('heading', { name: /Explicit versions- och CVE-matchning/ }),
    ).toBeVisible();
  });

  test('protokollsidan för Modbus TCP listar inga CVE-matchningar', async ({ page }) => {
    await page.goto('#/protokoll/svc-modbus-tcp');
    await expect(page.getByRole('heading', { level: 1, name: 'Modbus TCP' })).toBeVisible();
    await expect(page.getByText('Protokoll är inte produkter')).toBeVisible();
    await expect(page.getByRole('heading', { name: /CVE-matchning/ })).toHaveCount(0);
    await expect(page.getByRole('main').getByText(/^CVE-\d{4}-\d+$/)).toHaveCount(0);
  });

  test('katalogfilter origin=new visar registrets nya poster', async ({ page }) => {
    await page.goto('#/katalog?origin=new');
    await expect(page.getByRole('status')).toHaveText(/^59 av 125 poster$/);
    await expect(page.getByRole('link', { name: 'ABB ASPECT' }).first()).toBeVisible();
  });

  test('produktsidan för ABB ASPECT visar konto-, setup- och registersektioner samt CVE-tabell', async ({
    page,
  }) => {
    await page.goto('#/produkt/pf-abb-aspect');
    await expect(page.getByRole('heading', { level: 1, name: 'ABB ASPECT' })).toBeVisible();
    await expect(
      page.getByRole('heading', { name: 'Registeruppgifter och granskning' }),
    ).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Konton och initiallösenord' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Setup och installation' })).toBeVisible();
    await expect(page.getByText('OT-N-ICSA-25-007-01').first()).toBeVisible();
    await expect(
      page.getByText(/Underlaget innehåller inga lösenordsvärden/).first(),
    ).toBeVisible();
    const rows = page.locator('#matchning tbody tr');
    const showMore = page.getByRole('button', { name: /Visa fler/ });
    const n = await rows.count();
    expect(n >= 15 || (await showMore.count()) > 0).toBe(true);
    if ((await showMore.count()) > 0) {
      await showMore.click();
      expect(await rows.count()).toBeGreaterThanOrEqual(20);
    }
  });

  test('kontosammanställningen laddar med tabell och export', async ({ page }) => {
    await page.goto('#/konton');
    await expect(
      page.getByRole('heading', { level: 1, name: 'Konton och initiallösenord' }),
    ).toBeVisible();
    await expect(page.getByRole('table')).toBeVisible();
    await expect(page.getByRole('status')).toHaveText(/\d+ av \d+ poster/);
    await expect(page.getByRole('button', { name: 'Exportera CSV' })).toBeEnabled();
  });

  test('CVE-sidan för CVE-2025-41450 visar hotunderlag med materialtyp Emulator', async ({
    page,
  }) => {
    await page.goto('#/sarbarheter/CVE-2025-41450');
    await expect(page.getByRole('heading', { level: 1, name: 'CVE-2025-41450' })).toBeVisible();
    await expect(page.getByRole('heading', { name: /Hotunderlag/ })).toBeVisible();
    await expect(page.getByText(/Emulator/).first()).toBeVisible();
    await expect(page.getByText(/bevisar inte att offentlig/).first()).toBeVisible();
  });

  test('gamla snabböversikten leder till katalogen; KEV-filter och utfälld rad visar allt per produkt', async ({
    page,
  }) => {
    await page.goto('#/oversikt?sort=severity');
    await expect(page).toHaveURL(/#\/katalog\?sort=severity/);
    await expect(page.getByRole('heading', { level: 1, name: 'Katalog' })).toBeVisible();
    await expect(page.getByRole('status')).toHaveText(/^125 av 125 poster$/);
    // Defensiv disciplin: tydlig text om att inga lösenordsvärden finns
    await expect(
      page.getByText(/Underlaget innehåller inga lösenordsvärden/).first(),
    ).toBeVisible();
    // KEV-snabbfiltret ska minska antalet poster och speglas i URL
    await page.getByRole('button', { name: /CVE i CISA KEV/ }).click();
    await expect(page.getByRole('status')).toHaveText(/^2 av 125 poster$/);
    await expect(page).toHaveURL(/has=kev/);
    await expect(page.getByText('KEV ×1').first()).toBeVisible();
    // Fäll ut raden: konto, lösenordstyp och CVE-lista utan att lämna katalogen
    await page.getByRole('button', { name: /Visa detaljer för Unitronics Vision/ }).click();
    await expect(page.getByRole('link', { name: 'CVE-2023-6448' }).first()).toBeVisible();
    await expect(page.getByText('Initiallösenord (typ, aldrig värde)').first()).toBeVisible();
  });

  test('inga externa länkar utan säkra attribut', async ({ page }) => {
    await page.goto('#/produkt/pf-danfoss-ak-sm-800a');
    const external = page.locator('a[href^="http"]');
    const n = await external.count();
    for (let i = 0; i < n; i++) {
      const a = external.nth(i);
      expect(await a.getAttribute('href')).toMatch(/^https:\/\//);
      expect(await a.getAttribute('rel')).toContain('noopener');
    }
  });
});

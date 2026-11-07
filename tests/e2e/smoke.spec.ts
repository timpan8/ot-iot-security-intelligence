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

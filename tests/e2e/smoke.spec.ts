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

  test('gamla snabböversikten leder till katalogens dossiervy med allt per produkt', async ({
    page,
  }) => {
    await page.goto('#/oversikt?sort=severity');
    await expect(page).toHaveURL(/#\/katalog\?.*view=cards/);
    await expect(page.getByRole('heading', { level: 1, name: 'Katalog' })).toBeVisible();
    await expect(page.getByRole('status')).toHaveText(/^125 av 125 poster$/);
    // Defensiv disciplin: tydlig text om att inga lösenordsvärden finns
    await expect(
      page.getByText(/Underlaget innehåller inga lösenordsvärden/).first(),
    ).toBeVisible();
    // Dossiervyn visar signaler och CVE direkt, utan att klicka
    await expect(page.getByText('KEV ×1').first()).toBeVisible();
    await expect(page.getByRole('link', { name: 'CVE-2023-6448' }).first()).toBeVisible();
    await expect(page.getByText('Initiallösenord (typ, aldrig värde)').first()).toBeVisible();
  });

  test('dossiervyn visar konto, lösenordstyp, sökord och CVE per produkt utan att klicka', async ({
    page,
  }) => {
    await page.goto('#/katalog?view=cards&sort=severity&has=kev');
    await expect(page.getByRole('status')).toHaveText(/^2 av 125 poster$/);
    const card = page.locator('article').first();
    await expect(card.getByRole('link', { name: 'Unitronics Vision' })).toBeVisible();
    // Allt syns direkt i kortet – ingen utfällning behövs
    await expect(card.getByText('Standardkonto')).toBeVisible();
    await expect(card.getByText('Initiallösenord (typ, aldrig värde)')).toBeVisible();
    await expect(card.getByText('Sökord för egen inventering')).toBeVisible();
    await expect(card.getByRole('link', { name: 'CVE-2023-6448' })).toBeVisible();
    // Växling tillbaka till tabell speglas i URL
    await page.getByRole('button', { name: 'Tabell', exact: true }).click();
    await expect(page).not.toHaveURL(/view=cards/);
    await expect(page.getByRole('table')).toBeVisible();
  });

  test('detaljtabellen visar dossierns fält som kolumner, en rad per produkt', async ({ page }) => {
    await page.goto('#/katalog?view=fields&sort=severity&has=kev');
    await expect(page.getByRole('status')).toHaveText(/^2 av 125 poster$/);
    const table = page.getByRole('table');
    for (const h of [
      'Produkt',
      'Standardkonto och initiallösenord',
      'Sökord (egen inventering)',
      'Sårbarheter',
      'PoC-/hotunderlag',
      'Setup och dokumentation',
    ])
      await expect(table.getByRole('columnheader', { name: h })).toBeVisible();
    await expect(table.getByRole('link', { name: 'Unitronics Vision' })).toBeVisible();
    await expect(table.getByRole('link', { name: 'CVE-2023-6448' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Detaljtabell' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
  });

  test('detaljtabellens kolumner kan läggas till och tas bort och valet sparas', async ({
    page,
  }) => {
    await page.goto('#/katalog?view=fields');
    const table = page.getByRole('table');
    await expect(
      table.getByRole('columnheader', { name: 'Sökord (egen inventering)' }),
    ).toBeVisible();
    await page.getByText(/^Kolumner \(/).click();
    // Ta bort en standardkolumn och lägg till en extra
    await page.getByRole('checkbox', { name: 'Sökord (egen inventering)' }).uncheck();
    await page.getByRole('checkbox', { name: 'Högsta CVSS' }).check();
    await expect(
      table.getByRole('columnheader', { name: 'Sökord (egen inventering)' }),
    ).toHaveCount(0);
    await expect(table.getByRole('columnheader', { name: 'Högsta CVSS' })).toBeVisible();
    // Valet ligger kvar efter omladdning
    await page.reload();
    await expect(
      page.getByRole('table').getByRole('columnheader', { name: 'Högsta CVSS' }),
    ).toBeVisible();
    await page.getByText(/^Kolumner \(/).click();
    await page.getByRole('button', { name: 'Återställ standard' }).click();
    await expect(
      page.getByRole('table').getByRole('columnheader', { name: 'Sökord (egen inventering)' }),
    ).toBeVisible();
  });

  test('detaljtabellen har kolumner för konto och standardportar', async ({ page }) => {
    await page.goto('#/katalog?view=fields');
    const table = page.getByRole('table');
    await expect(
      table.getByRole('columnheader', { name: 'Standardkonto och initiallösenord' }),
    ).toBeVisible();
    await expect(
      table.getByRole('columnheader', { name: 'Standardportar (via protokoll)' }),
    ).toBeVisible();
    // En post med känt protokoll visar sin port
    await page.getByLabel(/Fulltextsökning/).fill('Danfoss AK-SM');
    await expect(table.getByText('502/tcp').first()).toBeVisible();
  });

  test('egen konto-/lösenordskolumn sparas lokalt och överlever omladdning', async ({ page }) => {
    await page.goto('#/katalog?view=fields');
    await page.getByLabel(/Fulltextsökning/).fill('Danfoss AK-SM');
    const row = page.getByRole('table').locator('tbody tr').first();
    await row.getByRole('button', { name: /Lägg till egna inloggningsuppgifter/ }).click();
    await row.getByPlaceholder('Användarnamn').fill('driftkonto');
    await row.getByPlaceholder('Lösenord').fill('ange-eget');
    await row.getByRole('button', { name: 'Spara' }).click();
    await expect(row.getByText('driftkonto')).toBeVisible();
    await expect(row.getByText('ange-eget')).toBeVisible();
    // Ligger kvar efter omladdning (localStorage, bara denna enhet)
    await page.reload();
    await page.getByLabel(/Fulltextsökning/).fill('Danfoss AK-SM');
    const row2 = page.getByRole('table').locator('tbody tr').first();
    await expect(row2.getByText('driftkonto')).toBeVisible();
    await expect(row2.getByText('ange-eget')).toBeVisible();
    // Städa upp så testdata inte ligger kvar
    await row2.getByRole('button', { name: /Redigera egna inloggningsuppgifter/ }).click();
    await row2.getByRole('button', { name: 'Ta bort' }).click();
    await expect(
      row2.getByRole('button', { name: /Lägg till egna inloggningsuppgifter/ }),
    ).toBeVisible();
  });

  test('inga sidor blir bredare än skärmen på mobil', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    for (const r of ['#/bulletiner', '#/konton', '#/atgarder', '#/produkt/pf-abb-aspect']) {
      await page.goto(r);
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
      const sw = await page.evaluate<number>('document.documentElement.scrollWidth');
      expect(sw, r).toBeLessThanOrEqual(390);
    }
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

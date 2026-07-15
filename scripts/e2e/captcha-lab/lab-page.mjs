export async function prepareLab(page, config, { locale, theme }) {
  await page.addInitScript(({ token, locale, theme }) => {
    localStorage.setItem('cheesewaf-token', token);
    localStorage.setItem('i18nextLng', locale);
    localStorage.setItem('cheesewaf-ui', JSON.stringify({
      state: { language: locale, sidebarCollapsed: false, theme },
      version: 0,
    }));
  }, { token: config.token, locale, theme });
  await page.goto(new URL(config.labPath, config.baseURL).toString(), { waitUntil: 'domcontentloaded' });
  await page.locator('#captcha-lab-title').waitFor();
}

export async function selectScenario(page, type) {
  const option = (type === 'curve_slider_v1' || type === 'curve_slider_v2' || type === 'curve_slider_v3')
    ? 'curve_slider'
    : type;
  await page.getByRole('combobox').selectOption(option);
}

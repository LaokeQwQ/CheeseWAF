export async function prepareLab(page, config, { locale, theme }) {
  await page.addInitScript(({ token, locale, theme }) => {
    localStorage.setItem('cheesewaf-token', token);
    localStorage.setItem('i18nextLng', locale);
    localStorage.setItem('cheesewaf-language', locale);
    localStorage.setItem('cheesewaf-theme', theme);
  }, { token: config.token, locale, theme });
  await page.goto(new URL(config.labPath, config.baseURL).toString(), { waitUntil: 'domcontentloaded' });
  await page.getByRole('heading', { name: 'Captcha Lab' }).waitFor();
}

export async function selectScenario(page, type) {
  const option = type === 'curve_slider_v1' ? 'curve_slider' : type;
  await page.getByRole('combobox').selectOption(option);
}

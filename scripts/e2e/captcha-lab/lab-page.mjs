export async function prepareLab(page, config, { locale, theme }) {
  const expectedPage = labPageExpectation(locale, theme);
  await page.addInitScript(({ token, locale, theme }) => {
    localStorage.setItem('cheesewaf-token', token);
    localStorage.setItem('i18nextLng', locale);
    localStorage.setItem('cheesewaf-ui', JSON.stringify({
      state: { language: locale, sidebarCollapsed: false, theme },
      version: 0,
    }));
  }, { token: config.token, locale, theme });
  await page.goto(new URL(config.labPath, config.baseURL).toString(), { waitUntil: 'domcontentloaded' });
  await page.locator('#captcha-lab-title').waitFor({ state: 'visible' });
  await page.waitForFunction(({ theme, lang, title }) => {
    const root = document.documentElement;
    const heading = document.querySelector('#captcha-lab-title');
    if (!heading || root.dataset.theme !== theme || root.lang !== lang || heading.textContent?.trim() !== title) return false;
    const style = getComputedStyle(heading);
    return style.display !== 'none' && style.visibility !== 'hidden' && heading.getClientRects().length > 0;
  }, expectedPage);
}

function labPageExpectation(locale, theme) {
  const localeExpectations = {
    'zh-CN': { lang: 'zh-CN', title: '\u4eba\u673a\u9a8c\u8bc1\u5b9e\u9a8c\u5ba4' },
    'en-US': { lang: 'en', title: 'Captcha Lab' },
  };
  const themeAttributes = {
    light: 'light',
    dark: 'dark',
    blackGold: 'black-gold',
    blueWhite: 'blue-white',
  };
  if (!localeExpectations[locale]) throw new Error(`Unsupported CAPTCHA lab locale: ${locale}`);
  if (!themeAttributes[theme]) throw new Error(`Unsupported CAPTCHA lab theme: ${theme}`);
  return { theme: themeAttributes[theme], ...localeExpectations[locale] };
}

export async function selectScenario(page, type) {
  const option = (type === 'curve_slider_v1' || type === 'curve_slider_v2' || type === 'curve_slider_v3')
    ? 'curve_slider'
    : type;
  await page.getByRole('combobox').selectOption(option);
}

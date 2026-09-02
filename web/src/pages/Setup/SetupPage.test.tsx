import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const apiMocks = vi.hoisted(() => ({
  setupAdmin: vi.fn(),
  unwrapAPIResponse: vi.fn(),
}));

const toastMocks = vi.hoisted(() => ({
  error: vi.fn(),
  success: vi.fn(),
  warning: vi.fn(),
  dismiss: vi.fn(),
}));

const navigateMock = vi.fn();

vi.mock('sonner', () => ({
  toast: toastMocks,
}));

vi.mock('react-i18next', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-i18next')>();
  return {
    ...actual,
    // Keys pass through verbatim so assertions do not depend on translations.
    useTranslation: () => ({ t: (key: string, opts?: { defaultValue?: string }) => opts?.defaultValue ?? key }),
  };
});

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => navigateMock };
});

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return {
    ...actual,
    setupAdmin: apiMocks.setupAdmin,
    unwrapAPIResponse: apiMocks.unwrapAPIResponse,
    apiClient: {
      post: vi.fn(() => Promise.resolve({})),
      patch: vi.fn(() => Promise.resolve({})),
    },
  };
});

import SetupPage from './SetupPage';
import { useAppStore } from '../../stores';

const NAV_LANGUAGE = 'en-US';

function setBrowserLanguage(value: string) {
  Object.defineProperty(navigator, 'language', { value, configurable: true });
}

function probePayload(overrides: Record<string, unknown> = {}) {
  return {
    probe: {
      profile: 'medium',
      cpu_logical: 4,
      memory_total_mb: 8192,
      memory_avail_mb: 4096,
      disk_write_mbps: 100,
      disk_ok: true,
      duration_ms: 12,
      incomplete: false,
      notes: [],
      suggested_config: { web_attack_level: 'smart' },
      ...overrides,
    },
  };
}

function clickNext() {
  fireEvent.click(screen.getByRole('button', { name: 'common.next' }));
}

function passwordInputs() {
  return screen.getAllByPlaceholderText('********') as HTMLInputElement[];
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers({ shouldAdvanceTime: true });
  localStorage.clear();
  setBrowserLanguage(NAV_LANGUAGE);
  // Start from the non-browser value and with no persisted choice, so a mount
  // has to fall back to `navigator.language` on its own.
  useAppStore.setState({ language: 'en-US' });
  useAppStore.persist.clearStorage();
  apiMocks.unwrapAPIResponse.mockResolvedValue(probePayload());
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  setBrowserLanguage(NAV_LANGUAGE);
});

/** Step 0 (language) → step 1 (environment). */
async function advanceToEnvironmentStep() {
  render(<SetupPage />);
  await waitFor(() => expect(screen.getByRole('radio', { name: /setup.languageZh/ })).toBeTruthy());
  clickNext();
  await waitFor(() => expect(screen.getByText('setup.probeChecklistTitle')).toBeTruthy());
}

/** … → step 2 (profile). */
async function advanceToProfileStep() {
  await advanceToEnvironmentStep();
  clickNext();
  await waitFor(() => expect(screen.getByText('setup.profileSmartDesc')).toBeTruthy());
}

/** … → step 3 (account). */
async function advanceToAccountStep() {
  await advanceToProfileStep();
  clickNext();
  await waitFor(() => expect(screen.getByPlaceholderText('setup.usernamePlaceholder')).toBeTruthy());
}

/** … → step 4 (integrations). */
async function advanceToIntegrationsStep(password = 'S3cure-Pass!') {
  await advanceToAccountStep();
  fireEvent.change(screen.getByPlaceholderText('setup.usernamePlaceholder'), { target: { value: 'root-admin' } });
  const [passwordInput, confirmInput] = passwordInputs();
  fireEvent.change(passwordInput, { target: { value: password } });
  fireEvent.change(confirmInput, { target: { value: password } });
  clickNext();
  await waitFor(() => expect(screen.getByRole('button', { name: 'setup.integrationsSkip' })).toBeTruthy());
}

/**
 * … → step 5 (review). The integrations step sits between account and review
 * and is owned by another workstream, so skip past it here.
 */
async function advanceToReviewStep(password = 'S3cure-Pass!') {
  await advanceToIntegrationsStep(password);
  fireEvent.click(screen.getByRole('button', { name: 'setup.integrationsSkip' }));
  await waitFor(() => expect(screen.getByText('setup.summaryTitle')).toBeTruthy());
}

async function completeSetup() {
  fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.click(screen.getByRole('button', { name: 'setup.complete' }));
  await waitFor(() => expect(apiMocks.setupAdmin).toHaveBeenCalled());
}

describe('SetupPage', () => {
  it('submits admin bootstrap with form values after confirmation', async () => {
    apiMocks.setupAdmin.mockResolvedValue({ setup_complete: true });
    await advanceToReviewStep();
    await completeSetup();

    expect(apiMocks.setupAdmin).toHaveBeenCalledWith(
      'root-admin',
      'S3cure-Pass!',
      expect.any(String),
      expect.any(String),
    );
    await vi.advanceTimersByTimeAsync(900);
    expect(navigateMock).toHaveBeenCalledWith('/login', { replace: true });
  });

  it('surfaces setup API failures', async () => {
    apiMocks.setupAdmin.mockRejectedValue(new Error('username already exists'));
    await advanceToReviewStep();
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: 'setup.complete' }));

    expect(await screen.findByText('username already exists')).toBeTruthy();
    expect(navigateMock).not.toHaveBeenCalled();
  });

  // 问题 2：语言选择必须是第一步，默认跟随浏览器。
  it('asks for the language before anything else', async () => {
    render(<SetupPage />);
    await waitFor(() => expect(screen.getByText('setup.languageZh')).toBeTruthy());
    expect(screen.getByTestId('setup-language-typewriter')).toBeTruthy();
    expect(screen.getByText('setup.languageEn')).toBeTruthy();
    // No wizard step chrome or probe output before the language is chosen.
    expect(screen.queryByText('setup.probeChecklistTitle')).toBeNull();
    expect(screen.queryByText('setup.stepProfile')).toBeNull();
  });

  it('preselects the browser language when the operator never chose one', async () => {
    setBrowserLanguage('zh-CN');
    render(<SetupPage />);
    await waitFor(() => expect(useAppStore.getState().language).toBe('zh-CN'));
    // No jest-dom in this suite, so read the ARIA attribute directly.
    await waitFor(() =>
      expect(screen.getByRole('radio', { name: /setup.languageZh/ }).getAttribute('aria-checked')).toBe('true'),
    );
  });

  it('keeps English preselected when the browser reports English', async () => {
    render(<SetupPage />);
    await waitFor(() =>
      expect(screen.getByRole('radio', { name: /setup.languageEn/ }).getAttribute('aria-checked')).toBe('true'),
    );
  });

  it('lets the operator switch language manually', async () => {
    setBrowserLanguage('zh-CN');
    render(<SetupPage />);
    await waitFor(() => expect(useAppStore.getState().language).toBe('zh-CN'));

    fireEvent.click(screen.getByRole('radio', { name: /setup.languageEn/ }));
    await waitFor(() => expect(useAppStore.getState().language).toBe('en-US'));
  });

  // 问题 3：环境检查清单必须包含 memory_avail_mb 与 disk_ok。
  it('renders a checklist covering every probe field including available memory and disk usability', async () => {
    await advanceToEnvironmentStep();
    expect(screen.getByText('setup.probeCpu')).toBeTruthy();
    expect(screen.getByText('setup.probeMemoryTotal')).toBeTruthy();
    expect(screen.getByText('setup.probeMemoryAvail')).toBeTruthy();
    expect(screen.getByText('setup.probeDiskWrite')).toBeTruthy();
    expect(screen.getByText('setup.probeDiskOk')).toBeTruthy();
    expect(screen.getByText('setup.probeIntegrity')).toBeTruthy();
    expect(screen.getByText('setup.probeValueOk')).toBeTruthy();
    expect(screen.getAllByText('setup.probeStatusPass').length).toBeGreaterThan(0);
  });

  it('flags a failing disk probe', async () => {
    apiMocks.unwrapAPIResponse.mockResolvedValue(
      probePayload({ disk_ok: false, disk_write_mbps: 5, profile: 'low' }),
    );
    await advanceToEnvironmentStep();
    expect(screen.getByText('setup.probeValueFailed')).toBeTruthy();
    expect(screen.getAllByText('setup.probeStatusFail').length).toBeGreaterThan(0);
  });

  // 问题 4：profile 需要引导说明、smart 档与推荐标记。
  it('explains every profile tier, offers smart, and marks the recommended one', async () => {
    await advanceToProfileStep();
    expect(screen.getByText('setup.profileSmart')).toBeTruthy();
    expect(screen.getByText('setup.profileLowDesc')).toBeTruthy();
    expect(screen.getByText('setup.profileMediumDesc')).toBeTruthy();
    expect(screen.getByText('setup.profileHighDesc')).toBeTruthy();
    expect(screen.getByText('setup.profileCustomDesc')).toBeTruthy();
    // Probe recommends medium, so exactly one option carries the badge.
    expect(screen.getAllByText('setup.profileRecommended')).toHaveLength(1);
  });

  it('shows the probe recommendation before the profile step', async () => {
    await advanceToEnvironmentStep();
    expect(screen.getByText('setup.probeRecommendationTitle')).toBeTruthy();
    expect(screen.getByText('setup.profileMedium')).toBeTruthy();
  });

  // 问题 5：用户名/密码校验、小眼睛、二次确认。
  it('rejects a username that does not start with a letter', async () => {
    await advanceToAccountStep();
    const username = screen.getByPlaceholderText('setup.usernamePlaceholder');
    fireEvent.change(username, { target: { value: '1admin' } });
    fireEvent.blur(username);
    expect(await screen.findByText('setup.usernameMustStartWithLetter')).toBeTruthy();
  });

  it('rejects a username that is too short or uses illegal characters', async () => {
    await advanceToAccountStep();
    const username = screen.getByPlaceholderText('setup.usernamePlaceholder');
    fireEvent.change(username, { target: { value: 'ad' } });
    fireEvent.blur(username);
    expect(await screen.findByText('setup.usernameTooShort')).toBeTruthy();

    fireEvent.change(username, { target: { value: 'admin name' } });
    expect(await screen.findByText('setup.usernameInvalidChars')).toBeTruthy();
  });

  it('toggles password visibility with the eye button', async () => {
    await advanceToAccountStep();
    expect(passwordInputs()[0].type).toBe('password');
    fireEvent.click(screen.getAllByRole('button', { name: 'setup.showPassword' })[0]);
    expect(passwordInputs()[0].type).toBe('text');
    fireEvent.click(screen.getAllByRole('button', { name: 'setup.hidePassword' })[0]);
    expect(passwordInputs()[0].type).toBe('password');
  });

  it('reports a password confirmation mismatch and blocks the step', async () => {
    await advanceToAccountStep();
    fireEvent.change(screen.getByPlaceholderText('setup.usernamePlaceholder'), { target: { value: 'root-admin' } });
    const [passwordInput, confirmInput] = passwordInputs();
    fireEvent.change(passwordInput, { target: { value: 'S3cure-Pass!' } });
    fireEvent.change(confirmInput, { target: { value: 'S3cure-Pass?' } });

    expect(await screen.findByText('setup.passwordMismatch')).toBeTruthy();

    clickNext();
    await waitFor(() => expect(toastMocks.error).toHaveBeenCalledWith('setup.passwordMismatch'));
    expect(screen.queryByRole('checkbox')).toBeNull();
  });

  it('accepts matching passwords and reports the strength', async () => {
    await advanceToAccountStep();
    const [passwordInput, confirmInput] = passwordInputs();
    fireEvent.change(passwordInput, { target: { value: 'S3cure-Pass!' } });
    expect(screen.getByText('setup.strengthLabel')).toBeTruthy();
    expect(screen.getByText('setup.strengthGood')).toBeTruthy();
    fireEvent.change(confirmInput, { target: { value: 'S3cure-Pass!' } });
    expect(screen.getByText('setup.passwordMatch')).toBeTruthy();
  });

  // 问题 6：监听地址与访问策略不该出现在首次初始化向导。
  it('keeps the admin listener and access strategy out of the wizard', async () => {
    await advanceToAccountStep();
    expect(screen.queryByLabelText('setup.adminListen')).toBeNull();
    expect(screen.queryByLabelText('setup.adminStrategy')).toBeNull();
  });

  it('uses the backend defaults for the admin listener', async () => {
    apiMocks.setupAdmin.mockResolvedValue({ setup_complete: true });
    await advanceToReviewStep();
    await completeSetup();
    expect(apiMocks.setupAdmin).toHaveBeenCalledWith('root-admin', 'S3cure-Pass!', '127.0.0.1:9443', 'local');
  });

  // 问题 7：review 使用 i18n 标签。
  it('renders the review summary with translated labels instead of raw field names', async () => {
    await advanceToReviewStep();
    expect(screen.getByText('setup.summaryTitle')).toBeTruthy();
    expect(screen.getByText('setup.summaryLanguage')).toBeTruthy();
    expect(screen.getByText('setup.summaryProfile')).toBeTruthy();
    expect(screen.getByText('setup.summaryWebAttack')).toBeTruthy();
    expect(screen.getByText('setup.summaryUsername')).toBeTruthy();
    expect(screen.queryByText(/^profile:/)).toBeNull();
    expect(screen.queryByText(/^username:/)).toBeNull();
    expect(screen.queryByText(/^admin_listen:/)).toBeNull();
    expect(screen.queryByText(/^admin_strategy:/)).toBeNull();
  });

  it('shows which advanced defaults will be applied', async () => {
    await advanceToReviewStep();
    expect(screen.getByText('setup.advancedTitle')).toBeTruthy();
    expect(screen.getByText('setup.adminListen')).toBeTruthy();
    expect(screen.getByText('setup.adminStrategy')).toBeTruthy();
    expect(screen.getByText('127.0.0.1:9443')).toBeTruthy();
  });

  // 问题 8：成功只提示一次。
  it('announces success exactly once', async () => {
    apiMocks.setupAdmin.mockResolvedValue({ setup_complete: true });
    await advanceToReviewStep();
    await completeSetup();

    await waitFor(() => expect(screen.getByRole('status')).toBeTruthy());
    expect(screen.getAllByText('setup.success')).toHaveLength(1);
    expect(toastMocks.success).not.toHaveBeenCalled();
  });

  // 问题 9：失败必须弹出 toast。
  it('raises an error toast when setup fails', async () => {
    apiMocks.setupAdmin.mockRejectedValue(new Error('username already exists'));
    await advanceToReviewStep();
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: 'setup.complete' }));

    await waitFor(() => expect(toastMocks.error).toHaveBeenCalledWith('username already exists'));
    expect(screen.getByText('username already exists')).toBeTruthy();
  });

  // 问题 2（续）：打字机标题一次只显示一种语言，绝不同屏混排。
  it('types the headline one language at a time so the two never mix', async () => {
    render(<SetupPage />);
    const headline = () => screen.getByTestId('setup-language-typewriter');
    const typed = () => (headline().textContent ?? '').replaceAll('|', '');
    const isOneLanguage = (text: string) =>
      'setup.languageTitleZh'.startsWith(text) || 'setup.languageTitleEn'.startsWith(text);

    // Both languages stay reachable to screen readers through the accessible name…
    expect(headline().getAttribute('aria-label')).toBe('setup.languageTitleZh / setup.languageTitleEn');
    // …while the visible text is always a prefix of exactly one of them.
    const first = typed();
    expect(isOneLanguage(first)).toBe(true);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(6000);
    });
    const later = typed();
    expect(later).not.toBe(first);
    expect(isOneLanguage(later)).toBe(true);
  });

  // 问题 5（续）：密码复用项目既有的 passwordPolicy。
  it('rejects a password that violates the shared password policy', async () => {
    await advanceToAccountStep();
    fireEvent.change(screen.getByPlaceholderText('setup.usernamePlaceholder'), { target: { value: 'root-admin' } });
    const [passwordInput, confirmInput] = passwordInputs();
    // Matches WEAK_EXACT in utils/passwordPolicy.ts.
    fireEvent.change(passwordInput, { target: { value: 'Admin123456' } });
    fireEvent.change(confirmInput, { target: { value: 'Admin123456' } });

    clickNext();
    await waitFor(() => expect(toastMocks.error).toHaveBeenCalledWith('passwordPolicy.weak'));
    expect(screen.queryByRole('checkbox')).toBeNull();
    expect(apiMocks.setupAdmin).not.toHaveBeenCalled();
  });

  it('rejects a username that ends with a separator', async () => {
    await advanceToAccountStep();
    const username = screen.getByPlaceholderText('setup.usernamePlaceholder');
    fireEvent.change(username, { target: { value: 'admin-' } });
    fireEvent.blur(username);
    expect(await screen.findByText('setup.usernameMustEndAlnum')).toBeTruthy();
  });

  // 问题 6（下）：外部集成放进向导，整步可跳过，且明确告知装完再配。
  it('offers the three optional integrations and lets the operator skip them all', async () => {
    await advanceToIntegrationsStep();
    expect(screen.getByText('setup.stepIntegrations')).toBeTruthy();
    expect(screen.getByText('setup.integrationsPostponed')).toBeTruthy();
    expect(screen.getByText('setup.integrationsPostgresTitle')).toBeTruthy();
    expect(screen.getByText('setup.integrationsPrometheusTitle')).toBeTruthy();
    expect(screen.getByText('setup.integrationsVictoriaTitle')).toBeTruthy();
    // Fields stay hidden until their own toggle is switched on.
    expect(screen.queryByLabelText('setup.integrationsPostgresDsn')).toBeNull();
    expect(screen.queryByLabelText('setup.integrationsVictoriaEndpoint')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'setup.integrationsSkip' }));
    await waitFor(() => expect(screen.getByText('setup.summaryTitle')).toBeTruthy());
    expect(screen.getByText('setup.integrationsSummaryNone')).toBeTruthy();
  });

  it('rejects a PostgreSQL integration with a missing or malformed DSN', async () => {
    await advanceToIntegrationsStep();
    fireEvent.click(screen.getByTestId('setup-integration-postgres-toggle'));
    await waitFor(() => expect(screen.getByLabelText('setup.integrationsPostgresDsn')).toBeTruthy());

    clickNext();
    await waitFor(() => expect(toastMocks.error).toHaveBeenCalledWith('setup.integrationsDsnRequired'));
    expect(screen.getByText('setup.integrationsDsnRequired')).toBeTruthy();
    expect(screen.queryByText('setup.summaryTitle')).toBeNull();

    fireEvent.change(screen.getByLabelText('setup.integrationsPostgresDsn'), {
      target: { value: 'mysql://user@localhost/cheesewaf' },
    });
    clickNext();
    await waitFor(() => expect(toastMocks.error).toHaveBeenCalledWith('setup.integrationsDsnInvalid'));
  });

  it('rejects a VictoriaLogs endpoint that is not an http URL', async () => {
    await advanceToIntegrationsStep();
    fireEvent.click(screen.getByTestId('setup-integration-victoria-toggle'));
    const endpoint = await screen.findByLabelText('setup.integrationsVictoriaEndpoint');
    fireEvent.change(endpoint, { target: { value: '127.0.0.1:9428' } });
    clickNext();
    await waitFor(() => expect(toastMocks.error).toHaveBeenCalledWith('setup.integrationsEndpointInvalid'));
    expect(screen.queryByText('setup.summaryTitle')).toBeNull();
  });

  it('rejects a Prometheus metrics path that is not absolute', async () => {
    await advanceToIntegrationsStep();
    fireEvent.click(screen.getByTestId('setup-integration-prometheus-toggle'));
    const path = await screen.findByLabelText('setup.integrationsPrometheusPath');
    fireEvent.change(path, { target: { value: 'metrics' } });
    clickNext();
    await waitFor(() => expect(toastMocks.error).toHaveBeenCalledWith('setup.integrationsPathInvalid'));
  });

  it('records an enabled integration in the review summary and says it applies after install', async () => {
    await advanceToIntegrationsStep();
    fireEvent.click(screen.getByTestId('setup-integration-prometheus-toggle'));
    await waitFor(() => expect(screen.getByLabelText('setup.integrationsPrometheusPath')).toBeTruthy());
    // The yaml default (/metrics) is prefilled, so the step accepts it as-is.
    clickNext();
    await waitFor(() => expect(screen.getByText('setup.summaryTitle')).toBeTruthy());
    expect(screen.getByText('setup.summaryIntegrations')).toBeTruthy();
    expect(screen.getByText('setup.integrationsPrometheusTitle')).toBeTruthy();
    expect(screen.getByText('setup.integrationsDeferred')).toBeTruthy();
  });
});

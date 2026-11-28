import type {
  AuthTestResult,
  ChatMode,
  EventLogEntry,
  GitHubAuthMode,
  PrGroupRecord,
  RateLimitState,
  RedactedPluginConfig,
  RepoRule,
  RepoRuntimeState,
} from '../types.ts';
import {
  DEFAULT_GITHUB_API_BASE_URL,
  DEFAULT_MAX_GROUP_CREATES_PER_HOUR,
  DEFAULT_POLL_INTERVAL_SEC,
  DEFAULT_SERVICE_PORT,
  DEFAULT_WEBHOOK_PATH,
} from '../types.ts';
import {
  PRESET_GROUP_NAME_TEMPLATE,
  PRESET_RULE_NAME,
  buildBotOptions,
  buildGlobalAdvancedSummary,
  changeCreatorBot,
  computeLatestSyncTime,
  countCustomizedAdvancedFields,
  createPresetRuleDraft,
  draftToRule,
  formatDisplayTime,
  formatGhAutoDetectedText,
  hasFullGitHubAppConfig,
  pickDefaultCreatorBotId,
  resolveBotDisplayName,
  resolveEffectiveAuthState,
  ruleToDraft,
  shouldAutoDetectGhAuth,
  splitCsv,
  toggleReviewerBot,
  validatePrSpecInput,
  validateRepoInput,
  validateRuleDraft,
  type BotListItem,
  type BotStatusItem,
  type RuleDraft,
} from './helpers.ts';

interface HostReact {
  createElement: (...args: unknown[]) => unknown;
  useState: <T>(initial: T | (() => T)) => [T, (next: T | ((prev: T) => T)) => void];
  useEffect: (effect: () => void | (() => void), deps?: unknown[]) => void;
  useCallback: <T extends (...args: never[]) => unknown>(fn: T, deps: unknown[]) => T;
  useMemo: <T>(factory: () => T, deps: unknown[]) => T;
}

export interface PluginDashboardApi {
  react: HostReact;
  getSettings(): Promise<unknown>;
  saveSettings(value: unknown): Promise<unknown>;
  listBots(): Promise<BotListItem[]>;
  getServiceStatus?: () => Promise<unknown>;
  startService?: () => Promise<unknown>;
  stopService?: () => Promise<unknown>;
  restartService?: () => Promise<unknown>;
  serviceFetch?: (
    path: string,
    init?: { method?: string; body?: string; headers?: Record<string, string> },
  ) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;
  requestService?: (req: { method: 'GET' | 'POST'; path: string; body?: unknown }) => Promise<unknown>;
}

interface SettingsEnvelope {
  ok?: boolean;
  config?: RedactedPluginConfig;
  service?: {
    online: boolean;
    mode: string;
    port: number;
    configuredPort: number;
    portRestartRequired?: boolean;
    uptimeSec?: number;
    queue?: { active: number; queued: number; pending: number };
  };
  rateLimits?: RateLimitState;
  repos?: Record<string, RepoRuntimeState>;
  prGroups?: Record<string, PrGroupRecord>;
  recentEvents?: EventLogEntry[];
  botStatus?: BotStatusItem[];
}

/**
 * Dual-core transport adapter:
 * - Prefers live service proxy (`api.serviceFetch` / `api.requestService`) when available.
 * - Falls back cleanly to `api.getSettings()` / `api.saveSettings(...)` on current core or offline service.
 */
async function callServiceOrSettingsAction(
  api: PluginDashboardApi,
  opts: {
    servicePath: string;
    serviceMethod: 'GET' | 'POST';
    serviceBody?: Record<string, unknown>;
    settingsAction?: string;
    settingsPayload?: Record<string, unknown>;
  },
): Promise<Record<string, unknown>> {
  if (typeof api.serviceFetch === 'function') {
    try {
      const resp = await api.serviceFetch(opts.servicePath, {
        method: opts.serviceMethod,
        ...(opts.serviceBody
          ? {
              body: JSON.stringify(opts.serviceBody),
              headers: {
                'Content-Type': 'application/json',
                'X-Botmux-Plugin-Control': '1',
              },
            }
          : {}),
      });
      if (resp.ok) {
        const data = await resp.json();
        if (data && typeof data === 'object') {
          return data as Record<string, unknown>;
        }
      }
      if (
        resp.status !== 401 &&
        resp.status !== 403 &&
        resp.status !== 404 &&
        resp.status !== 501 &&
        resp.status !== 502 &&
        resp.status !== 503 &&
        resp.status !== 504
      ) {
        const data = await resp.json().catch(() => ({ ok: false, error: `HTTP ${resp.status}` }));
        if (data && typeof data === 'object') {
          return data as Record<string, unknown>;
        }
      }
    } catch {
      // Fall through to getSettings/saveSettings bridge
    }
  } else if (typeof api.requestService === 'function') {
    try {
      const data = await api.requestService({
        method: opts.serviceMethod,
        path: opts.servicePath,
        ...(opts.serviceBody ? { body: opts.serviceBody } : {}),
      });
      if (data && typeof data === 'object') {
        return data as Record<string, unknown>;
      }
    } catch {
      // Fall through to getSettings/saveSettings bridge
    }
  }

  if (opts.serviceMethod === 'GET') {
    const data = await api.getSettings();
    return (data && typeof data === 'object' ? data : {}) as Record<string, unknown>;
  }
  const data = await api.saveSettings({
    action: opts.settingsAction,
    ...(opts.settingsPayload ?? {}),
  });
  return (data && typeof data === 'object' ? data : {}) as Record<string, unknown>;
}

const STYLES = {
  page: {
    maxWidth: '960px',
    margin: '0 auto',
    padding: '20px 16px 48px',
    fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    color: 'inherit',
    lineHeight: 1.5,
  },
  card: {
    border: '1px solid rgba(128,128,128,0.24)',
    borderRadius: '12px',
    padding: '16px 18px',
    marginBottom: '16px',
    background: 'rgba(128,128,128,0.035)',
  },
  subCard: {
    border: '1px solid rgba(128,128,128,0.22)',
    borderRadius: '10px',
    padding: '14px 16px',
    marginTop: '12px',
    background: 'rgba(128,128,128,0.03)',
  },
  statusBanner: (tone: 'ok' | 'warn' | 'err' | 'neutral') => ({
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    flexWrap: 'wrap' as const,
    gap: '12px',
    padding: '12px 14px',
    borderRadius: '10px',
    border:
      tone === 'ok'
        ? '1px solid rgba(22,163,74,0.45)'
        : tone === 'warn'
          ? '1px solid rgba(234,179,8,0.45)'
          : tone === 'err'
            ? '1px solid rgba(220,38,38,0.45)'
            : '1px solid rgba(128,128,128,0.28)',
    background:
      tone === 'ok'
        ? 'rgba(22,163,74,0.09)'
        : tone === 'warn'
          ? 'rgba(234,179,8,0.09)'
          : tone === 'err'
            ? 'rgba(220,38,38,0.09)'
            : 'rgba(128,128,128,0.06)',
  }),
  kpiGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(175px, 1fr))',
    gap: '10px',
    marginTop: '12px',
  },
  kpiTile: {
    border: '1px solid rgba(128,128,128,0.18)',
    borderRadius: '8px',
    padding: '10px 12px',
    background: 'rgba(128,128,128,0.03)',
  },
  kpiLabel: {
    fontSize: '11.5px',
    opacity: 0.72,
    marginBottom: '4px',
  },
  kpiValue: {
    fontSize: '14px',
    fontWeight: 600,
  },
  row: {
    display: 'flex',
    flexWrap: 'wrap' as const,
    gap: '8px',
    alignItems: 'center',
  },
  between: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    flexWrap: 'wrap' as const,
    gap: '10px',
  },
  grid2: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
    gap: '12px',
  },
  label: {
    display: 'block',
    fontSize: '12.5px',
    fontWeight: 600,
    marginBottom: '5px',
    opacity: 0.9,
  },
  hint: {
    fontSize: '12px',
    opacity: 0.72,
    marginTop: '4px',
  },
  input: {
    width: '100%',
    boxSizing: 'border-box' as const,
    padding: '8px 10px',
    borderRadius: '7px',
    border: '1px solid rgba(128,128,128,0.35)',
    background: 'transparent',
    color: 'inherit',
    fontSize: '13px',
  },
  btn: {
    padding: '7px 13px',
    borderRadius: '7px',
    border: '1px solid rgba(128,128,128,0.35)',
    background: 'rgba(128,128,128,0.09)',
    color: 'inherit',
    cursor: 'pointer',
    fontSize: '13px',
    fontWeight: 500,
  },
  btnPrimary: {
    padding: '7px 14px',
    borderRadius: '7px',
    border: '1px solid #2563eb',
    background: '#2563eb',
    color: '#ffffff',
    cursor: 'pointer',
    fontSize: '13px',
    fontWeight: 600,
  },
  btnDanger: {
    padding: '6px 11px',
    borderRadius: '7px',
    border: '1px solid rgba(220,38,38,0.45)',
    background: 'rgba(220,38,38,0.08)',
    color: '#ef4444',
    cursor: 'pointer',
    fontSize: '12px',
  },
  collapseBtn: {
    width: '100%',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    flexWrap: 'wrap' as const,
    gap: '8px',
    padding: '8px 10px',
    borderRadius: '8px',
    border: '1px solid rgba(128,128,128,0.2)',
    background: 'rgba(128,128,128,0.05)',
    color: 'inherit',
    cursor: 'pointer',
    fontSize: '13px',
    fontWeight: 600,
    textAlign: 'left' as const,
  },
  badge: (tone: 'ok' | 'warn' | 'muted' | 'err' | 'info') => ({
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: '999px',
    fontSize: '11px',
    fontWeight: 600,
    background:
      tone === 'ok'
        ? 'rgba(22,163,74,0.18)'
        : tone === 'warn'
          ? 'rgba(234,179,8,0.22)'
          : tone === 'err'
            ? 'rgba(220,38,38,0.2)'
            : tone === 'info'
              ? 'rgba(37,99,235,0.18)'
              : 'rgba(128,128,128,0.2)',
    color:
      tone === 'ok'
        ? '#16a34a'
        : tone === 'warn'
          ? '#ca8a04'
          : tone === 'err'
            ? '#ef4444'
            : tone === 'info'
              ? '#3b82f6'
              : 'inherit',
  }),
  stepTag: {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '20px',
    height: '20px',
    borderRadius: '999px',
    background: 'rgba(37,99,235,0.16)',
    color: '#3b82f6',
    fontSize: '11.5px',
    fontWeight: 700,
    marginRight: '6px',
  },
  checkboxList: {
    border: '1px solid rgba(128,128,128,0.32)',
    borderRadius: '8px',
    padding: '8px 10px',
    maxHeight: '150px',
    overflowY: 'auto' as const,
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '6px',
    fontSize: '13px',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse' as const,
    fontSize: '12.5px',
  },
  th: {
    textAlign: 'left' as const,
    padding: '8px 6px',
    borderBottom: '1px solid rgba(128,128,128,0.24)',
    fontWeight: 600,
    opacity: 0.78,
  },
  td: {
    padding: '9px 6px',
    borderBottom: '1px solid rgba(128,128,128,0.14)',
    verticalAlign: 'top' as const,
  },
};

export default function GitHubPluginDashboard(props: {
  pluginId: string;
  api: PluginDashboardApi;
}) {
  const { api } = props;
  const React = api.react;
  const h = React.createElement;
  const { useState, useEffect, useCallback, useMemo } = React;

  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [probingAuth, setProbingAuth] = useState(false);
  const [notice, setNotice] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);
  const [envelope, setEnvelope] = useState<SettingsEnvelope | null>(null);
  const [bots, setBots] = useState<BotListItem[]>([]);

  // Collapsible disclosure states (all default collapsed!)
  const [showAuthSwitch, setShowAuthSwitch] = useState(false);
  const [showRuleAdvanced, setShowRuleAdvanced] = useState(false);
  const [showGlobalAdvanced, setShowGlobalAdvanced] = useState(false);

  // Auth form state (write-only secrets always start blank!)
  const [authMode, setAuthMode] = useState<GitHubAuthMode>('gh_cli');
  const [apiBaseUrl, setApiBaseUrl] = useState(DEFAULT_GITHUB_API_BASE_URL);
  const [ghHostname, setGhHostname] = useState('');
  const [patInput, setPatInput] = useState('');
  const [clearPat, setClearPat] = useState(false);
  const [appId, setAppId] = useState('');
  const [installationId, setInstallationId] = useState('');
  const [privateKeyInput, setPrivateKeyInput] = useState('');
  const [clearPrivateKey, setClearPrivateKey] = useState(false);

  // Global advanced settings state (write-only secrets always start blank!)
  const [proxyUrl, setProxyUrl] = useState('');
  const [proxyUsername, setProxyUsername] = useState('');
  const [proxyPasswordInput, setProxyPasswordInput] = useState('');
  const [clearProxyPassword, setClearProxyPassword] = useState(false);
  const [webhookEnabled, setWebhookEnabled] = useState(false);
  const [webhookPath, setWebhookPath] = useState(DEFAULT_WEBHOOK_PATH);
  const [webhookSecretInput, setWebhookSecretInput] = useState('');
  const [clearWebhookSecret, setClearWebhookSecret] = useState(false);
  const [servicePort, setServicePort] = useState(String(DEFAULT_SERVICE_PORT));
  const [pollIntervalSec, setPollIntervalSec] = useState(String(DEFAULT_POLL_INTERVAL_SEC));
  const [maxCreatesPerHour, setMaxCreatesPerHour] = useState(
    String(DEFAULT_MAX_GROUP_CREATES_PER_HOUR),
  );

  // Rules list & inline editor state
  const [rules, setRules] = useState<RepoRule[]>([]);
  const [editingIndex, setEditingIndex] = useState<number | null>(null);
  const [ruleDraft, setRuleDraft] = useState<RuleDraft | null>(null);

  // Auth probe & manual backfill state
  const [authTestResult, setAuthTestResult] = useState<AuthTestResult | null>(null);
  const [openPrInput, setOpenPrInput] = useState('');

  // Mutable ref-like box without React.useRef (compatible with minimal mockReact)
  const autoProbeTracker = useMemo(() => ({ lastKey: '' }), []);

  const hydrateFromEnvelope = useCallback((env: SettingsEnvelope) => {
    setEnvelope(env);
    const cfg = env.config;
    if (!cfg) return;

    const fullApp = hasFullGitHubAppConfig(cfg);
    // Default UI auth selector to gh_cli when config is fresh auto without PAT/App
    const uiAuthMode: GitHubAuthMode =
      cfg.github.mode === 'auto' && !cfg.github.hasPat && !fullApp ? 'gh_cli' : cfg.github.mode;
    setAuthMode(uiAuthMode);
    setApiBaseUrl(cfg.github.apiBaseUrl);
    setGhHostname(cfg.github.ghHostname ?? '');
    setAppId(cfg.github.app.appId);
    setInstallationId(cfg.github.app.installationId);

    setProxyUrl(cfg.proxy.url);
    setProxyUsername(cfg.proxy.username ?? '');
    setWebhookEnabled(cfg.webhook.enabled);
    setWebhookPath(cfg.webhook.path);
    setServicePort(String(cfg.service.port));
    setPollIntervalSec(String(cfg.service.pollIntervalSec));
    setMaxCreatesPerHour(
      String(cfg.service.maxGroupCreatesPerRepoPerHour ?? DEFAULT_MAX_GROUP_CREATES_PER_HOUR),
    );
    setRules(cfg.repos);

    // Always clear write-only secret inputs after save/refresh
    setPatInput('');
    setClearPat(false);
    setPrivateKeyInput('');
    setClearPrivateKey(false);
    setProxyPasswordInput('');
    setClearProxyPassword(false);
    setWebhookSecretInput('');
    setClearWebhookSecret(false);
  }, []);

  const runAuthProbe = useCallback(
    async (opts?: { silent?: boolean }) => {
      const silent = opts?.silent === true;
      if (silent) {
        setProbingAuth(true);
      } else {
        setBusy(true);
        setNotice(null);
      }
      try {
        const raw = await callServiceOrSettingsAction(api, {
          servicePath: '/api/test-auth',
          serviceMethod: 'POST',
          serviceBody: {},
          settingsAction: 'testAuth',
        });
        const res = raw as unknown as AuthTestResult;
        // Guard against mock responses that do not carry auth result fields
        if (typeof res?.ok === 'boolean' && (res.resolvedMethod || res.error || res.identity)) {
          setAuthTestResult(res);
          if (res.ok && res.resolvedMethod === 'gh_cli') {
            setAuthMode(prev => (prev === 'auto' ? 'gh_cli' : prev));
          }
          if (!silent) {
            setNotice({
              kind: res.ok ? 'ok' : 'err',
              text: res.ok
                ? `连接正常（${res.resolvedMethod ?? res.authMode}）：${res.identity ?? '已通过鉴权'}`
                : `连接测试失败：${res.error ?? '未知错误'}`,
            });
          }
        } else if (!silent) {
          setNotice({
            kind: res?.ok ? 'ok' : 'err',
            text: res?.ok ? '连接测试通过' : `连接测试失败：${res?.error ?? '未知错误'}`,
          });
        }
      } catch (err) {
        if (!silent) {
          setNotice({ kind: 'err', text: `连接测试失败：${String(err)}` });
        }
      } finally {
        if (silent) {
          setProbingAuth(false);
        } else {
          setBusy(false);
        }
      }
    },
    [api],
  );

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [settingsRaw, botList, hostServiceStatus] = await Promise.all([
        api.getSettings(),
        api.listBots().catch(() => [] as BotListItem[]),
        typeof api.getServiceStatus === 'function'
          ? api.getServiceStatus().catch(() => undefined)
          : Promise.resolve(undefined),
      ]);
      const baseEnv = (settingsRaw && typeof settingsRaw === 'object'
        ? settingsRaw
        : {}) as SettingsEnvelope;

      if (
        hostServiceStatus &&
        typeof hostServiceStatus === 'object' &&
        (hostServiceStatus as { status?: unknown }).status === 'online' &&
        baseEnv.service
      ) {
        baseEnv.service.online = true;
      }

      // Probe live service directly via new-core serviceFetch/requestService
      let live: Record<string, unknown> | null = null;
      if (typeof api.serviceFetch === 'function') {
        try {
          const resp = await api.serviceFetch('/api/status', { method: 'GET' });
          if (resp.ok) {
            const parsed = await resp.json();
            if (parsed && typeof parsed === 'object') {
              live = parsed as Record<string, unknown>;
            }
          }
        } catch {
          // Service offline; keep baseEnv
        }
      } else if (typeof api.requestService === 'function') {
        try {
          const parsed = await api.requestService({ method: 'GET', path: '/api/status' });
          if (parsed && typeof parsed === 'object') {
            live = parsed as Record<string, unknown>;
          }
        } catch {
          // Service offline; keep baseEnv
        }
      }

      if (live && live.ok === true && live.config) {
        baseEnv.service = {
          online: true,
          mode: String(live.mode ?? baseEnv.service?.mode ?? 'dormant'),
          port: Number(live.port ?? baseEnv.service?.port ?? DEFAULT_SERVICE_PORT),
          configuredPort: Number(
            live.configuredPort ?? baseEnv.service?.configuredPort ?? DEFAULT_SERVICE_PORT,
          ),
          portRestartRequired: Boolean(live.portRestartRequired),
          uptimeSec: typeof live.uptimeSec === 'number' ? live.uptimeSec : undefined,
        };
        if (live.rateLimits) baseEnv.rateLimits = live.rateLimits as RateLimitState;
        if (live.repos) baseEnv.repos = live.repos as Record<string, RepoRuntimeState>;
        if (live.prGroups) baseEnv.prGroups = live.prGroups as Record<string, PrGroupRecord>;
        if (Array.isArray(live.recentEvents)) {
          baseEnv.recentEvents = live.recentEvents as EventLogEntry[];
        }
      }

      hydrateFromEnvelope(baseEnv);
      setBots(Array.isArray(botList) ? botList : []);

      // Auto-detect local gh auth token once per auth config signature when gh_cli is the default path
      const cfg = baseEnv.config;
      if (cfg && shouldAutoDetectGhAuth(cfg)) {
        const probeKey = `${cfg.github.mode}|${cfg.github.apiBaseUrl}|${cfg.github.ghHostname ?? ''}|${cfg.github.hasPat}|${hasFullGitHubAppConfig(cfg)}`;
        if (autoProbeTracker.lastKey !== probeKey) {
          autoProbeTracker.lastKey = probeKey;
          void runAuthProbe({ silent: true });
        }
      }
    } catch (err) {
      setNotice({ kind: 'err', text: `加载 GitHub 插件配置失败：${String(err)}` });
    } finally {
      setLoading(false);
    }
  }, [api, hydrateFromEnvelope, runAuthProbe, autoProbeTracker]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const botOptions = useMemo(
    () => buildBotOptions(bots, envelope?.botStatus),
    [bots, envelope],
  );

  const persistPatch = useCallback(
    async (patch: Record<string, unknown>, successText: string) => {
      setBusy(true);
      setNotice(null);
      try {
        const res = (await api.saveSettings({
          action: 'saveConfig',
          patch,
        })) as { ok?: boolean; error?: string; portRestartRequired?: boolean };
        if (res?.ok === false) {
          setNotice({ kind: 'err', text: res.error || '保存配置失败' });
          return false;
        }
        setNotice({
          kind: 'ok',
          text: res?.portRestartRequired
            ? `${successText}（已更改端口，请重启服务生效）`
            : successText,
        });
        await refresh();
        return true;
      } catch (err) {
        setNotice({ kind: 'err', text: `保存失败：${String(err)}` });
        return false;
      } finally {
        setBusy(false);
      }
    },
    [api, refresh],
  );

  const handleSaveAuthSettings = useCallback(async () => {
    const patch = {
      github: {
        mode: authMode,
        apiBaseUrl: apiBaseUrl.trim() || DEFAULT_GITHUB_API_BASE_URL,
        ghHostname: ghHostname.trim(),
        ...(clearPat ? { clearPat: true } : patInput.trim() ? { pat: patInput.trim() } : {}),
        app: {
          appId: appId.trim(),
          installationId: installationId.trim(),
          ...(clearPrivateKey
            ? { clearPrivateKey: true }
            : privateKeyInput.trim()
              ? { privateKeyPem: privateKeyInput.trim() }
              : {}),
        },
      },
    };
    const prevProbeKey = autoProbeTracker.lastKey;
    autoProbeTracker.lastKey = '';
    setAuthTestResult(null);
    const ok = await persistPatch(patch, '已保存 GitHub 鉴权设置。');
    if (ok) {
      setShowAuthSwitch(false);
    } else {
      autoProbeTracker.lastKey = prevProbeKey;
    }
  }, [
    authMode,
    apiBaseUrl,
    ghHostname,
    clearPat,
    patInput,
    appId,
    installationId,
    clearPrivateKey,
    privateKeyInput,
    persistPatch,
    autoProbeTracker,
  ]);

  const handleSaveGlobalAdvanced = useCallback(async () => {
    const patch = {
      proxy: {
        url: proxyUrl.trim(),
        username: proxyUsername.trim(),
        ...(clearProxyPassword
          ? { clearPassword: true }
          : proxyPasswordInput
            ? { password: proxyPasswordInput }
            : {}),
      },
      webhook: {
        enabled: webhookEnabled,
        path: webhookPath.trim() || DEFAULT_WEBHOOK_PATH,
        ...(clearWebhookSecret
          ? { clearSecret: true }
          : webhookSecretInput.trim()
            ? { secret: webhookSecretInput.trim() }
            : {}),
      },
      service: {
        port: servicePort.trim() === '' ? DEFAULT_SERVICE_PORT : Number(servicePort),
        pollIntervalSec:
          pollIntervalSec.trim() === '' ? DEFAULT_POLL_INTERVAL_SEC : Number(pollIntervalSec),
        maxGroupCreatesPerRepoPerHour:
          maxCreatesPerHour.trim() === ''
            ? DEFAULT_MAX_GROUP_CREATES_PER_HOUR
            : Number(maxCreatesPerHour),
      },
    };
    await persistPatch(patch, '已保存高级设置。');
  }, [
    proxyUrl,
    proxyUsername,
    clearProxyPassword,
    proxyPasswordInput,
    webhookEnabled,
    webhookPath,
    clearWebhookSecret,
    webhookSecretInput,
    servicePort,
    pollIntervalSec,
    maxCreatesPerHour,
    persistPatch,
  ]);

  const handleOpenNewRule = useCallback(() => {
    setEditingIndex(null);
    setShowRuleAdvanced(false);
    setRuleDraft(createPresetRuleDraft(pickDefaultCreatorBotId(botOptions)));
  }, [botOptions]);

  const handleOpenEditRule = useCallback((idx: number, rule: RepoRule) => {
    setEditingIndex(idx);
    setShowRuleAdvanced(false);
    setRuleDraft(ruleToDraft(rule));
  }, []);

  const handleSaveRuleDraft = useCallback(async () => {
    if (!ruleDraft) return;
    const validationErr = validateRuleDraft(ruleDraft, rules, editingIndex);
    if (validationErr) {
      setNotice({ kind: 'err', text: validationErr });
      return;
    }
    const rule = draftToRule(ruleDraft);
    const nextRules = [...rules];
    if (editingIndex === null || editingIndex < 0 || editingIndex >= nextRules.length) {
      nextRules.push(rule);
    } else {
      nextRules[editingIndex] = rule;
    }

    const cfg = envelope?.config;
    const shouldPinGhCliMode =
      cfg &&
      cfg.github.mode === 'auto' &&
      !cfg.github.hasPat &&
      !hasFullGitHubAppConfig(cfg) &&
      authTestResult?.ok === true &&
      authTestResult.resolvedMethod === 'gh_cli';

    const patch: Record<string, unknown> = {
      ...(shouldPinGhCliMode ? { github: { mode: 'gh_cli' } } : {}),
      repos: nextRules,
    };

    const ok = await persistPatch(patch, `已保存仓库规则：${rule.repo}`);
    if (ok) {
      setRuleDraft(null);
      setEditingIndex(null);
      setShowRuleAdvanced(false);
    }
  }, [ruleDraft, rules, editingIndex, envelope, authTestResult, persistPatch]);

  const handleDeleteRule = useCallback(
    async (index: number) => {
      const target = rules[index];
      if (!target) return;
      const nextRules = rules.filter((_, i) => i !== index);
      await persistPatch({ repos: nextRules }, `已删除仓库规则：${target.repo}`);
    },
    [rules, persistPatch],
  );

  const handleToggleRule = useCallback(
    async (index: number) => {
      const target = rules[index];
      if (!target) return;
      const nextRules = rules.map((r, i) => (i === index ? { ...r, enabled: !r.enabled } : r));
      await persistPatch(
        { repos: nextRules },
        `${target.enabled ? '已停用' : '已启用'}仓库监控：${target.repo}`,
      );
    },
    [rules, persistPatch],
  );

  const handleSyncNow = useCallback(
    async (dryRun: boolean) => {
      setBusy(true);
      setNotice(null);
      try {
        const res = await callServiceOrSettingsAction(api, {
          servicePath: '/api/sync',
          serviceMethod: 'POST',
          serviceBody: { dryRun, async: !dryRun },
          settingsAction: 'sync',
          settingsPayload: { dryRun },
        });
        if (res.ok === false) {
          setNotice({ kind: 'err', text: String(res.error ?? '同步失败') });
        } else if (res.accepted) {
          setNotice({ kind: 'ok', text: '已触发后台立即同步。' });
          setTimeout(() => void refresh(), 1200);
        } else {
          const count = Array.isArray(res.actions) ? res.actions.length : 0;
          setNotice({
            kind: 'ok',
            text: `${dryRun ? '模拟同步' : '同步'}完成（${count} 条动作）。`,
          });
          await refresh();
        }
      } catch (err) {
        setNotice({ kind: 'err', text: `同步失败：${String(err)}` });
      } finally {
        setBusy(false);
      }
    },
    [api, refresh],
  );

  const handleOpenPr = useCallback(
    async (dryRun: boolean) => {
      const parsed = validatePrSpecInput(openPrInput);
      if (!parsed.ok) {
        setNotice({ kind: 'err', text: parsed.error });
        return;
      }
      setBusy(true);
      setNotice(null);
      try {
        const res = await callServiceOrSettingsAction(api, {
          servicePath: '/api/open-pr',
          serviceMethod: 'POST',
          serviceBody: { repo: parsed.repo, prNumber: parsed.prNumber, dryRun },
          settingsAction: 'openPr',
          settingsPayload: { repo: parsed.repo, prNumber: parsed.prNumber, dryRun },
        });
        if (res.ok === false) {
          setNotice({ kind: 'err', text: String(res.error ?? '补建评审群失败') });
        } else {
          setNotice({
            kind: 'ok',
            text: `${parsed.repo}#${parsed.prNumber}：${String(res.action ?? 'ok')}${res.chatId ? `（群 ID: ${String(res.chatId)}）` : ''}`,
          });
          await refresh();
        }
      } catch (err) {
        setNotice({ kind: 'err', text: `补建评审群失败：${String(err)}` });
      } finally {
        setBusy(false);
      }
    },
    [api, openPrInput, refresh],
  );

  const handleServiceLifecycle = useCallback(
    async (op: 'start' | 'stop' | 'restart') => {
      const fn =
        op === 'start'
          ? api.startService
          : op === 'stop'
            ? api.stopService
            : api.restartService;
      if (typeof fn !== 'function') return;
      setBusy(true);
      setNotice(null);
      try {
        await fn();
        const opText = op === 'start' ? '启动' : op === 'stop' ? '停止' : '重启';
        setNotice({ kind: 'ok', text: `已发送服务${opText}指令。` });
        await refresh();
      } catch (err) {
        setNotice({ kind: 'err', text: `服务操作失败：${String(err)}` });
      } finally {
        setBusy(false);
      }
    },
    [api, refresh],
  );

  const cfg = envelope?.config;
  const svc = envelope?.service;
  const rl = envelope?.rateLimits;
  const coreQuota = rl?.core ?? authTestResult?.rateLimit;
  const enabledRulesCount = rules.filter(r => r.enabled).length;
  const latestSyncAt = useMemo(() => computeLatestSyncTime(envelope?.repos), [envelope]);
  const prGroups = useMemo(() => {
    const entries = Object.values(envelope?.prGroups ?? {});
    return entries.sort((a, b) => Date.parse(b.updatedAt) - Date.parse(a.updatedAt));
  }, [envelope]);
  const recentEvents = envelope?.recentEvents ?? [];

  const serviceMode = svc?.mode ?? (enabledRulesCount > 0 ? 'active' : 'dormant');
  const modeBadgeTone =
    serviceMode === 'active' ? 'ok' : serviceMode === 'paused' ? 'warn' : 'muted';
  const modeLabel =
    serviceMode === 'active'
      ? '监控中 (active)'
      : serviceMode === 'paused'
        ? '限流退避 (paused)'
        : '休眠等待首条规则 (dormant)';

  const effectiveAuth = resolveEffectiveAuthState(cfg);
  const isCustomApiBase = Boolean(
    cfg?.github.apiBaseUrl && cfg.github.apiBaseUrl !== DEFAULT_GITHUB_API_BASE_URL,
  );

  const globalAdvancedSummary = buildGlobalAdvancedSummary({
    pollIntervalSec: Number(pollIntervalSec) || DEFAULT_POLL_INTERVAL_SEC,
    webhookEnabled,
    proxyUrl,
    port: Number(servicePort) || DEFAULT_SERVICE_PORT,
    maxGroupCreatesPerRepoPerHour:
      Number(maxCreatesPerHour) || DEFAULT_MAX_GROUP_CREATES_PER_HOUR,
  });

  // Compute inline validation & custom badge for active RuleDraft
  const repoLiveError =
    ruleDraft && ruleDraft.repo.trim().length > 0
      ? (() => {
          const check = validateRepoInput(ruleDraft.repo);
          return check.ok ? null : check.error;
        })()
      : null;
  const customizedAdvancedCount = ruleDraft ? countCustomizedAdvancedFields(ruleDraft) : 0;

  // Build auth status card content
  const renderAuthStatusCard = () => {
    let tone: 'ok' | 'warn' | 'err' | 'neutral' = 'neutral';
    let title = '正在检测本机 gh 登录状态…';
    let subtitle = '免配置自动探测本机 GitHub CLI 凭证（仅内存使用，不回显给前端）';

    if (effectiveAuth === 'gh_cli') {
      if (authTestResult?.ok && authTestResult.resolvedMethod === 'gh_cli') {
        tone = 'ok';
        title = formatGhAutoDetectedText(authTestResult.identity);
        subtitle = `当前模式：gh-cli（内存读取，不落盘、不回显给前端）${isCustomApiBase ? ` · API: ${cfg?.github.apiBaseUrl}` : ''}`;
      } else if (probingAuth) {
        tone = 'neutral';
        title = '正在检测本机 gh 登录状态…';
        subtitle = '默认复用本机 gh auth token，免手动配置密钥';
      } else if (authTestResult && !authTestResult.ok) {
        tone = 'warn';
        title = '未检测到可用的本机 gh 登录状态';
        subtitle = `可在本机终端执行 gh auth login 后点击「测试连接」，或展开下方切换 PAT / GitHub App。${authTestResult.error ? `（${authTestResult.error}）` : ''}`;
      } else {
        tone = 'neutral';
        title = '默认使用本机 gh CLI 鉴权（gh-cli）';
        subtitle = '点击右侧「测试连接」验证本机 gh 登录状态，或展开下方切换其他鉴权方式';
      }
    } else if (effectiveAuth === 'pat') {
      tone = authTestResult && !authTestResult.ok ? 'err' : 'ok';
      title = `已配置 Personal Access Token（PAT）鉴权${authTestResult?.ok && authTestResult.identity ? ` · ${authTestResult.identity}` : ''}`;
      subtitle = `密钥仅服务端只写保存（0600 权限，不回显给前端）${isCustomApiBase ? ` · API: ${cfg?.github.apiBaseUrl}` : ''}${authTestResult && !authTestResult.ok && authTestResult.error ? ` · 测试失败：${authTestResult.error}` : ''}`;
    } else if (effectiveAuth === 'github_app') {
      tone = authTestResult && !authTestResult.ok ? 'err' : 'ok';
      title = `已配置 GitHub App 鉴权${authTestResult?.ok && authTestResult.identity ? ` · ${authTestResult.identity}` : ''}`;
      subtitle = `App ID: ${cfg?.github.app.appId ?? ''} · Installation ID: ${cfg?.github.app.installationId ?? ''} · 私钥已安全保存（不回显给前端）${isCustomApiBase ? ` · API: ${cfg?.github.apiBaseUrl}` : ''}${authTestResult && !authTestResult.ok && authTestResult.error ? ` · 测试失败：${authTestResult.error}` : ''}`;
    } else if (effectiveAuth === 'incomplete_pat') {
      tone = 'warn';
      title = '已选择 PAT 鉴权，但尚未填写 Token';
      subtitle = '请展开下方「切换其他鉴权方式」填写 PAT，或切换回本机 gh 免配模式';
    } else {
      tone = 'warn';
      title = '已选择 GitHub App 鉴权，但配置不完整';
      subtitle = '请展开下方「切换其他鉴权方式」补齐 App ID、Installation ID 与 RSA 私钥';
    }

    return h(
      'div',
      { style: STYLES.statusBanner(tone), 'data-section': 'auth-status' },
      h(
        'div',
        { style: { flex: '1 1 280px' } },
        h('div', { style: { fontSize: '14px', fontWeight: 600 } }, title),
        h('div', { style: { fontSize: '12px', opacity: 0.82, marginTop: '3px' } }, subtitle),
      ),
      h(
        'button',
        {
          style: STYLES.btn,
          disabled: busy || probingAuth,
          'data-action': 'test-auth',
          onClick: () => void runAuthProbe({ silent: false }),
        },
        probingAuth ? '检测中…' : '测试连接',
      ),
    );
  };

  // Build rule editor (2 required steps + collapsed advanced section)
  const renderRuleEditor = () => {
    if (!ruleDraft) return null;

    const creatorInList = botOptions.some(b => b.id === ruleDraft.creatorBotAppId);
    const reviewerCandidates = botOptions.filter(b => b.id !== ruleDraft.creatorBotAppId);
    const kickoffCandidates = [
      ...reviewerCandidates.filter(b => ruleDraft.memberBotAppIds.includes(b.id)),
      ...reviewerCandidates.filter(b => !ruleDraft.memberBotAppIds.includes(b.id)),
    ];
    const kickoffInList =
      !ruleDraft.kickoffBotAppId || kickoffCandidates.some(b => b.id === ruleDraft.kickoffBotAppId);

    return h(
      'div',
      { style: STYLES.subCard, 'data-section': 'rule-editor' },
      h(
        'div',
        { style: { ...STYLES.between, marginBottom: '12px' } },
        h(
          'div',
          { style: STYLES.row },
          h(
            'h4',
            { style: { margin: 0, fontSize: '14.5px' } },
            editingIndex === null ? '新增仓库监控规则' : `编辑规则：${ruleDraft.repo}`,
          ),
          h('span', { style: STYLES.badge('info') }, `预设：${PRESET_RULE_NAME}`),
        ),
        h(
          'label',
          { style: { display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '12.5px' } },
          h('input', {
            type: 'checkbox',
            checked: ruleDraft.enabled,
            onChange: (e: { target: { checked: boolean } }) =>
              setRuleDraft({ ...ruleDraft, enabled: e.target.checked }),
          }),
          '保存后立即启用',
        ),
      ),

      // Step 1: Repository Slug (Required)
      h(
        'div',
        { style: { marginBottom: '14px' } },
        h(
          'label',
          { style: STYLES.label },
          h('span', { style: STYLES.stepTag }, '1'),
          '仓库名（必填，格式 owner/repo）',
        ),
        h('input', {
          style: {
            ...STYLES.input,
            ...(repoLiveError ? { borderColor: 'rgba(220,38,38,0.7)' } : {}),
          },
          'data-field': 'repo',
          value: ruleDraft.repo,
          placeholder: '例如 deepcoldy/botmux',
          onChange: (e: { target: { value: string } }) =>
            setRuleDraft({ ...ruleDraft, repo: e.target.value }),
        }),
        repoLiveError
          ? h('div', { style: { fontSize: '12px', color: '#ef4444', marginTop: '4px' } }, repoLiveError)
          : h(
              'div',
              { style: STYLES.hint },
              '首次启用时会先记录当前已打开 PR 基线，只对新提交 / 新就绪 PR 自动拉群，避免历史 PR 风暴。',
            ),
      ),

      // Step 2: Bot Roles (Required)
      h(
        'div',
        { style: { marginBottom: '14px' } },
        h(
          'div',
          { style: STYLES.label },
          h('span', { style: STYLES.stepTag }, '2'),
          'Bot 角色选择（必填）',
        ),
        h(
          'div',
          { style: STYLES.grid2 },
          // Creator Bot (single select)
          h(
            'div',
            null,
            h('label', { style: STYLES.label }, '建群 Bot（负责创建评审群）'),
            botOptions.length > 0
              ? h(
                  'select',
                  {
                    style: STYLES.input,
                    'data-field': 'creator-bot',
                    value: ruleDraft.creatorBotAppId,
                    onChange: (e: { target: { value: string } }) =>
                      setRuleDraft(changeCreatorBot(ruleDraft, e.target.value)),
                  },
                  h('option', { value: '' }, '-- 请选择建群 Bot --'),
                  !creatorInList && ruleDraft.creatorBotAppId
                    ? h(
                        'option',
                        { value: ruleDraft.creatorBotAppId },
                        `${ruleDraft.creatorBotAppId}（当前列表未找到）`,
                      )
                    : null,
                  ...botOptions.map(b => h('option', { key: b.id, value: b.id }, b.label)),
                )
              : h('input', {
                  style: STYLES.input,
                  'data-field': 'creator-bot',
                  value: ruleDraft.creatorBotAppId,
                  placeholder: '未检测到可用 Bot，可手动输入 cli_...',
                  onChange: (e: { target: { value: string } }) =>
                    setRuleDraft(changeCreatorBot(ruleDraft, e.target.value)),
                }),
          ),

          // Reviewer Bots (multi-select checkboxes + synced Kickoff Bot dropdown)
          h(
            'div',
            null,
            h('label', { style: STYLES.label }, '评审 Bot（可多选，勾选后自动设为首审触发 Bot）'),
            botOptions.length > 0
              ? reviewerCandidates.length > 0
                ? h(
                    'div',
                    { style: STYLES.checkboxList, 'data-field': 'reviewer-bots' },
                    ...reviewerCandidates.map(b =>
                      h(
                        'label',
                        {
                          key: b.id,
                          style: {
                            display: 'flex',
                            alignItems: 'center',
                            gap: '8px',
                            cursor: 'pointer',
                          },
                        },
                        h('input', {
                          type: 'checkbox',
                          'data-reviewer-bot': b.id,
                          checked: ruleDraft.memberBotAppIds.includes(b.id),
                          onChange: (e: { target: { checked: boolean } }) =>
                            setRuleDraft(toggleReviewerBot(ruleDraft, b.id, e.target.checked)),
                        }),
                        h('span', null, b.label),
                        ruleDraft.kickoffBotAppId === b.id
                          ? h('span', { style: STYLES.badge('info') }, '首审')
                          : null,
                      ),
                    ),
                  )
                : h(
                    'div',
                    { style: STYLES.hint },
                    '当前仅检测到 1 个可用 Bot（已作为建群 Bot）；添加更多 Bot 后即可勾选评审 Bot。',
                  )
              : h('input', {
                  style: STYLES.input,
                  'data-field': 'reviewer-bots',
                  value: ruleDraft.memberBotAppIds.join(', '),
                  placeholder: '可选，多个用逗号分隔（cli_...）',
                  onChange: (e: { target: { value: string } }) => {
                    const nextMembers = splitCsv(e.target.value).filter(
                      id => id !== ruleDraft.creatorBotAppId,
                    );
                    setRuleDraft({
                      ...ruleDraft,
                      memberBotAppIds: nextMembers,
                      kickoffBotAppId:
                        ruleDraft.kickoffBotAppId || nextMembers[0] || '',
                    });
                  },
                }),

            // Kickoff Bot override selector (shown once at least one reviewer/kickoff bot is chosen)
            ruleDraft.memberBotAppIds.length > 0 || ruleDraft.kickoffBotAppId
              ? h(
                  'div',
                  { style: { marginTop: '8px' } },
                  h(
                    'label',
                    { style: { ...STYLES.label, fontSize: '12px', opacity: 0.8 } },
                    '首审触发 Bot（建群后自动 @ 该 Bot 开始评审）',
                  ),
                  botOptions.length > 0
                    ? h(
                        'select',
                        {
                          style: STYLES.input,
                          'data-field': 'kickoff-bot',
                          value: ruleDraft.kickoffBotAppId,
                          onChange: (e: { target: { value: string } }) =>
                            setRuleDraft({ ...ruleDraft, kickoffBotAppId: e.target.value }),
                        },
                        h('option', { value: '' }, '不自动触发首审（仅拉群）'),
                        !kickoffInList && ruleDraft.kickoffBotAppId
                          ? h(
                              'option',
                              { value: ruleDraft.kickoffBotAppId },
                              `${ruleDraft.kickoffBotAppId}（当前列表未找到）`,
                            )
                          : null,
                        ...kickoffCandidates.map(b =>
                          h('option', { key: b.id, value: b.id }, b.label),
                        ),
                      )
                    : h('input', {
                        style: STYLES.input,
                        'data-field': 'kickoff-bot',
                        value: ruleDraft.kickoffBotAppId,
                        placeholder: '留空或输入与建群 Bot 不同的 cli_...',
                        onChange: (e: { target: { value: string } }) =>
                          setRuleDraft({ ...ruleDraft, kickoffBotAppId: e.target.value }),
                      }),
                )
              : null,
          ),
        ),
      ),

      // Collapsed: Advanced filter & template settings
      h(
        'div',
        { style: { marginTop: '10px' } },
        h(
          'button',
          {
            type: 'button',
            style: STYLES.collapseBtn,
            'aria-expanded': showRuleAdvanced,
            'data-toggle': 'rule-advanced',
            onClick: () => setShowRuleAdvanced(v => !v),
          },
          h(
            'span',
            { style: STYLES.row },
            h('span', null, `${showRuleAdvanced ? '▾' : '▸'} 高级过滤与模板设置`),
            customizedAdvancedCount > 0
              ? h(
                  'span',
                  { style: STYLES.badge('warn'), 'data-badge': 'rule-customized-count' },
                  `已自定义 ${customizedAdvancedCount} 项`,
                )
              : null,
          ),
          h(
            'span',
            { style: { fontSize: '12px', fontWeight: 400, opacity: 0.7 } },
            '分支过滤 / 触发时机 / 黑白名单 / 群名与提示词模板 / 通知行为',
          ),
        ),
        showRuleAdvanced
          ? h(
              'div',
              {
                style: {
                  marginTop: '10px',
                  padding: '12px',
                  borderRadius: '8px',
                  border: '1px solid rgba(128,128,128,0.18)',
                },
                'data-panel': 'rule-advanced',
              },
              h(
                'div',
                { style: STYLES.grid2 },
                h(
                  'div',
                  null,
                  h('label', { style: STYLES.label }, '目标分支（留空 = 所有分支）'),
                  h('input', {
                    style: STYLES.input,
                    'data-field': 'base-branches',
                    value: ruleDraft.baseBranchesText,
                    placeholder: '如 main, release（留空表示所有分支）',
                    onChange: (e: { target: { value: string } }) =>
                      setRuleDraft({ ...ruleDraft, baseBranchesText: e.target.value }),
                  }),
                ),
                h(
                  'div',
                  null,
                  h('label', { style: STYLES.label }, '会话模式'),
                  h(
                    'select',
                    {
                      style: STYLES.input,
                      'data-field': 'chat-mode',
                      value: ruleDraft.chatMode,
                      onChange: (e: { target: { value: string } }) =>
                        setRuleDraft({ ...ruleDraft, chatMode: e.target.value as ChatMode }),
                    },
                    h('option', { value: 'group' }, '普通群聊 (group)'),
                    h('option', { value: 'topic' }, '话题群 (topic)'),
                  ),
                ),
                h(
                  'div',
                  null,
                  h('label', { style: STYLES.label }, '作者白名单（逗号分隔）'),
                  h('input', {
                    style: STYLES.input,
                    'data-field': 'author-allowlist',
                    value: ruleDraft.authorAllowlistText,
                    placeholder: '留空不限制',
                    onChange: (e: { target: { value: string } }) =>
                      setRuleDraft({ ...ruleDraft, authorAllowlistText: e.target.value }),
                  }),
                ),
                h(
                  'div',
                  null,
                  h('label', { style: STYLES.label }, '作者黑名单（逗号分隔）'),
                  h('input', {
                    style: STYLES.input,
                    'data-field': 'author-denylist',
                    value: ruleDraft.authorDenylistText,
                    placeholder: '例如 dependabot[bot]',
                    onChange: (e: { target: { value: string } }) =>
                      setRuleDraft({ ...ruleDraft, authorDenylistText: e.target.value }),
                  }),
                ),
                h(
                  'div',
                  null,
                  h('label', { style: STYLES.label }, '标签白名单（逗号分隔）'),
                  h('input', {
                    style: STYLES.input,
                    'data-field': 'label-allowlist',
                    value: ruleDraft.labelAllowlistText,
                    placeholder: '留空不限制',
                    onChange: (e: { target: { value: string } }) =>
                      setRuleDraft({ ...ruleDraft, labelAllowlistText: e.target.value }),
                  }),
                ),
                h(
                  'div',
                  null,
                  h('label', { style: STYLES.label }, '标签黑名单（逗号分隔）'),
                  h('input', {
                    style: STYLES.input,
                    'data-field': 'label-denylist',
                    value: ruleDraft.labelDenylistText,
                    placeholder: '例如 wip',
                    onChange: (e: { target: { value: string } }) =>
                      setRuleDraft({ ...ruleDraft, labelDenylistText: e.target.value }),
                  }),
                ),
                h(
                  'div',
                  null,
                  h('label', { style: STYLES.label }, '绑定工作目录（可选绝对路径）'),
                  h('input', {
                    style: STYLES.input,
                    'data-field': 'bind-working-dir',
                    value: ruleDraft.bindWorkingDir,
                    placeholder: '例如 /workspace/my-repo',
                    onChange: (e: { target: { value: string } }) =>
                      setRuleDraft({ ...ruleDraft, bindWorkingDir: e.target.value }),
                  }),
                ),
                h(
                  'div',
                  null,
                  h('label', { style: STYLES.label }, '自定义轮询间隔（秒，留空使用全局默认）'),
                  h('input', {
                    style: STYLES.input,
                    type: 'number',
                    'data-field': 'rule-poll-interval',
                    value: ruleDraft.pollIntervalSecText,
                    placeholder: `默认跟随全局（${pollIntervalSec}s）`,
                    onChange: (e: { target: { value: string } }) =>
                      setRuleDraft({ ...ruleDraft, pollIntervalSecText: e.target.value }),
                  }),
                ),
              ),
              h(
                'div',
                { style: { marginTop: '10px' } },
                h('label', { style: STYLES.label }, '群名模板'),
                h('input', {
                  style: STYLES.input,
                  'data-field': 'group-name-template',
                  value: ruleDraft.groupNameTemplate,
                  placeholder: PRESET_GROUP_NAME_TEMPLATE,
                  onChange: (e: { target: { value: string } }) =>
                    setRuleDraft({ ...ruleDraft, groupNameTemplate: e.target.value }),
                }),
                h(
                  'div',
                  { style: STYLES.hint },
                  '支持变量：{{prNumber}}、{{title}}、{{repo}}、{{author}}',
                ),
              ),
              h(
                'div',
                { style: { marginTop: '10px' } },
                h(
                  'label',
                  { style: STYLES.label },
                  '首审提示词模板（PR 元数据会自动隔离进 <untrusted_pr_metadata> 防注入）',
                ),
                h('textarea', {
                  style: { ...STYLES.input, minHeight: '64px' },
                  'data-field': 'kickoff-prompt-template',
                  value: ruleDraft.kickoffPromptTemplate,
                  onChange: (e: { target: { value: string } }) =>
                    setRuleDraft({ ...ruleDraft, kickoffPromptTemplate: e.target.value }),
                }),
              ),
              h(
                'div',
                { style: { ...STYLES.row, marginTop: '12px', fontSize: '12.5px', gap: '14px' } },
                h(
                  'label',
                  { style: { display: 'inline-flex', alignItems: 'center', gap: '5px' } },
                  h('input', {
                    type: 'checkbox',
                    checked: ruleDraft.triggerOpened,
                    onChange: (e: { target: { checked: boolean } }) =>
                      setRuleDraft({ ...ruleDraft, triggerOpened: e.target.checked }),
                  }),
                  '触发：新开 PR (opened)',
                ),
                h(
                  'label',
                  { style: { display: 'inline-flex', alignItems: 'center', gap: '5px' } },
                  h('input', {
                    type: 'checkbox',
                    checked: ruleDraft.triggerReady,
                    onChange: (e: { target: { checked: boolean } }) =>
                      setRuleDraft({ ...ruleDraft, triggerReady: e.target.checked }),
                  }),
                  '触发：转为就绪 (ready_for_review)',
                ),
                h(
                  'label',
                  { style: { display: 'inline-flex', alignItems: 'center', gap: '5px' } },
                  h('input', {
                    type: 'checkbox',
                    checked: ruleDraft.ignoreDrafts,
                    onChange: (e: { target: { checked: boolean } }) =>
                      setRuleDraft({ ...ruleDraft, ignoreDrafts: e.target.checked }),
                  }),
                  '忽略 Draft PR',
                ),
                h(
                  'label',
                  { style: { display: 'inline-flex', alignItems: 'center', gap: '5px' } },
                  h('input', {
                    type: 'checkbox',
                    checked: ruleDraft.setTopNotice,
                    onChange: (e: { target: { checked: boolean } }) =>
                      setRuleDraft({ ...ruleDraft, setTopNotice: e.target.checked }),
                  }),
                  '群置顶公告',
                ),
                h(
                  'label',
                  { style: { display: 'inline-flex', alignItems: 'center', gap: '5px' } },
                  h('input', {
                    type: 'checkbox',
                    checked: ruleDraft.postShareLinkToPr,
                    onChange: (e: { target: { checked: boolean } }) =>
                      setRuleDraft({ ...ruleDraft, postShareLinkToPr: e.target.checked }),
                  }),
                  'PR 留加群链接',
                ),
                h(
                  'label',
                  { style: { display: 'inline-flex', alignItems: 'center', gap: '5px' } },
                  h('input', {
                    type: 'checkbox',
                    checked: ruleDraft.onNewCommit,
                    onChange: (e: { target: { checked: boolean } }) =>
                      setRuleDraft({ ...ruleDraft, onNewCommit: e.target.checked }),
                  }),
                  '新提交通知群内',
                ),
                h(
                  'label',
                  { style: { display: 'inline-flex', alignItems: 'center', gap: '5px' } },
                  h('input', {
                    type: 'checkbox',
                    checked: ruleDraft.onPrClosed,
                    onChange: (e: { target: { checked: boolean } }) =>
                      setRuleDraft({ ...ruleDraft, onPrClosed: e.target.checked }),
                  }),
                  'PR 关闭/合并通知群内',
                ),
              ),
            )
          : null,
      ),

      h(
        'div',
        { style: { ...STYLES.row, marginTop: '14px' } },
        h(
          'button',
          {
            style: STYLES.btnPrimary,
            disabled: busy,
            'data-action': 'save-rule',
            onClick: () => void handleSaveRuleDraft(),
          },
          '保存规则',
        ),
        h(
          'button',
          {
            style: STYLES.btn,
            onClick: () => {
              setRuleDraft(null);
              setEditingIndex(null);
              setShowRuleAdvanced(false);
            },
          },
          '取消',
        ),
      ),
    );
  };

  return h(
    'div',
    { style: STYLES.page, 'data-page': 'github-plugin-dashboard' },

    // 1. Top Overview Card
    h(
      'div',
      { style: STYLES.card, 'data-section': 'overview' },
      h(
        'div',
        { style: STYLES.between },
        h(
          'div',
          null,
          h('h2', { style: { margin: '0 0 4px', fontSize: '19px' } }, 'GitHub PR 自动评审'),
          h(
            'div',
            { style: { ...STYLES.row, fontSize: '12.5px', opacity: 0.85 } },
            h(
              'span',
              { style: STYLES.badge(svc?.online ? 'ok' : 'muted') },
              svc?.online ? '服务运行中' : '服务未启动',
            ),
            h('span', { style: STYLES.badge(modeBadgeTone) }, modeLabel),
            svc?.portRestartRequired
              ? h('span', { style: STYLES.badge('warn') }, '端口变更待重启')
              : null,
          ),
        ),
        h(
          'div',
          { style: STYLES.row },
          h(
            'button',
            { style: STYLES.btn, disabled: busy || loading, onClick: () => void refresh() },
            '刷新',
          ),
          h(
            'button',
            {
              style: STYLES.btnPrimary,
              disabled: busy,
              'data-action': 'sync-now',
              onClick: () => void handleSyncNow(false),
            },
            '立即同步一次',
          ),
          api.startService && !svc?.online
            ? h(
                'button',
                { style: STYLES.btn, disabled: busy, onClick: () => void handleServiceLifecycle('start') },
                '启动服务',
              )
            : null,
          api.restartService && svc?.online
            ? h(
                'button',
                { style: STYLES.btn, disabled: busy, onClick: () => void handleServiceLifecycle('restart') },
                '重启',
              )
            : null,
          api.stopService && svc?.online
            ? h(
                'button',
                { style: STYLES.btn, disabled: busy, onClick: () => void handleServiceLifecycle('stop') },
                '停止',
              )
            : null,
        ),
      ),

      // 4 crisp KPI summary tiles
      h(
        'div',
        { style: STYLES.kpiGrid },
        h(
          'div',
          { style: STYLES.kpiTile },
          h('div', { style: STYLES.kpiLabel }, '运行状态'),
          h(
            'div',
            { style: STYLES.kpiValue },
            serviceMode === 'active'
              ? '监控中'
              : serviceMode === 'paused'
                ? '限流退避中'
                : '休眠等待首条规则',
          ),
        ),
        h(
          'div',
          { style: STYLES.kpiTile },
          h('div', { style: STYLES.kpiLabel }, '已启用规则'),
          h('div', { style: STYLES.kpiValue }, `${enabledRulesCount} / ${rules.length}`),
        ),
        h(
          'div',
          { style: STYLES.kpiTile },
          h('div', { style: STYLES.kpiLabel }, '最近一次同步'),
          h('div', { style: STYLES.kpiValue }, formatDisplayTime(latestSyncAt)),
        ),
        h(
          'div',
          { style: STYLES.kpiTile },
          h('div', { style: STYLES.kpiLabel }, 'API 额度余量'),
          h(
            'div',
            { style: { ...STYLES.kpiValue, display: 'flex', alignItems: 'center', gap: '6px' } },
            coreQuota
              ? [
                  h('span', { key: 'val' }, `${coreQuota.remaining} / ${coreQuota.limit}`),
                  h(
                    'span',
                    { key: 'badge', style: STYLES.badge(coreQuota.low ? 'warn' : 'ok') },
                    coreQuota.low ? '偏低' : '充裕',
                  ),
                ]
              : '待首次请求',
          ),
        ),
      ),
    ),

    // Feedback notice banner
    notice
      ? h(
          'div',
          {
            style: {
              ...STYLES.card,
              borderColor:
                notice.kind === 'ok' ? 'rgba(22,163,74,0.45)' : 'rgba(220,38,38,0.45)',
              background:
                notice.kind === 'ok' ? 'rgba(22,163,74,0.08)' : 'rgba(220,38,38,0.08)',
              padding: '10px 14px',
              fontSize: '13px',
            },
            'data-notice': notice.kind,
          },
          notice.text,
        )
      : null,

    // 2. Auth Status Card (Zero-config by default, PAT / GitHub App / GHES collapsed)
    h(
      'div',
      { style: STYLES.card, 'data-section': 'auth' },
      h(
        'div',
        { style: { ...STYLES.between, marginBottom: '10px' } },
        h('h3', { style: { margin: 0, fontSize: '15px' } }, '1. GitHub 账号与鉴权'),
        h('span', { style: { fontSize: '12px', opacity: 0.7 } }, '默认免配 · 密钥只写不回显'),
      ),
      renderAuthStatusCard(),
      h(
        'div',
        { style: { marginTop: '10px' } },
        h(
          'button',
          {
            type: 'button',
            style: STYLES.collapseBtn,
            'aria-expanded': showAuthSwitch,
            'data-toggle': 'auth-switch',
            onClick: () => setShowAuthSwitch(v => !v),
          },
          h('span', null, `${showAuthSwitch ? '▾' : '▸'} 切换其他鉴权方式`),
          h(
            'span',
            { style: { fontSize: '12px', fontWeight: 400, opacity: 0.7 } },
            'PAT / GitHub App / 自定义 GHES API 地址',
          ),
        ),
        showAuthSwitch
          ? h(
              'div',
              { style: STYLES.subCard, 'data-panel': 'auth-switch' },
              h(
                'div',
                { style: STYLES.grid2 },
                h(
                  'div',
                  null,
                  h('label', { style: STYLES.label }, '鉴权方式'),
                  h(
                    'select',
                    {
                      style: STYLES.input,
                      'data-field': 'auth-mode',
                      value: authMode,
                      onChange: (e: { target: { value: string } }) =>
                        setAuthMode(e.target.value as GitHubAuthMode),
                    },
                    h('option', { value: 'gh_cli' }, '本机 gh CLI 登录态（默认免配推荐）'),
                    h('option', { value: 'pat' }, 'Personal Access Token (Fine-grained / Classic)'),
                    h('option', { value: 'github_app' }, 'GitHub App Installation Token'),
                    h('option', { value: 'auto' }, '自动选择（GitHub App → PAT → gh CLI）'),
                  ),
                ),
                h(
                  'div',
                  null,
                  h('label', { style: STYLES.label }, 'GitHub API 地址（支持自建 GHES）'),
                  h('input', {
                    style: STYLES.input,
                    'data-field': 'api-base-url',
                    value: apiBaseUrl,
                    placeholder: DEFAULT_GITHUB_API_BASE_URL,
                    onChange: (e: { target: { value: string } }) => setApiBaseUrl(e.target.value),
                  }),
                ),
              ),

              // gh CLI hostname field (shown for gh_cli or auto)
              authMode === 'gh_cli' || authMode === 'auto'
                ? h(
                    'div',
                    { style: { marginTop: '10px' } },
                    h('label', { style: STYLES.label }, 'gh CLI Hostname（可选，默认 github.com）'),
                    h('input', {
                      style: STYLES.input,
                      'data-field': 'gh-hostname',
                      value: ghHostname,
                      placeholder: 'github.com',
                      onChange: (e: { target: { value: string } }) => setGhHostname(e.target.value),
                    }),
                  )
                : null,

              // PAT field (shown for pat or auto)
              authMode === 'pat' || authMode === 'auto'
                ? h(
                    'div',
                    { style: { marginTop: '10px' } },
                    h(
                      'label',
                      { style: STYLES.label },
                      'Personal Access Token（只写不回显） ',
                      cfg?.github.hasPat
                        ? h('span', { style: STYLES.badge('ok') }, '已配置')
                        : null,
                    ),
                    h('input', {
                      style: STYLES.input,
                      type: 'password',
                      autoComplete: 'new-password',
                      'data-field': 'pat',
                      value: patInput,
                      placeholder: cfg?.github.hasPat
                        ? '已保存，留空保持不变'
                        : 'github_pat_... 或 ghp_...',
                      onChange: (e: { target: { value: string } }) => {
                        setPatInput(e.target.value);
                        if (e.target.value) setClearPat(false);
                      },
                    }),
                    cfg?.github.hasPat
                      ? h(
                          'label',
                          {
                            style: {
                              fontSize: '12px',
                              display: 'inline-flex',
                              gap: '6px',
                              marginTop: '4px',
                            },
                          },
                          h('input', {
                            type: 'checkbox',
                            checked: clearPat,
                            onChange: (e: { target: { checked: boolean } }) =>
                              setClearPat(e.target.checked),
                          }),
                          '清除已保存的 PAT',
                        )
                      : null,
                  )
                : null,

              // GitHub App fields (shown for github_app or auto)
              authMode === 'github_app' || authMode === 'auto'
                ? h(
                    'div',
                    { style: { marginTop: '10px' } },
                    h(
                      'div',
                      { style: STYLES.grid2 },
                      h(
                        'div',
                        null,
                        h('label', { style: STYLES.label }, 'GitHub App ID'),
                        h('input', {
                          style: STYLES.input,
                          'data-field': 'app-id',
                          value: appId,
                          placeholder: '例如 123456',
                          onChange: (e: { target: { value: string } }) => setAppId(e.target.value),
                        }),
                      ),
                      h(
                        'div',
                        null,
                        h('label', { style: STYLES.label }, 'Installation ID'),
                        h('input', {
                          style: STYLES.input,
                          'data-field': 'installation-id',
                          value: installationId,
                          placeholder: '例如 98765432',
                          onChange: (e: { target: { value: string } }) =>
                            setInstallationId(e.target.value),
                        }),
                      ),
                    ),
                    h(
                      'div',
                      { style: { marginTop: '10px' } },
                      h(
                        'label',
                        { style: STYLES.label },
                        'GitHub App 私钥 PEM（只写不回显） ',
                        cfg?.github.app.hasPrivateKey
                          ? h('span', { style: STYLES.badge('ok') }, '已配置')
                          : null,
                      ),
                      h('textarea', {
                        style: { ...STYLES.input, minHeight: '64px', fontFamily: 'monospace' },
                        'data-field': 'private-key',
                        value: privateKeyInput,
                        placeholder: cfg?.github.app.hasPrivateKey
                          ? '已保存 RSA 私钥，留空保持不变'
                          : '-----BEGIN PRIVATE KEY-----',
                        onChange: (e: { target: { value: string } }) => {
                          setPrivateKeyInput(e.target.value);
                          if (e.target.value) setClearPrivateKey(false);
                        },
                      }),
                      cfg?.github.app.hasPrivateKey
                        ? h(
                            'label',
                            {
                              style: {
                                fontSize: '12px',
                                display: 'inline-flex',
                                gap: '6px',
                                marginTop: '4px',
                              },
                            },
                            h('input', {
                              type: 'checkbox',
                              checked: clearPrivateKey,
                              onChange: (e: { target: { checked: boolean } }) =>
                                setClearPrivateKey(e.target.checked),
                            }),
                            '清除已保存的私钥',
                          )
                        : null,
                    ),
                  )
                : null,

              h(
                'div',
                { style: { ...STYLES.row, marginTop: '12px' } },
                h(
                  'button',
                  {
                    style: STYLES.btnPrimary,
                    disabled: busy,
                    'data-action': 'save-auth',
                    onClick: () => void handleSaveAuthSettings(),
                  },
                  '保存鉴权设置',
                ),
                h(
                  'button',
                  {
                    style: STYLES.btn,
                    onClick: () => setShowAuthSwitch(false),
                  },
                  '收起',
                ),
              ),
            )
          : null,
      ),
    ),

    // 3. Repository Watch Rules Card (Preset + 2 Required Fields)
    h(
      'div',
      { style: STYLES.card, 'data-section': 'repos' },
      h(
        'div',
        { style: { ...STYLES.between, marginBottom: '12px' } },
        h(
          'div',
          null,
          h('h3', { style: { margin: 0, fontSize: '15px' } }, `2. 仓库监控规则 (${rules.length})`),
          h(
            'div',
            { style: { fontSize: '12px', opacity: 0.72 } },
            '填写仓库名并选择 Bot 即可完成配置，其余过滤与模板项均已预设默认值',
          ),
        ),
        h(
          'button',
          {
            style: STYLES.btnPrimary,
            disabled: busy || loading,
            'data-action': 'add-rule',
            onClick: handleOpenNewRule,
          },
          '+ 添加监控仓库',
        ),
      ),

      rules.length === 0
        ? h(
            'div',
            {
              style: {
                padding: '16px 12px',
                borderRadius: '8px',
                border: '1px dashed rgba(128,128,128,0.32)',
                textAlign: 'center' as const,
                fontSize: '13px',
                opacity: 0.85,
              },
            },
            '尚未添加监控仓库。点击右上角「+ 添加监控仓库」，2 步即可开启新 PR 自动拉群评审。',
          )
        : h(
            'table',
            { style: STYLES.table },
            h(
              'thead',
              null,
              h(
                'tr',
                null,
                h('th', { style: STYLES.th }, '仓库'),
                h('th', { style: STYLES.th }, '状态'),
                h('th', { style: STYLES.th }, 'Bot 角色'),
                h('th', { style: STYLES.th }, '轮询状态'),
                h('th', { style: STYLES.th }, '操作'),
              ),
            ),
            h(
              'tbody',
              null,
              ...rules.map((r, idx) => {
                const rs = envelope?.repos?.[r.repo.toLowerCase()];
                const customCnt = countCustomizedAdvancedFields(ruleToDraft(r));
                const creatorName = resolveBotDisplayName(r.creatorBotAppId, botOptions);
                const reviewerNames = r.memberBotAppIds.map(id =>
                  resolveBotDisplayName(id, botOptions),
                );
                const kickoffName = r.kickoffBotAppId
                  ? resolveBotDisplayName(r.kickoffBotAppId, botOptions)
                  : null;

                return h(
                  'tr',
                  { key: r.id || r.repo },
                  h(
                    'td',
                    { style: STYLES.td },
                    h('div', { style: { fontWeight: 600 } }, r.repo),
                    customCnt > 0
                      ? h(
                          'span',
                          { style: { ...STYLES.badge('muted'), marginTop: '3px' } },
                          `已自定义 ${customCnt} 项`,
                        )
                      : null,
                  ),
                  h(
                    'td',
                    { style: STYLES.td },
                    h(
                      'span',
                      { style: STYLES.badge(r.enabled ? 'ok' : 'muted') },
                      r.enabled ? '已启用' : '已停用',
                    ),
                  ),
                  h(
                    'td',
                    { style: STYLES.td },
                    h('div', null, `建群：${creatorName}`),
                    reviewerNames.length > 0
                      ? h('div', { style: { opacity: 0.85 } }, `评审：${reviewerNames.join('、')}`)
                      : null,
                    kickoffName
                      ? h('div', { style: { opacity: 0.78, fontSize: '12px' } }, `首审触发：${kickoffName}`)
                      : null,
                  ),
                  h(
                    'td',
                    { style: STYLES.td },
                    rs?.lastPollStatus === 'error' || rs?.lastPollStatus === 'rate_limited'
                      ? h(
                          'div',
                          null,
                          h(
                            'span',
                            {
                              style: STYLES.badge(
                                rs.lastPollStatus === 'error' ? 'err' : 'warn',
                              ),
                            },
                            rs.lastPollStatus === 'error' ? '轮询异常' : '限流等待',
                          ),
                          rs.lastError
                            ? h(
                                'div',
                                { style: { fontSize: '11.5px', opacity: 0.82, marginTop: '2px' } },
                                rs.lastError,
                              )
                            : null,
                        )
                      : rs?.baselineCapturedAt
                        ? `已就绪（追踪 ${Object.keys(rs.knownPrs ?? {}).length} 个 PR）`
                        : '待建立基线',
                  ),
                  h(
                    'td',
                    { style: STYLES.td },
                    h(
                      'div',
                      { style: STYLES.row },
                      h(
                        'button',
                        { style: STYLES.btn, disabled: busy, onClick: () => void handleToggleRule(idx) },
                        r.enabled ? '停用' : '启用',
                      ),
                      h(
                        'button',
                        {
                          style: STYLES.btn,
                          disabled: busy,
                          'data-action': `edit-rule-${idx}`,
                          onClick: () => handleOpenEditRule(idx, r),
                        },
                        '编辑',
                      ),
                      h(
                        'button',
                        {
                          style: STYLES.btnDanger,
                          disabled: busy,
                          onClick: () => void handleDeleteRule(idx),
                        },
                        '删除',
                      ),
                    ),
                  ),
                );
              }),
            ),
          ),

      renderRuleEditor(),
    ),

    // 4. Global Advanced Settings (Collapsed by default with 1-line summary)
    h(
      'div',
      { style: STYLES.card, 'data-section': 'global-advanced' },
      h(
        'button',
        {
          type: 'button',
          style: STYLES.collapseBtn,
          'aria-expanded': showGlobalAdvanced,
          'data-toggle': 'global-advanced',
          onClick: () => setShowGlobalAdvanced(v => !v),
        },
        h(
          'span',
          null,
          `${showGlobalAdvanced ? '▾' : '▸'} 高级设置（代理 / Webhook / 轮询与限流）`,
        ),
        !showGlobalAdvanced
          ? h(
              'span',
              {
                style: { fontSize: '12px', fontWeight: 400, opacity: 0.78 },
                'data-summary': 'global-advanced',
              },
              globalAdvancedSummary,
            )
          : null,
      ),
      showGlobalAdvanced
        ? h(
            'div',
            { style: STYLES.subCard, 'data-panel': 'global-advanced' },
            h(
              'div',
              { style: STYLES.grid2 },
              h(
                'div',
                null,
                h('label', { style: STYLES.label }, '出站代理 URL（无效配置将 fail-closed 拒绝出站）'),
                h('input', {
                  style: STYLES.input,
                  'data-field': 'proxy-url',
                  value: proxyUrl,
                  placeholder: 'http://proxy.example.com:8080（留空直连）',
                  onChange: (e: { target: { value: string } }) => setProxyUrl(e.target.value),
                }),
              ),
              h(
                'div',
                null,
                h('label', { style: STYLES.label }, '代理账号（可选）'),
                h('input', {
                  style: STYLES.input,
                  'data-field': 'proxy-username',
                  value: proxyUsername,
                  placeholder: '可选',
                  onChange: (e: { target: { value: string } }) => setProxyUsername(e.target.value),
                }),
              ),
              h(
                'div',
                null,
                h(
                  'label',
                  { style: STYLES.label },
                  '代理密码（只写不回显） ',
                  cfg?.proxy.hasPassword
                    ? h('span', { style: STYLES.badge('ok') }, '已配置')
                    : null,
                ),
                h('input', {
                  style: STYLES.input,
                  type: 'password',
                  autoComplete: 'new-password',
                  'data-field': 'proxy-password',
                  value: proxyPasswordInput,
                  placeholder: cfg?.proxy.hasPassword ? '已保存，留空保持不变' : '可选',
                  onChange: (e: { target: { value: string } }) => {
                    setProxyPasswordInput(e.target.value);
                    if (e.target.value) setClearProxyPassword(false);
                  },
                }),
                cfg?.proxy.hasPassword
                  ? h(
                      'label',
                      {
                        style: {
                          fontSize: '12px',
                          display: 'inline-flex',
                          gap: '6px',
                          marginTop: '4px',
                        },
                      },
                      h('input', {
                        type: 'checkbox',
                        checked: clearProxyPassword,
                        onChange: (e: { target: { checked: boolean } }) =>
                          setClearProxyPassword(e.target.checked),
                      }),
                      '清除已保存的代理密码',
                    )
                  : null,
              ),
              h(
                'div',
                null,
                h('label', { style: STYLES.label }, '本机回环 Webhook'),
                h(
                  'label',
                  {
                    style: {
                      fontSize: '13px',
                      display: 'inline-flex',
                      gap: '8px',
                      alignItems: 'center',
                      marginTop: '6px',
                    },
                  },
                  h('input', {
                    type: 'checkbox',
                    'data-field': 'webhook-enabled',
                    checked: webhookEnabled,
                    onChange: (e: { target: { checked: boolean } }) =>
                      setWebhookEnabled(e.target.checked),
                  }),
                  `开启 127.0.0.1:${servicePort}${webhookPath}`,
                ),
              ),
              h(
                'div',
                null,
                h('label', { style: STYLES.label }, 'Webhook 路径'),
                h('input', {
                  style: STYLES.input,
                  'data-field': 'webhook-path',
                  value: webhookPath,
                  placeholder: DEFAULT_WEBHOOK_PATH,
                  onChange: (e: { target: { value: string } }) => setWebhookPath(e.target.value),
                }),
              ),
              h(
                'div',
                null,
                h(
                  'label',
                  { style: STYLES.label },
                  'Webhook Secret（>= 32 字节，只写不回显） ',
                  cfg?.webhook.hasSecret
                    ? h('span', { style: STYLES.badge('ok') }, '已配置')
                    : null,
                ),
                h('input', {
                  style: STYLES.input,
                  type: 'password',
                  autoComplete: 'new-password',
                  'data-field': 'webhook-secret',
                  value: webhookSecretInput,
                  placeholder: cfg?.webhook.hasSecret
                    ? '已保存，留空保持不变'
                    : '至少 32 字节高熵密钥',
                  onChange: (e: { target: { value: string } }) => {
                    setWebhookSecretInput(e.target.value);
                    if (e.target.value) setClearWebhookSecret(false);
                  },
                }),
                cfg?.webhook.hasSecret
                  ? h(
                      'label',
                      {
                        style: {
                          fontSize: '12px',
                          display: 'inline-flex',
                          gap: '6px',
                          marginTop: '4px',
                        },
                      },
                      h('input', {
                        type: 'checkbox',
                        checked: clearWebhookSecret,
                        onChange: (e: { target: { checked: boolean } }) =>
                          setClearWebhookSecret(e.target.checked),
                      }),
                      '清除已保存的 Webhook Secret',
                    )
                  : null,
              ),
              h(
                'div',
                null,
                h('label', { style: STYLES.label }, '本地服务端口 (127.0.0.1)'),
                h('input', {
                  style: STYLES.input,
                  type: 'number',
                  'data-field': 'service-port',
                  value: servicePort,
                  onChange: (e: { target: { value: string } }) => setServicePort(e.target.value),
                }),
              ),
              h(
                'div',
                null,
                h('label', { style: STYLES.label }, '全局轮询间隔（秒，>= 15）'),
                h('input', {
                  style: STYLES.input,
                  type: 'number',
                  'data-field': 'poll-interval-sec',
                  value: pollIntervalSec,
                  onChange: (e: { target: { value: string } }) =>
                    setPollIntervalSec(e.target.value),
                }),
              ),
              h(
                'div',
                null,
                h('label', { style: STYLES.label }, '每仓库每小时拉群上限（1–1000）'),
                h('input', {
                  style: STYLES.input,
                  type: 'number',
                  'data-field': 'max-creates-per-hour',
                  value: maxCreatesPerHour,
                  onChange: (e: { target: { value: string } }) =>
                    setMaxCreatesPerHour(e.target.value),
                }),
              ),
            ),
            h(
              'div',
              { style: { ...STYLES.row, marginTop: '14px' } },
              h(
                'button',
                {
                  style: STYLES.btnPrimary,
                  disabled: busy,
                  'data-action': 'save-global-advanced',
                  onClick: () => void handleSaveGlobalAdvanced(),
                },
                '保存高级设置',
              ),
              h(
                'button',
                {
                  style: STYLES.btn,
                  onClick: () => setShowGlobalAdvanced(false),
                },
                '收起',
              ),
            ),
          )
        : null,
    ),

    // 5. Collapsible Diagnostics, History & Manual Backfill (<details> closed by default)
    h(
      'details',
      { style: STYLES.card, 'data-section': 'diagnostics' },
      h(
        'summary',
        {
          style: {
            cursor: 'pointer',
            fontSize: '14px',
            fontWeight: 600,
            userSelect: 'none' as const,
          },
        },
        `运行记录与诊断（已拉群 ${prGroups.length} · 最近事件 ${recentEvents.length} · 手动补建）`,
      ),
      h(
        'div',
        { style: { marginTop: '14px' } },

        // Runtime & Rate-Limit Diagnostics bar
        h(
          'div',
          { style: { ...STYLES.between, marginBottom: '14px', fontSize: '12.5px', opacity: 0.85 } },
          h(
            'div',
            { style: STYLES.row },
            h('span', null, `监听地址：127.0.0.1:${svc?.port ?? DEFAULT_SERVICE_PORT}`),
            h(
              'span',
              null,
              rl?.search
                ? `Search 额度：${rl.search.remaining}/${rl.search.limit}`
                : 'Search 额度：未使用',
            ),
            rl?.pausedUntil
              ? h('span', { style: STYLES.badge('err') }, `次级限流退避至 ${rl.pausedUntil}`)
              : h('span', { style: STYLES.badge('ok') }, '无限流退避'),
          ),
          h(
            'button',
            { style: STYLES.btn, disabled: busy, onClick: () => void handleSyncNow(true) },
            '模拟同步 (Dry-Run)',
          ),
        ),

        // Manual PR Group Backfill
        h(
          'div',
          { style: { marginBottom: '16px' } },
          h('div', { style: STYLES.label }, '手动补建历史 PR 评审群'),
          h(
            'div',
            { style: STYLES.row },
            h('input', {
              style: { ...STYLES.input, maxWidth: '340px' },
              value: openPrInput,
              placeholder: 'owner/repo#123',
              onChange: (e: { target: { value: string } }) => setOpenPrInput(e.target.value),
            }),
            h(
              'button',
              { style: STYLES.btn, disabled: busy, onClick: () => void handleOpenPr(true) },
              '预览 (Dry-Run)',
            ),
            h(
              'button',
              {
                style: STYLES.btnPrimary,
                disabled: busy,
                'data-action': 'open-pr',
                onClick: () => void handleOpenPr(false),
              },
              '补建评审群',
            ),
          ),
        ),

        // PR -> Group Mappings
        h(
          'div',
          { style: { marginBottom: '16px' } },
          h('h4', { style: { margin: '0 0 8px', fontSize: '13.5px' } }, `已拉群记录 (${prGroups.length})`),
          prGroups.length === 0
            ? h('div', { style: { fontSize: '12.5px', opacity: 0.72 } }, '暂无 PR 评审群记录。')
            : h(
                'table',
                { style: STYLES.table },
                h(
                  'thead',
                  null,
                  h(
                    'tr',
                    null,
                    h('th', { style: STYLES.th }, 'PR'),
                    h('th', { style: STYLES.th }, '状态'),
                    h('th', { style: STYLES.th }, '群 ID'),
                    h('th', { style: STYLES.th }, '首审 / 置顶'),
                    h('th', { style: STYLES.th }, 'Head SHA'),
                    h('th', { style: STYLES.th }, '更新时间'),
                  ),
                ),
                h(
                  'tbody',
                  null,
                  ...prGroups.slice(0, 30).map(g =>
                    h(
                      'tr',
                      { key: `${g.repo}#${g.prNumber}` },
                      h('td', { style: STYLES.td }, `${g.repo}#${g.prNumber}`),
                      h(
                        'td',
                        { style: STYLES.td },
                        h(
                          'span',
                          {
                            style: STYLES.badge(
                              g.status === 'active'
                                ? 'ok'
                                : g.status === 'creating'
                                  ? 'warn'
                                  : 'muted',
                            ),
                          },
                          g.status,
                        ),
                      ),
                      h(
                        'td',
                        { style: { ...STYLES.td, fontFamily: 'monospace' } },
                        g.chatId ?? '(创建中)',
                      ),
                      h(
                        'td',
                        { style: STYLES.td },
                        `首审=${g.kickoffVerified ? '已校验' : g.kickoffMessageId ? '已发送' : '无'}，置顶=${g.topNoticeSet ? '是' : '否'}`,
                      ),
                      h(
                        'td',
                        { style: { ...STYLES.td, fontFamily: 'monospace' } },
                        g.lastHeadSha.slice(0, 10),
                      ),
                      h('td', { style: STYLES.td }, g.updatedAt),
                    ),
                  ),
                ),
              ),
        ),

        // Recent Events Log
        h(
          'div',
          null,
          h(
            'h4',
            { style: { margin: '0 0 8px', fontSize: '13.5px' } },
            `最近事件日志 (${recentEvents.length})`,
          ),
          recentEvents.length === 0
            ? h('div', { style: { fontSize: '12.5px', opacity: 0.72 } }, '暂无事件日志。')
            : h(
                'div',
                {
                  style: {
                    maxHeight: '220px',
                    overflowY: 'auto' as const,
                    fontSize: '12px',
                    fontFamily: 'monospace',
                  },
                },
                ...recentEvents.slice(0, 25).map((ev, i) =>
                  h(
                    'div',
                    {
                      key: `${ev.ts}-${i}`,
                      style: { padding: '4px 0', borderBottom: '1px solid rgba(128,128,128,0.12)' },
                    },
                    `[${ev.ts}] [${ev.level.toUpperCase()}] ${ev.kind}${ev.repo ? ` (${ev.repo}${ev.prNumber ? `#${ev.prNumber}` : ''})` : ''}: ${ev.message}`,
                  ),
                ),
              ),
        ),
      ),
    ),
  );
}

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
  TriggerKind,
} from '../types.ts';
import {
  DEFAULT_GITHUB_API_BASE_URL,
  DEFAULT_GROUP_NAME_TEMPLATE,
  DEFAULT_KICKOFF_PROMPT_TEMPLATE,
  DEFAULT_POLL_INTERVAL_SEC,
  DEFAULT_SERVICE_PORT,
  DEFAULT_WEBHOOK_PATH,
} from '../types.ts';

interface BotListItem {
  id: string;
  name: string;
  plugins: string[];
}

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
  // Upcoming Botmux core service proxy methods (auto-detected when available)
  serviceFetch?: (path: string, init?: { method?: string; body?: string; headers?: Record<string, string> }) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;
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
  botStatus?: Array<{ id: string; name: string; brand: string; online: boolean; apiOnly: boolean }>;
}

interface RuleDraft {
  id: string;
  repo: string;
  enabled: boolean;
  baseBranchesText: string;
  triggerOpened: boolean;
  triggerReady: boolean;
  ignoreDrafts: boolean;
  authorAllowlistText: string;
  authorDenylistText: string;
  labelAllowlistText: string;
  labelDenylistText: string;
  creatorBotAppId: string;
  memberBotAppIds: string[];
  kickoffBotAppId: string;
  chatMode: ChatMode;
  groupNameTemplate: string;
  kickoffPromptTemplate: string;
  bindWorkingDir: string;
  setTopNotice: boolean;
  postShareLinkToPr: boolean;
  onNewCommit: boolean;
  onPrClosed: boolean;
  pollIntervalSecText: string;
}

function emptyRuleDraft(defaultBotId = ''): RuleDraft {
  return {
    id: '',
    repo: '',
    enabled: true,
    baseBranchesText: '',
    triggerOpened: true,
    triggerReady: true,
    ignoreDrafts: true,
    authorAllowlistText: '',
    authorDenylistText: '',
    labelAllowlistText: '',
    labelDenylistText: '',
    creatorBotAppId: defaultBotId,
    memberBotAppIds: [],
    kickoffBotAppId: '',
    chatMode: 'group',
    groupNameTemplate: DEFAULT_GROUP_NAME_TEMPLATE,
    kickoffPromptTemplate: DEFAULT_KICKOFF_PROMPT_TEMPLATE,
    bindWorkingDir: '',
    setTopNotice: true,
    postShareLinkToPr: false,
    onNewCommit: false,
    onPrClosed: false,
    pollIntervalSecText: '',
  };
}

function ruleToDraft(rule: RepoRule): RuleDraft {
  return {
    id: rule.id,
    repo: rule.repo,
    enabled: rule.enabled,
    baseBranchesText: rule.baseBranches.join(', '),
    triggerOpened: rule.triggerOn.includes('opened'),
    triggerReady: rule.triggerOn.includes('ready_for_review'),
    ignoreDrafts: rule.ignoreDrafts,
    authorAllowlistText: rule.authorAllowlist.join(', '),
    authorDenylistText: rule.authorDenylist.join(', '),
    labelAllowlistText: rule.labelAllowlist.join(', '),
    labelDenylistText: rule.labelDenylist.join(', '),
    creatorBotAppId: rule.creatorBotAppId,
    memberBotAppIds: [...rule.memberBotAppIds],
    kickoffBotAppId: rule.kickoffBotAppId ?? '',
    chatMode: rule.chatMode,
    groupNameTemplate: rule.groupNameTemplate,
    kickoffPromptTemplate: rule.kickoffPromptTemplate,
    bindWorkingDir: rule.bindWorkingDir ?? '',
    setTopNotice: rule.setTopNotice,
    postShareLinkToPr: rule.postShareLinkToPr,
    onNewCommit: rule.onNewCommit,
    onPrClosed: rule.onPrClosed,
    pollIntervalSecText: rule.pollIntervalSec !== undefined ? String(rule.pollIntervalSec) : '',
  };
}

function splitCsv(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map(s => s.trim())
    .filter(Boolean);
}

function draftToRule(draft: RuleDraft): RepoRule {
  const triggers: TriggerKind[] = [];
  if (draft.triggerOpened) triggers.push('opened');
  if (draft.triggerReady) triggers.push('ready_for_review');
  if (triggers.length === 0) triggers.push('opened');

  const parsedPoll = draft.pollIntervalSecText.trim()
    ? Number.parseInt(draft.pollIntervalSecText.trim(), 10)
    : undefined;

  return {
    id: draft.id || draft.repo.trim().toLowerCase(),
    repo: draft.repo.trim(),
    enabled: draft.enabled,
    baseBranches: splitCsv(draft.baseBranchesText),
    triggerOn: triggers,
    ignoreDrafts: draft.ignoreDrafts,
    authorAllowlist: splitCsv(draft.authorAllowlistText),
    authorDenylist: splitCsv(draft.authorDenylistText),
    labelAllowlist: splitCsv(draft.labelAllowlistText),
    labelDenylist: splitCsv(draft.labelDenylistText),
    creatorBotAppId: draft.creatorBotAppId.trim(),
    memberBotAppIds: draft.memberBotAppIds.filter(Boolean),
    ...(draft.kickoffBotAppId.trim() ? { kickoffBotAppId: draft.kickoffBotAppId.trim() } : {}),
    chatMode: draft.chatMode,
    groupNameTemplate: draft.groupNameTemplate.trim() || DEFAULT_GROUP_NAME_TEMPLATE,
    kickoffPromptTemplate: draft.kickoffPromptTemplate.trim() || DEFAULT_KICKOFF_PROMPT_TEMPLATE,
    ...(draft.bindWorkingDir.trim() ? { bindWorkingDir: draft.bindWorkingDir.trim() } : {}),
    setTopNotice: draft.setTopNotice,
    postShareLinkToPr: draft.postShareLinkToPr,
    onNewCommit: draft.onNewCommit,
    onPrClosed: draft.onPrClosed,
    ...(parsedPoll !== undefined && Number.isInteger(parsedPoll) ? { pollIntervalSec: parsedPoll } : {}),
  };
}

/**
 * Dual-core transport adapter:
 * - When upcoming Botmux core provides `api.serviceFetch` or `api.requestService`,
 *   live service queries/actions route directly through it.
 * - On Phase 1 current core (or if the service is offline / returns 401/404/501/503),
 *   smoothly falls back to `api.getSettings()` / `api.saveSettings(...)`.
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
      // Fall through to current-core getSettings/saveSettings bridge
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
      // Fall through to current-core getSettings/saveSettings bridge
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
    maxWidth: '1080px',
    margin: '0 auto',
    padding: '20px 16px 48px',
    fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    color: 'inherit',
    lineHeight: 1.5,
  },
  card: {
    border: '1px solid rgba(128,128,128,0.25)',
    borderRadius: '10px',
    padding: '16px',
    marginBottom: '16px',
    background: 'rgba(128,128,128,0.04)',
  },
  row: {
    display: 'flex',
    flexWrap: 'wrap' as const,
    gap: '10px',
    alignItems: 'center',
  },
  grid2: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
    gap: '12px',
  },
  label: {
    display: 'block',
    fontSize: '12px',
    fontWeight: 600,
    marginBottom: '4px',
    opacity: 0.85,
  },
  input: {
    width: '100%',
    boxSizing: 'border-box' as const,
    padding: '7px 10px',
    borderRadius: '6px',
    border: '1px solid rgba(128,128,128,0.35)',
    background: 'transparent',
    color: 'inherit',
    fontSize: '13px',
  },
  btn: {
    padding: '7px 13px',
    borderRadius: '6px',
    border: '1px solid rgba(128,128,128,0.35)',
    background: 'rgba(128,128,128,0.1)',
    color: 'inherit',
    cursor: 'pointer',
    fontSize: '13px',
    fontWeight: 500,
  },
  btnPrimary: {
    padding: '7px 14px',
    borderRadius: '6px',
    border: '1px solid #2563eb',
    background: '#2563eb',
    color: '#ffffff',
    cursor: 'pointer',
    fontSize: '13px',
    fontWeight: 600,
  },
  btnDanger: {
    padding: '6px 11px',
    borderRadius: '6px',
    border: '1px solid rgba(220,38,38,0.5)',
    background: 'rgba(220,38,38,0.1)',
    color: '#ef4444',
    cursor: 'pointer',
    fontSize: '12px',
  },
  badge: (tone: 'ok' | 'warn' | 'muted' | 'err') => ({
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: '999px',
    fontSize: '11px',
    fontWeight: 600,
    background:
      tone === 'ok'
        ? 'rgba(22,163,74,0.18)'
        : tone === 'warn'
          ? 'rgba(234,179,8,0.2)'
          : tone === 'err'
            ? 'rgba(220,38,38,0.2)'
            : 'rgba(128,128,128,0.2)',
    color:
      tone === 'ok'
        ? '#16a34a'
        : tone === 'warn'
          ? '#ca8a04'
          : tone === 'err'
            ? '#ef4444'
            : 'inherit',
  }),
  table: {
    width: '100%',
    borderCollapse: 'collapse' as const,
    fontSize: '12.5px',
  },
  th: {
    textAlign: 'left' as const,
    padding: '8px 6px',
    borderBottom: '1px solid rgba(128,128,128,0.25)',
    fontWeight: 600,
    opacity: 0.8,
  },
  td: {
    padding: '8px 6px',
    borderBottom: '1px solid rgba(128,128,128,0.15)',
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
  const [notice, setNotice] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);
  const [envelope, setEnvelope] = useState<SettingsEnvelope | null>(null);
  const [bots, setBots] = useState<BotListItem[]>([]);

  // Auth / Proxy / Webhook / Service form state (write-only secrets start blank!)
  const [authMode, setAuthMode] = useState<GitHubAuthMode>('auto');
  const [apiBaseUrl, setApiBaseUrl] = useState(DEFAULT_GITHUB_API_BASE_URL);
  const [ghHostname, setGhHostname] = useState('');
  const [patInput, setPatInput] = useState('');
  const [clearPat, setClearPat] = useState(false);
  const [appId, setAppId] = useState('');
  const [installationId, setInstallationId] = useState('');
  const [privateKeyInput, setPrivateKeyInput] = useState('');
  const [clearPrivateKey, setClearPrivateKey] = useState(false);
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

  // Rules list & editor state
  const [rules, setRules] = useState<RepoRule[]>([]);
  const [editingIndex, setEditingIndex] = useState<number | null>(null);
  const [ruleDraft, setRuleDraft] = useState<RuleDraft | null>(null);

  // Interactive test/manual actions
  const [authTestResult, setAuthTestResult] = useState<AuthTestResult | null>(null);
  const [openPrInput, setOpenPrInput] = useState('');

  const hydrateFromEnvelope = useCallback((env: SettingsEnvelope) => {
    setEnvelope(env);
    const cfg = env.config;
    if (!cfg) return;
    setAuthMode(cfg.github.mode);
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

      // Also honor Botmux supervisor service report if host reports online
      if (
        hostServiceStatus &&
        typeof hostServiceStatus === 'object' &&
        (hostServiceStatus as { status?: unknown }).status === 'online' &&
        baseEnv.service
      ) {
        baseEnv.service.online = true;
      }

      // Probe live service directly via new core api.serviceFetch / api.requestService
      // (without falling back to getSettings, so an offline service is NEVER falsely marked online!)
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
          // Offline or unavailable; keep baseEnv.service.online as reported by getSettings/supervisor
        }
      } else if (typeof api.requestService === 'function') {
        try {
          const parsed = await api.requestService({ method: 'GET', path: '/api/status' });
          if (parsed && typeof parsed === 'object') {
            live = parsed as Record<string, unknown>;
          }
        } catch {
          // Offline or unavailable
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
    } catch (err) {
      setNotice({ kind: 'err', text: `Failed to load GitHub plugin settings: ${String(err)}` });
    } finally {
      setLoading(false);
    }
  }, [api, hydrateFromEnvelope]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const botOptions = useMemo(() => {
    const statusById = new Map((envelope?.botStatus ?? []).map(b => [b.id, b]));
    const merged: Array<{ id: string; label: string; apiOnly: boolean }> = [];
    const seen = new Set<string>();
    for (const b of bots) {
      seen.add(b.id);
      const st = statusById.get(b.id);
      merged.push({
        id: b.id,
        label: `${b.name || b.id} (${b.id})${st ? ` [${st.brand}${st.online ? ', online' : ', offline'}]` : ''}`,
        apiOnly: st?.apiOnly === true,
      });
    }
    for (const st of envelope?.botStatus ?? []) {
      if (seen.has(st.id)) continue;
      merged.push({
        id: st.id,
        label: `${st.name} (${st.id}) [${st.brand}${st.online ? ', online' : ', offline'}]`,
        apiOnly: st.apiOnly,
      });
    }
    return merged.filter(b => !b.apiOnly);
  }, [bots, envelope]);

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
          setNotice({ kind: 'err', text: res.error || 'Failed to save configuration' });
          return false;
        }
        setNotice({
          kind: 'ok',
          text: res?.portRestartRequired
            ? `${successText} (Restart service to apply new port.)`
            : successText,
        });
        await refresh();
        return true;
      } catch (err) {
        setNotice({ kind: 'err', text: `Save failed: ${String(err)}` });
        return false;
      } finally {
        setBusy(false);
      }
    },
    [api, refresh],
  );

  const handleSaveGlobalSettings = useCallback(async () => {
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
        port: Number(servicePort) || DEFAULT_SERVICE_PORT,
        pollIntervalSec: Number(pollIntervalSec) || DEFAULT_POLL_INTERVAL_SEC,
      },
    };
    await persistPatch(patch, 'Saved GitHub plugin configuration.');
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
    persistPatch,
  ]);

  const handleSaveRuleDraft = useCallback(async () => {
    if (!ruleDraft) return;
    const rule = draftToRule(ruleDraft);
    if (!rule.repo.includes('/')) {
      setNotice({ kind: 'err', text: 'Repository must be in owner/repo format.' });
      return;
    }
    if (rule.kickoffBotAppId && rule.kickoffBotAppId === rule.creatorBotAppId) {
      setNotice({ kind: 'err', text: 'kickoffBotAppId must be different from creatorBotAppId.' });
      return;
    }
    const nextRules = [...rules];
    if (editingIndex === null || editingIndex < 0 || editingIndex >= nextRules.length) {
      nextRules.push(rule);
    } else {
      nextRules[editingIndex] = rule;
    }
    const ok = await persistPatch({ repos: nextRules }, `Saved repository rule for ${rule.repo}.`);
    if (ok) {
      setRuleDraft(null);
      setEditingIndex(null);
    }
  }, [ruleDraft, rules, editingIndex, persistPatch]);

  const handleDeleteRule = useCallback(
    async (index: number) => {
      const target = rules[index];
      if (!target) return;
      const nextRules = rules.filter((_, i) => i !== index);
      await persistPatch({ repos: nextRules }, `Removed repository rule for ${target.repo}.`);
    },
    [rules, persistPatch],
  );

  const handleToggleRule = useCallback(
    async (index: number) => {
      const nextRules = rules.map((r, i) => (i === index ? { ...r, enabled: !r.enabled } : r));
      await persistPatch({ repos: nextRules }, 'Updated repository rule status.');
    },
    [rules, persistPatch],
  );

  const handleTestAuth = useCallback(async () => {
    setBusy(true);
    setNotice(null);
    try {
      const res = (await callServiceOrSettingsAction(api, {
        servicePath: '/api/test-auth',
        serviceMethod: 'POST',
        serviceBody: {},
        settingsAction: 'testAuth',
      })) as unknown as AuthTestResult;
      setAuthTestResult(res);
      setNotice({
        kind: res.ok ? 'ok' : 'err',
        text: res.ok
          ? `Auth OK (${res.resolvedMethod ?? res.authMode}): ${res.identity ?? 'authenticated'}`
          : `Auth test failed: ${res.error ?? 'unknown error'}`,
      });
    } catch (err) {
      setNotice({ kind: 'err', text: `Auth test failed: ${String(err)}` });
    } finally {
      setBusy(false);
    }
  }, [api]);

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
          setNotice({ kind: 'err', text: String(res.error ?? 'Sync failed') });
        } else if (res.accepted) {
          setNotice({ kind: 'ok', text: 'Sync scheduled in background service.' });
          setTimeout(() => void refresh(), 1200);
        } else {
          const count = Array.isArray(res.actions) ? res.actions.length : 0;
          setNotice({
            kind: 'ok',
            text: `Sync ${dryRun ? '(dry-run) ' : ''}complete (${count} action(s)).`,
          });
          await refresh();
        }
      } catch (err) {
        setNotice({ kind: 'err', text: `Sync failed: ${String(err)}` });
      } finally {
        setBusy(false);
      }
    },
    [api, refresh],
  );

  const handleOpenPr = useCallback(
    async (dryRun: boolean) => {
      const spec = openPrInput.trim();
      const idx = spec.lastIndexOf('#');
      if (idx <= 0) {
        setNotice({ kind: 'err', text: 'Enter PR as owner/repo#123.' });
        return;
      }
      const repo = spec.slice(0, idx).trim();
      const numRaw = spec.slice(idx + 1).trim();
      if (!/^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})\/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$/.test(repo)) {
        setNotice({ kind: 'err', text: 'Repository must be in valid owner/repo format.' });
        return;
      }
      if (!/^\d+$/.test(numRaw)) {
        setNotice({ kind: 'err', text: 'PR number must be a positive integer (e.g. owner/repo#123).' });
        return;
      }
      const prNumber = Number(numRaw);
      if (!Number.isSafeInteger(prNumber) || prNumber < 1) {
        setNotice({ kind: 'err', text: 'PR number must be a positive integer.' });
        return;
      }
      setBusy(true);
      setNotice(null);
      try {
        const res = await callServiceOrSettingsAction(api, {
          servicePath: '/api/open-pr',
          serviceMethod: 'POST',
          serviceBody: { repo, prNumber, dryRun },
          settingsAction: 'openPr',
          settingsPayload: { repo, prNumber, dryRun },
        });
        if (res.ok === false) {
          setNotice({ kind: 'err', text: String(res.error ?? 'Open PR failed') });
        } else {
          setNotice({
            kind: 'ok',
            text: `${repo}#${prNumber}: ${String(res.action ?? 'ok')}${res.chatId ? ` (chatId=${String(res.chatId)})` : ''}`,
          });
          await refresh();
        }
      } catch (err) {
        setNotice({ kind: 'err', text: `Open PR failed: ${String(err)}` });
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
        setNotice({ kind: 'ok', text: `Service ${op} requested.` });
        await refresh();
      } catch (err) {
        setNotice({ kind: 'err', text: `Service ${op} failed: ${String(err)}` });
      } finally {
        setBusy(false);
      }
    },
    [api, refresh],
  );

  const cfg = envelope?.config;
  const svc = envelope?.service;
  const rl = envelope?.rateLimits;
  const prGroups = useMemo(() => {
    const entries = Object.values(envelope?.prGroups ?? {});
    return entries.sort((a, b) => Date.parse(b.updatedAt) - Date.parse(a.updatedAt));
  }, [envelope]);

  const modeTone =
    svc?.mode === 'active'
      ? 'ok'
      : svc?.mode === 'paused'
        ? 'warn'
        : 'muted';

  return h(
    'div',
    { style: STYLES.page },
    // Header & status bar
    h(
      'div',
      { style: { ...STYLES.card, display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px', alignItems: 'center' } },
      h(
        'div',
        null,
        h('h2', { style: { margin: '0 0 4px', fontSize: '20px' } }, 'GitHub PR Watcher & Auto Review Groups'),
        h(
          'div',
          { style: { ...STYLES.row, fontSize: '12.5px', opacity: 0.85 } },
          h('span', { style: STYLES.badge(svc?.online ? 'ok' : 'muted') }, svc?.online ? 'Service Online' : 'Service Offline'),
          h('span', { style: STYLES.badge(modeTone) }, `Mode: ${svc?.mode ?? 'dormant'}`),
          h('span', null, `Port: 127.0.0.1:${svc?.port ?? DEFAULT_SERVICE_PORT}`),
          svc?.mode === 'dormant'
            ? h('span', null, 'Dormant by default (0 GitHub / Feishu requests until a repo rule is enabled)')
            : null,
        ),
      ),
      h(
        'div',
        { style: STYLES.row },
        h('button', { style: STYLES.btn, disabled: busy || loading, onClick: () => void refresh() }, 'Refresh'),
        h('button', { style: STYLES.btn, disabled: busy, onClick: () => void handleTestAuth() }, 'Test Auth'),
        h('button', { style: STYLES.btn, disabled: busy, onClick: () => void handleSyncNow(true) }, 'Dry-Run Sync'),
        h('button', { style: STYLES.btnPrimary, disabled: busy, onClick: () => void handleSyncNow(false) }, 'Sync Now'),
        api.startService && !svc?.online
          ? h('button', { style: STYLES.btn, disabled: busy, onClick: () => void handleServiceLifecycle('start') }, 'Start')
          : null,
        api.restartService && svc?.online
          ? h('button', { style: STYLES.btn, disabled: busy, onClick: () => void handleServiceLifecycle('restart') }, 'Restart')
          : null,
        api.stopService && svc?.online
          ? h('button', { style: STYLES.btn, disabled: busy, onClick: () => void handleServiceLifecycle('stop') }, 'Stop')
          : null,
      ),
    ),

    notice
      ? h(
          'div',
          {
            style: {
              ...STYLES.card,
              borderColor: notice.kind === 'ok' ? 'rgba(22,163,74,0.45)' : 'rgba(220,38,38,0.45)',
              background: notice.kind === 'ok' ? 'rgba(22,163,74,0.08)' : 'rgba(220,38,38,0.08)',
              padding: '10px 14px',
              fontSize: '13px',
            },
          },
          notice.text,
        )
      : null,

    // Rate Limit & Health Summary
    h(
      'div',
      { style: STYLES.card },
      h('h3', { style: { margin: '0 0 10px', fontSize: '15px' } }, 'Polling Health & GitHub Rate Limits'),
      h(
        'div',
        { style: STYLES.grid2 },
        h(
          'div',
          null,
          h('div', { style: STYLES.label }, 'Core Quota'),
          rl?.core
            ? h(
                'div',
                { style: { fontSize: '13px' } },
                `${rl.core.remaining} / ${rl.core.limit} `,
                h('span', { style: STYLES.badge(rl.core.low ? 'warn' : 'ok') }, rl.core.low ? '<10% Low' : 'Healthy'),
                h('div', { style: { fontSize: '11.5px', opacity: 0.7 } }, `Resets: ${rl.core.resetAt}`),
              )
            : h('div', { style: { fontSize: '12.5px', opacity: 0.7 } }, 'No requests sent yet'),
        ),
        h(
          'div',
          null,
          h('div', { style: STYLES.label }, 'Search Quota'),
          rl?.search
            ? h(
                'div',
                { style: { fontSize: '13px' } },
                `${rl.search.remaining} / ${rl.search.limit} `,
                h('span', { style: STYLES.badge(rl.search.low ? 'warn' : 'ok') }, rl.search.low ? '<10% Low' : 'Healthy'),
              )
            : h('div', { style: { fontSize: '12.5px', opacity: 0.7 } }, 'Unused'),
        ),
        h(
          'div',
          null,
          h('div', { style: STYLES.label }, 'Secondary Rate-Limit Backoff'),
          rl?.pausedUntil
            ? h('span', { style: STYLES.badge('err') }, `Paused until ${rl.pausedUntil}`)
            : h('span', { style: STYLES.badge('ok') }, 'Not paused'),
        ),
      ),
      authTestResult
        ? h(
            'div',
            { style: { marginTop: '10px', fontSize: '12.5px', opacity: 0.9 } },
            `Last Auth Check: ${authTestResult.ok ? 'OK' : 'FAILED'} — ${authTestResult.identity ?? authTestResult.error ?? ''}`,
          )
        : null,
    ),

    // Auth, Proxy & Webhook Configuration (Write-only secrets!)
    h(
      'div',
      { style: STYLES.card },
      h('h3', { style: { margin: '0 0 12px', fontSize: '15px' } }, 'Authentication, Proxy & Webhook Settings'),
      h(
        'div',
        { style: STYLES.grid2 },
        h(
          'div',
          null,
          h('label', { style: STYLES.label }, 'Auth Mode'),
          h(
            'select',
            {
              style: STYLES.input,
              value: authMode,
              onChange: (e: { target: { value: string } }) => setAuthMode(e.target.value as GitHubAuthMode),
            },
            h('option', { value: 'auto' }, 'Auto (GitHub App -> PAT -> gh auth token)'),
            h('option', { value: 'pat' }, 'Fine-grained / Classic PAT'),
            h('option', { value: 'github_app' }, 'GitHub App Installation Token'),
            h('option', { value: 'gh_cli' }, 'Local gh auth token (in-memory)'),
          ),
        ),
        h(
          'div',
          null,
          h('label', { style: STYLES.label }, 'GitHub API Base URL (GHES supported)'),
          h('input', {
            style: STYLES.input,
            value: apiBaseUrl,
            placeholder: DEFAULT_GITHUB_API_BASE_URL,
            onChange: (e: { target: { value: string } }) => setApiBaseUrl(e.target.value),
          }),
        ),
        h(
          'div',
          null,
          h(
            'label',
            { style: STYLES.label },
            'Personal Access Token (write-only) ',
            cfg?.github.hasPat ? h('span', { style: STYLES.badge('ok') }, 'Configured') : null,
          ),
          h('input', {
            style: STYLES.input,
            type: 'password',
            autoComplete: 'new-password',
            value: patInput,
            placeholder: cfg?.github.hasPat ? 'Leave blank to keep stored token' : 'github_pat_... or ghp_...',
            onChange: (e: { target: { value: string } }) => {
              setPatInput(e.target.value);
              if (e.target.value) setClearPat(false);
            },
          }),
          cfg?.github.hasPat
            ? h(
                'label',
                { style: { fontSize: '12px', display: 'inline-flex', gap: '6px', marginTop: '4px' } },
                h('input', {
                  type: 'checkbox',
                  checked: clearPat,
                  onChange: (e: { target: { checked: boolean } }) => setClearPat(e.target.checked),
                }),
                'Clear stored PAT',
              )
            : null,
        ),
        h(
          'div',
          null,
          h('label', { style: STYLES.label }, 'gh CLI Hostname (optional)'),
          h('input', {
            style: STYLES.input,
            value: ghHostname,
            placeholder: 'github.com',
            onChange: (e: { target: { value: string } }) => setGhHostname(e.target.value),
          }),
        ),
        h(
          'div',
          null,
          h('label', { style: STYLES.label }, 'GitHub App ID'),
          h('input', {
            style: STYLES.input,
            value: appId,
            placeholder: '123456',
            onChange: (e: { target: { value: string } }) => setAppId(e.target.value),
          }),
        ),
        h(
          'div',
          null,
          h('label', { style: STYLES.label }, 'GitHub App Installation ID'),
          h('input', {
            style: STYLES.input,
            value: installationId,
            placeholder: '98765432',
            onChange: (e: { target: { value: string } }) => setInstallationId(e.target.value),
          }),
        ),
      ),
      h(
        'div',
        { style: { marginTop: '10px' } },
        h(
          'label',
          { style: STYLES.label },
          'GitHub App Private Key PEM (write-only) ',
          cfg?.github.app.hasPrivateKey ? h('span', { style: STYLES.badge('ok') }, 'Configured') : null,
        ),
        h('textarea', {
          style: { ...STYLES.input, minHeight: '64px', fontFamily: 'monospace' },
          value: privateKeyInput,
          placeholder: cfg?.github.app.hasPrivateKey
            ? 'Leave blank to keep stored RSA private key'
            : '-----BEGIN PRIVATE KEY-----',
          onChange: (e: { target: { value: string } }) => {
            setPrivateKeyInput(e.target.value);
            if (e.target.value) setClearPrivateKey(false);
          },
        }),
        cfg?.github.app.hasPrivateKey
          ? h(
              'label',
              { style: { fontSize: '12px', display: 'inline-flex', gap: '6px', marginTop: '4px' } },
              h('input', {
                type: 'checkbox',
                checked: clearPrivateKey,
                onChange: (e: { target: { checked: boolean } }) => setClearPrivateKey(e.target.checked),
              }),
              'Clear stored private key',
            )
          : null,
      ),
      h(
        'div',
        { style: { ...STYLES.grid2, marginTop: '12px' } },
        h(
          'div',
          null,
          h('label', { style: STYLES.label }, 'Outbound Proxy URL (fail-closed if invalid)'),
          h('input', {
            style: STYLES.input,
            value: proxyUrl,
            placeholder: 'http://proxy.example.com:8080 (blank = direct)',
            onChange: (e: { target: { value: string } }) => setProxyUrl(e.target.value),
          }),
        ),
        h(
          'div',
          null,
          h('label', { style: STYLES.label }, 'Proxy Username (optional)'),
          h('input', {
            style: STYLES.input,
            value: proxyUsername,
            placeholder: 'Optional proxy username',
            onChange: (e: { target: { value: string } }) => setProxyUsername(e.target.value),
          }),
        ),
        h(
          'div',
          null,
          h(
            'label',
            { style: STYLES.label },
            'Proxy Password (write-only) ',
            cfg?.proxy.hasPassword ? h('span', { style: STYLES.badge('ok') }, 'Configured') : null,
          ),
          h('input', {
            style: STYLES.input,
            type: 'password',
            autoComplete: 'new-password',
            value: proxyPasswordInput,
            placeholder: cfg?.proxy.hasPassword ? 'Leave blank to keep' : 'Optional',
            onChange: (e: { target: { value: string } }) => {
              setProxyPasswordInput(e.target.value);
              if (e.target.value) setClearProxyPassword(false);
            },
          }),
          cfg?.proxy.hasPassword
            ? h(
                'label',
                { style: { fontSize: '12px', display: 'inline-flex', gap: '6px', marginTop: '4px' } },
                h('input', {
                  type: 'checkbox',
                  checked: clearProxyPassword,
                  onChange: (e: { target: { checked: boolean } }) =>
                    setClearProxyPassword(e.target.checked),
                }),
                'Clear stored proxy password',
              )
            : null,
        ),
        h(
          'div',
          null,
          h('label', { style: STYLES.label }, 'Loopback Webhook'),
          h(
            'label',
            { style: { fontSize: '13px', display: 'inline-flex', gap: '8px', alignItems: 'center', marginTop: '4px' } },
            h('input', {
              type: 'checkbox',
              checked: webhookEnabled,
              onChange: (e: { target: { checked: boolean } }) => setWebhookEnabled(e.target.checked),
            }),
            `Enable 127.0.0.1:${servicePort}${webhookPath}`,
          ),
        ),
        h(
          'div',
          null,
          h(
            'label',
            { style: STYLES.label },
            'Webhook Secret (>= 32 bytes, write-only) ',
            cfg?.webhook.hasSecret ? h('span', { style: STYLES.badge('ok') }, 'Configured') : null,
          ),
          h('input', {
            style: STYLES.input,
            type: 'password',
            autoComplete: 'new-password',
            value: webhookSecretInput,
            placeholder: cfg?.webhook.hasSecret ? 'Leave blank to keep stored secret' : 'At least 32 high-entropy characters',
            onChange: (e: { target: { value: string } }) => {
              setWebhookSecretInput(e.target.value);
              if (e.target.value) setClearWebhookSecret(false);
            },
          }),
          cfg?.webhook.hasSecret
            ? h(
                'label',
                { style: { fontSize: '12px', display: 'inline-flex', gap: '6px', marginTop: '4px' } },
                h('input', {
                  type: 'checkbox',
                  checked: clearWebhookSecret,
                  onChange: (e: { target: { checked: boolean } }) => setClearWebhookSecret(e.target.checked),
                }),
                'Clear stored webhook secret',
              )
            : null,
        ),
        h(
          'div',
          null,
          h('label', { style: STYLES.label }, 'Service Port (127.0.0.1)'),
          h('input', {
            style: STYLES.input,
            type: 'number',
            value: servicePort,
            onChange: (e: { target: { value: string } }) => setServicePort(e.target.value),
          }),
        ),
        h(
          'div',
          null,
          h('label', { style: STYLES.label }, 'Default Poll Interval (seconds, >= 15)'),
          h('input', {
            style: STYLES.input,
            type: 'number',
            value: pollIntervalSec,
            onChange: (e: { target: { value: string } }) => setPollIntervalSec(e.target.value),
          }),
        ),
      ),
      h(
        'div',
        { style: { marginTop: '14px' } },
        h(
          'button',
          { style: STYLES.btnPrimary, disabled: busy, onClick: () => void handleSaveGlobalSettings() },
          'Save Settings',
        ),
      ),
    ),

    // Repository Rules CRUD
    h(
      'div',
      { style: STYLES.card },
      h(
        'div',
        { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' } },
        h('h3', { style: { margin: 0, fontSize: '15px' } }, `Repository Watch Rules (${rules.length})`),
        h(
          'button',
          {
            style: STYLES.btnPrimary,
            disabled: busy,
            onClick: () => {
              setEditingIndex(null);
              setRuleDraft(emptyRuleDraft(botOptions[0]?.id ?? ''));
            },
          },
          '+ Add Repository Rule',
        ),
      ),

      rules.length === 0
        ? h(
            'div',
            { style: { fontSize: '13px', opacity: 0.75, padding: '8px 0' } },
            'No repository rules configured. Add and enable a rule to activate PR monitoring.',
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
                h('th', { style: STYLES.th }, 'Repository'),
                h('th', { style: STYLES.th }, 'State'),
                h('th', { style: STYLES.th }, 'Bots (Creator / Kickoff)'),
                h('th', { style: STYLES.th }, 'Options'),
                h('th', { style: STYLES.th }, 'Poll Status'),
                h('th', { style: STYLES.th }, 'Actions'),
              ),
            ),
            h(
              'tbody',
              null,
              ...rules.map((r, idx) => {
                const rs = envelope?.repos?.[r.repo.toLowerCase()];
                return h(
                  'tr',
                  { key: r.id || r.repo },
                  h('td', { style: STYLES.td }, h('strong', null, r.repo)),
                  h(
                    'td',
                    { style: STYLES.td },
                    h('span', { style: STYLES.badge(r.enabled ? 'ok' : 'muted') }, r.enabled ? 'Enabled' : 'Disabled'),
                  ),
                  h(
                    'td',
                    { style: STYLES.td },
                    h('div', null, `Creator: ${r.creatorBotAppId || '(unset)'}`),
                    r.kickoffBotAppId ? h('div', null, `Kickoff: ${r.kickoffBotAppId}`) : null,
                    r.memberBotAppIds.length > 0
                      ? h('div', { style: { opacity: 0.75 } }, `Members: ${r.memberBotAppIds.length}`)
                      : null,
                  ),
                  h(
                    'td',
                    { style: STYLES.td },
                    `mode=${r.chatMode}, drafts=${r.ignoreDrafts ? 'ignore' : 'include'}, topNotice=${r.setTopNotice ? 'on' : 'off'}`,
                  ),
                  h(
                    'td',
                    { style: STYLES.td },
                    rs?.lastPollStatus === 'error' || rs?.lastPollStatus === 'rate_limited'
                      ? h(
                          'div',
                          null,
                          h('span', { style: STYLES.badge(rs.lastPollStatus === 'error' ? 'err' : 'warn') }, rs.lastPollStatus),
                          rs.lastError
                            ? h('div', { style: { fontSize: '11.5px', opacity: 0.85, marginTop: '2px' } }, rs.lastError)
                            : null,
                        )
                      : rs?.baselineCapturedAt
                        ? `${rs.lastPollStatus ?? 'ready'} (${Object.keys(rs.knownPrs ?? {}).length} PRs)`
                        : 'Baseline pending',
                  ),
                  h(
                    'td',
                    { style: STYLES.td },
                    h(
                      'div',
                      { style: STYLES.row },
                      h('button', { style: STYLES.btn, disabled: busy, onClick: () => void handleToggleRule(idx) }, r.enabled ? 'Disable' : 'Enable'),
                      h(
                        'button',
                        {
                          style: STYLES.btn,
                          disabled: busy,
                          onClick: () => {
                            setEditingIndex(idx);
                            setRuleDraft(ruleToDraft(r));
                          },
                        },
                        'Edit',
                      ),
                      h('button', { style: STYLES.btnDanger, disabled: busy, onClick: () => void handleDeleteRule(idx) }, 'Delete'),
                    ),
                  ),
                );
              }),
            ),
          ),

      // Inline rule editor
      ruleDraft
        ? h(
            'div',
            { style: { ...STYLES.card, marginTop: '14px', marginBottom: 0 } },
            h(
              'h4',
              { style: { margin: '0 0 10px', fontSize: '14px' } },
              editingIndex === null ? 'New Repository Rule' : `Edit Rule: ${ruleDraft.repo}`,
            ),
            h(
              'div',
              { style: STYLES.grid2 },
              h(
                'div',
                null,
                h('label', { style: STYLES.label }, 'Repository (owner/repo)'),
                h('input', {
                  style: STYLES.input,
                  value: ruleDraft.repo,
                  placeholder: 'owner/repository',
                  onChange: (e: { target: { value: string } }) =>
                    setRuleDraft({ ...ruleDraft, repo: e.target.value }),
                }),
              ),
              h(
                'div',
                null,
                h('label', { style: STYLES.label }, 'Creator Bot (larkAppId)'),
                botOptions.length > 0
                  ? h(
                      'select',
                      {
                        style: STYLES.input,
                        value: ruleDraft.creatorBotAppId,
                        onChange: (e: { target: { value: string } }) => {
                          const nextCreator = e.target.value;
                          setRuleDraft({
                            ...ruleDraft,
                            creatorBotAppId: nextCreator,
                            kickoffBotAppId:
                              ruleDraft.kickoffBotAppId === nextCreator
                                ? ''
                                : ruleDraft.kickoffBotAppId,
                            memberBotAppIds: ruleDraft.memberBotAppIds.filter(
                              id => id !== nextCreator,
                            ),
                          });
                        },
                      },
                      h('option', { value: '' }, '-- Select Creator Bot --'),
                      ...botOptions.map(b => h('option', { key: b.id, value: b.id }, b.label)),
                    )
                  : h('input', {
                      style: STYLES.input,
                      value: ruleDraft.creatorBotAppId,
                      placeholder: 'cli_...',
                      onChange: (e: { target: { value: string } }) => {
                        const nextCreator = e.target.value;
                        setRuleDraft({
                          ...ruleDraft,
                          creatorBotAppId: nextCreator,
                          kickoffBotAppId:
                            ruleDraft.kickoffBotAppId === nextCreator
                              ? ''
                              : ruleDraft.kickoffBotAppId,
                          memberBotAppIds: ruleDraft.memberBotAppIds.filter(
                            id => id !== nextCreator,
                          ),
                        });
                      },
                    }),
              ),
              h(
                'div',
                null,
                h('label', { style: STYLES.label }, 'Kickoff Bot (optional, must != Creator)'),
                botOptions.length > 0
                  ? h(
                      'select',
                      {
                        style: STYLES.input,
                        value: ruleDraft.kickoffBotAppId,
                        onChange: (e: { target: { value: string } }) =>
                          setRuleDraft({ ...ruleDraft, kickoffBotAppId: e.target.value }),
                      },
                      h('option', { value: '' }, '-- None --'),
                      ...botOptions
                        .filter(b => b.id !== ruleDraft.creatorBotAppId)
                        .map(b => h('option', { key: b.id, value: b.id }, b.label)),
                    )
                  : h('input', {
                      style: STYLES.input,
                      value: ruleDraft.kickoffBotAppId,
                      placeholder: 'cli_... (different from creator)',
                      onChange: (e: { target: { value: string } }) =>
                        setRuleDraft({ ...ruleDraft, kickoffBotAppId: e.target.value }),
                    }),
              ),
              h(
                'div',
                null,
                h('label', { style: STYLES.label }, 'Member Bots (additional invited bots)'),
                botOptions.length > 0
                  ? h(
                      'div',
                      {
                        style: {
                          border: '1px solid rgba(128,128,128,0.35)',
                          borderRadius: '6px',
                          padding: '6px 8px',
                          maxHeight: '110px',
                          overflowY: 'auto',
                          fontSize: '12.5px',
                        },
                      },
                      ...botOptions
                        .filter(b => b.id !== ruleDraft.creatorBotAppId)
                        .map(b =>
                          h(
                            'label',
                            {
                              key: b.id,
                              style: { display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '3px' },
                            },
                            h('input', {
                              type: 'checkbox',
                              checked: ruleDraft.memberBotAppIds.includes(b.id),
                              onChange: (e: { target: { checked: boolean } }) => {
                                const nextMembers = e.target.checked
                                  ? [...ruleDraft.memberBotAppIds, b.id]
                                  : ruleDraft.memberBotAppIds.filter(id => id !== b.id);
                                setRuleDraft({ ...ruleDraft, memberBotAppIds: nextMembers });
                              },
                            }),
                            b.label,
                          ),
                        ),
                    )
                  : h('input', {
                      style: STYLES.input,
                      value: ruleDraft.memberBotAppIds.join(', '),
                      placeholder: 'cli_bot_a, cli_bot_b',
                      onChange: (e: { target: { value: string } }) =>
                        setRuleDraft({ ...ruleDraft, memberBotAppIds: splitCsv(e.target.value) }),
                    }),
              ),
              h(
                'div',
                null,
                h('label', { style: STYLES.label }, 'Per-Repo Poll Interval (sec, optional >= 15)'),
                h('input', {
                  style: STYLES.input,
                  type: 'number',
                  value: ruleDraft.pollIntervalSecText,
                  placeholder: 'Default global interval',
                  onChange: (e: { target: { value: string } }) =>
                    setRuleDraft({ ...ruleDraft, pollIntervalSecText: e.target.value }),
                }),
              ),
              h(
                'div',
                null,
                h('label', { style: STYLES.label }, 'Chat Mode'),
                h(
                  'select',
                  {
                    style: STYLES.input,
                    value: ruleDraft.chatMode,
                    onChange: (e: { target: { value: string } }) =>
                      setRuleDraft({ ...ruleDraft, chatMode: e.target.value as ChatMode }),
                  },
                  h('option', { value: 'group' }, 'group'),
                  h('option', { value: 'topic' }, 'topic'),
                ),
              ),
              h(
                'div',
                null,
                h('label', { style: STYLES.label }, 'Base Branches (comma-separated, blank = all)'),
                h('input', {
                  style: STYLES.input,
                  value: ruleDraft.baseBranchesText,
                  placeholder: 'main, release',
                  onChange: (e: { target: { value: string } }) =>
                    setRuleDraft({ ...ruleDraft, baseBranchesText: e.target.value }),
                }),
              ),
              h(
                'div',
                null,
                h('label', { style: STYLES.label }, 'Bind Working Directory (optional abs path)'),
                h('input', {
                  style: STYLES.input,
                  value: ruleDraft.bindWorkingDir,
                  placeholder: '/path/to/repo',
                  onChange: (e: { target: { value: string } }) =>
                    setRuleDraft({ ...ruleDraft, bindWorkingDir: e.target.value }),
                }),
              ),
              h(
                'div',
                null,
                h('label', { style: STYLES.label }, 'Author Allowlist (comma-separated)'),
                h('input', {
                  style: STYLES.input,
                  value: ruleDraft.authorAllowlistText,
                  onChange: (e: { target: { value: string } }) =>
                    setRuleDraft({ ...ruleDraft, authorAllowlistText: e.target.value }),
                }),
              ),
              h(
                'div',
                null,
                h('label', { style: STYLES.label }, 'Author Denylist (comma-separated)'),
                h('input', {
                  style: STYLES.input,
                  value: ruleDraft.authorDenylistText,
                  placeholder: 'dependabot[bot]',
                  onChange: (e: { target: { value: string } }) =>
                    setRuleDraft({ ...ruleDraft, authorDenylistText: e.target.value }),
                }),
              ),
              h(
                'div',
                null,
                h('label', { style: STYLES.label }, 'Label Allowlist (comma-separated)'),
                h('input', {
                  style: STYLES.input,
                  value: ruleDraft.labelAllowlistText,
                  onChange: (e: { target: { value: string } }) =>
                    setRuleDraft({ ...ruleDraft, labelAllowlistText: e.target.value }),
                }),
              ),
              h(
                'div',
                null,
                h('label', { style: STYLES.label }, 'Label Denylist (comma-separated)'),
                h('input', {
                  style: STYLES.input,
                  value: ruleDraft.labelDenylistText,
                  onChange: (e: { target: { value: string } }) =>
                    setRuleDraft({ ...ruleDraft, labelDenylistText: e.target.value }),
                }),
              ),
            ),
            h(
              'div',
              { style: { marginTop: '10px' } },
              h('label', { style: STYLES.label }, 'Group Name Template'),
              h('input', {
                style: STYLES.input,
                value: ruleDraft.groupNameTemplate,
                onChange: (e: { target: { value: string } }) =>
                  setRuleDraft({ ...ruleDraft, groupNameTemplate: e.target.value }),
              }),
            ),
            h(
              'div',
              { style: { marginTop: '10px' } },
              h('label', { style: STYLES.label }, 'Kickoff Prompt Template (PR fields auto-wrapped in <untrusted_pr_metadata>)'),
              h('textarea', {
                style: { ...STYLES.input, minHeight: '64px' },
                value: ruleDraft.kickoffPromptTemplate,
                onChange: (e: { target: { value: string } }) =>
                  setRuleDraft({ ...ruleDraft, kickoffPromptTemplate: e.target.value }),
              }),
            ),
            h(
              'div',
              { style: { ...STYLES.row, marginTop: '10px', fontSize: '12.5px' } },
              h(
                'label',
                null,
                h('input', {
                  type: 'checkbox',
                  checked: ruleDraft.enabled,
                  onChange: (e: { target: { checked: boolean } }) =>
                    setRuleDraft({ ...ruleDraft, enabled: e.target.checked }),
                }),
                ' Enabled',
              ),
              h(
                'label',
                null,
                h('input', {
                  type: 'checkbox',
                  checked: ruleDraft.ignoreDrafts,
                  onChange: (e: { target: { checked: boolean } }) =>
                    setRuleDraft({ ...ruleDraft, ignoreDrafts: e.target.checked }),
                }),
                ' Ignore Drafts',
              ),
              h(
                'label',
                null,
                h('input', {
                  type: 'checkbox',
                  checked: ruleDraft.triggerOpened,
                  onChange: (e: { target: { checked: boolean } }) =>
                    setRuleDraft({ ...ruleDraft, triggerOpened: e.target.checked }),
                }),
                ' Trigger: opened',
              ),
              h(
                'label',
                null,
                h('input', {
                  type: 'checkbox',
                  checked: ruleDraft.triggerReady,
                  onChange: (e: { target: { checked: boolean } }) =>
                    setRuleDraft({ ...ruleDraft, triggerReady: e.target.checked }),
                }),
                ' Trigger: ready_for_review',
              ),
              h(
                'label',
                null,
                h('input', {
                  type: 'checkbox',
                  checked: ruleDraft.setTopNotice,
                  onChange: (e: { target: { checked: boolean } }) =>
                    setRuleDraft({ ...ruleDraft, setTopNotice: e.target.checked }),
                }),
                ' Set Top Notice',
              ),
              h(
                'label',
                null,
                h('input', {
                  type: 'checkbox',
                  checked: ruleDraft.postShareLinkToPr,
                  onChange: (e: { target: { checked: boolean } }) =>
                    setRuleDraft({ ...ruleDraft, postShareLinkToPr: e.target.checked }),
                }),
                ' Post Share Link to PR',
              ),
              h(
                'label',
                null,
                h('input', {
                  type: 'checkbox',
                  checked: ruleDraft.onNewCommit,
                  onChange: (e: { target: { checked: boolean } }) =>
                    setRuleDraft({ ...ruleDraft, onNewCommit: e.target.checked }),
                }),
                ' Notify on New Commit',
              ),
              h(
                'label',
                null,
                h('input', {
                  type: 'checkbox',
                  checked: ruleDraft.onPrClosed,
                  onChange: (e: { target: { checked: boolean } }) =>
                    setRuleDraft({ ...ruleDraft, onPrClosed: e.target.checked }),
                }),
                ' Notify on PR Closed',
              ),
            ),
            h(
              'div',
              { style: { ...STYLES.row, marginTop: '12px' } },
              h('button', { style: STYLES.btnPrimary, disabled: busy, onClick: () => void handleSaveRuleDraft() }, 'Save Rule'),
              h(
                'button',
                {
                  style: STYLES.btn,
                  onClick: () => {
                    setRuleDraft(null);
                    setEditingIndex(null);
                  },
                },
                'Cancel',
              ),
            ),
          )
        : null,
    ),

    // Explicit Backfill / Manual Open PR
    h(
      'div',
      { style: STYLES.card },
      h('h3', { style: { margin: '0 0 8px', fontSize: '15px' } }, 'Manual PR Group Backfill'),
      h(
        'div',
        { style: STYLES.row },
        h('input', {
          style: { ...STYLES.input, maxWidth: '340px' },
          value: openPrInput,
          placeholder: 'owner/repo#123',
          onChange: (e: { target: { value: string } }) => setOpenPrInput(e.target.value),
        }),
        h('button', { style: STYLES.btn, disabled: busy, onClick: () => void handleOpenPr(true) }, 'Dry-Run'),
        h('button', { style: STYLES.btnPrimary, disabled: busy, onClick: () => void handleOpenPr(false) }, 'Open Review Group'),
      ),
    ),

    // Recent PR -> Group Mappings
    h(
      'div',
      { style: STYLES.card },
      h('h3', { style: { margin: '0 0 10px', fontSize: '15px' } }, `PR -> Group Mappings (${prGroups.length})`),
      prGroups.length === 0
        ? h('div', { style: { fontSize: '13px', opacity: 0.75 } }, 'No PR review groups recorded yet.')
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
                h('th', { style: STYLES.th }, 'Status'),
                h('th', { style: STYLES.th }, 'Chat ID'),
                h('th', { style: STYLES.th }, 'Kickoff / Top Notice'),
                h('th', { style: STYLES.th }, 'Head SHA'),
                h('th', { style: STYLES.th }, 'Updated'),
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
                      { style: STYLES.badge(g.status === 'active' ? 'ok' : g.status === 'creating' ? 'warn' : 'muted') },
                      g.status,
                    ),
                  ),
                  h('td', { style: { ...STYLES.td, fontFamily: 'monospace' } }, g.chatId ?? '(pending)'),
                  h(
                    'td',
                    { style: STYLES.td },
                    `kickoff=${g.kickoffVerified ? 'verified' : g.kickoffMessageId ? 'sent' : 'none'}, topNotice=${g.topNoticeSet ? 'yes' : 'no'}`,
                  ),
                  h('td', { style: { ...STYLES.td, fontFamily: 'monospace' } }, g.lastHeadSha.slice(0, 10)),
                  h('td', { style: STYLES.td }, g.updatedAt),
                ),
              ),
            ),
          ),
    ),
    // Recent Events Log
    h(
      'div',
      { style: STYLES.card },
      h(
        'h3',
        { style: { margin: '0 0 10px', fontSize: '15px' } },
        `Recent Activity Log (${(envelope?.recentEvents ?? []).length})`,
      ),
      (envelope?.recentEvents ?? []).length === 0
        ? h('div', { style: { fontSize: '13px', opacity: 0.75 } }, 'No recent events logged.')
        : h(
            'div',
            { style: { maxHeight: '220px', overflowY: 'auto', fontSize: '12px', fontFamily: 'monospace' } },
            ...(envelope?.recentEvents ?? []).slice(0, 25).map((ev, i) =>
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
  );
}

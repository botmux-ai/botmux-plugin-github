import type {
  ChatMode,
  RedactedPluginConfig,
  RepoRule,
  RepoRuntimeState,
  TriggerKind,
} from '../types.ts';
import {
  DEFAULT_KICKOFF_PROMPT_TEMPLATE,
  DEFAULT_MAX_GROUP_CREATES_PER_HOUR,
  DEFAULT_SERVICE_PORT,
  MIN_POLL_INTERVAL_SEC,
} from '../types.ts';

export const PRESET_RULE_NAME = 'PR 自动拉群评审';
export const PRESET_GROUP_NAME_TEMPLATE = 'pr {{prNumber}} {{title}}';
export const PRESET_KICKOFF_PROMPT_TEMPLATE = DEFAULT_KICKOFF_PROMPT_TEMPLATE;

export const REPO_SLUG_RE =
  /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})\/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$/;

export interface BotListItem {
  id: string;
  name: string;
  plugins: string[];
}

export interface BotStatusItem {
  id: string;
  name: string;
  brand: string;
  online: boolean;
  apiOnly: boolean;
}

export interface NormalizedBotOption {
  id: string;
  name: string;
  label: string;
  brand?: string;
  online?: boolean;
  apiOnly: boolean;
}

export interface RuleDraft {
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

export function splitCsv(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const part of text.split(/[\n,]/)) {
    const trimmed = part.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    out.push(trimmed);
  }
  return out;
}

function formatBrandLabel(brand?: string): string {
  if (!brand) return '';
  const lower = brand.toLowerCase();
  if (lower === 'feishu') return '飞书';
  if (lower === 'lark') return 'Lark';
  return brand;
}

/**
 * Merges host listBots() with backend botStatus metadata into human-friendly
 * Chinese labels (displaying Bot names instead of raw cli_... IDs).
 * Online non-apiOnly bots are ordered first so default selection picks an active bot.
 */
export function buildBotOptions(
  bots: BotListItem[],
  botStatus?: BotStatusItem[],
): NormalizedBotOption[] {
  const statusById = new Map((botStatus ?? []).map(b => [b.id, b]));
  const rawList: Array<{
    id: string;
    name: string;
    brand?: string;
    online?: boolean;
    apiOnly: boolean;
  }> = [];
  const seen = new Set<string>();

  for (const b of bots) {
    if (!b?.id || seen.has(b.id)) continue;
    seen.add(b.id);
    const st = statusById.get(b.id);
    const displayName = (b.name || st?.name || '').trim() || b.id;
    rawList.push({
      id: b.id,
      name: displayName,
      brand: st?.brand,
      online: st?.online,
      apiOnly: st?.apiOnly === true,
    });
  }

  for (const st of botStatus ?? []) {
    if (!st?.id || seen.has(st.id)) continue;
    seen.add(st.id);
    const displayName = (st.name || '').trim() || st.id;
    rawList.push({
      id: st.id,
      name: displayName,
      brand: st.brand,
      online: st.online,
      apiOnly: st.apiOnly === true,
    });
  }

  const usable = rawList.filter(b => !b.apiOnly);

  // Count duplicate display names so we disambiguate only when needed
  const nameCounts = new Map<string, number>();
  for (const item of usable) {
    nameCounts.set(item.name, (nameCounts.get(item.name) ?? 0) + 1);
  }

  const formatted: NormalizedBotOption[] = usable.map(item => {
    const dup = (nameCounts.get(item.name) ?? 0) > 1;
    const baseName = dup ? `${item.name}（…${item.id.slice(-6)}）` : item.name;
    const tags: string[] = [];
    const brandLabel = formatBrandLabel(item.brand);
    if (brandLabel) tags.push(brandLabel);
    if (typeof item.online === 'boolean') {
      tags.push(item.online ? '在线' : '离线');
    }
    const label = tags.length > 0 ? `${baseName}（${tags.join(' · ')}）` : baseName;
    return {
      id: item.id,
      name: item.name,
      label,
      brand: item.brand,
      online: item.online,
      apiOnly: item.apiOnly,
    };
  });

  // Prioritize online bots ahead of offline bots while keeping relative order stable
  formatted.sort((a, b) => {
    const rank = (x: NormalizedBotOption) => (x.online === true ? 0 : x.online === undefined ? 1 : 2);
    return rank(a) - rank(b);
  });

  return formatted;
}

export function pickDefaultCreatorBotId(options: NormalizedBotOption[]): string {
  return options[0]?.id ?? '';
}

export function resolveBotDisplayName(
  botId: string | undefined,
  options: NormalizedBotOption[],
): string {
  if (!botId) return '未设置';
  const match = options.find(b => b.id === botId);
  return match ? match.name : botId;
}

/**
 * Creates a new rule draft pre-filled with the "PR 自动拉群评审" preset defaults.
 */
export function createPresetRuleDraft(defaultCreatorBotId = ''): RuleDraft {
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
    creatorBotAppId: defaultCreatorBotId,
    memberBotAppIds: [],
    kickoffBotAppId: '',
    chatMode: 'group',
    groupNameTemplate: PRESET_GROUP_NAME_TEMPLATE,
    kickoffPromptTemplate: PRESET_KICKOFF_PROMPT_TEMPLATE,
    bindWorkingDir: '',
    setTopNotice: true,
    postShareLinkToPr: true,
    onNewCommit: false,
    onPrClosed: false,
    pollIntervalSecText: '',
  };
}

export function ruleToDraft(rule: RepoRule): RuleDraft {
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

export function draftToRule(draft: RuleDraft): RepoRule {
  const triggers: TriggerKind[] = [];
  if (draft.triggerOpened) triggers.push('opened');
  if (draft.triggerReady) triggers.push('ready_for_review');
  if (triggers.length === 0) triggers.push('opened');

  const trimmedPoll = draft.pollIntervalSecText.trim();
  const parsedPoll = trimmedPoll ? Number(trimmedPoll) : undefined;
  const creator = draft.creatorBotAppId.trim();
  const members = Array.from(
    new Set(draft.memberBotAppIds.map(id => id.trim()).filter(id => Boolean(id) && id !== creator)),
  );
  const kickoff = draft.kickoffBotAppId.trim();

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
    creatorBotAppId: creator,
    memberBotAppIds: members,
    ...(kickoff ? { kickoffBotAppId: kickoff } : {}),
    chatMode: draft.chatMode,
    groupNameTemplate: draft.groupNameTemplate.trim() || PRESET_GROUP_NAME_TEMPLATE,
    kickoffPromptTemplate: draft.kickoffPromptTemplate.trim() || PRESET_KICKOFF_PROMPT_TEMPLATE,
    ...(draft.bindWorkingDir.trim() ? { bindWorkingDir: draft.bindWorkingDir.trim() } : {}),
    setTopNotice: draft.setTopNotice,
    postShareLinkToPr: draft.postShareLinkToPr,
    onNewCommit: draft.onNewCommit,
    onPrClosed: draft.onPrClosed,
    ...(parsedPoll !== undefined && Number.isInteger(parsedPoll)
      ? { pollIntervalSec: parsedPoll }
      : {}),
  };
}

/**
 * Updates creatorBotAppId and prevents creator/reviewer/kickoff collisions.
 */
export function changeCreatorBot(draft: RuleDraft, nextCreatorId: string): RuleDraft {
  const nextMembers = draft.memberBotAppIds.filter(id => id !== nextCreatorId);
  const nextKickoff =
    draft.kickoffBotAppId === nextCreatorId ? (nextMembers[0] ?? '') : draft.kickoffBotAppId;
  return {
    ...draft,
    creatorBotAppId: nextCreatorId,
    memberBotAppIds: nextMembers,
    kickoffBotAppId: nextKickoff,
  };
}

/**
 * Toggles a reviewer bot checkbox and keeps kickoffBotAppId synced:
 * - Checking the first reviewer bot automatically selects it as kickoffBotAppId.
 * - Unchecking the currently selected kickoffBotAppId falls back to the next remaining reviewer bot.
 */
export function toggleReviewerBot(draft: RuleDraft, botId: string, checked: boolean): RuleDraft {
  if (!botId || botId === draft.creatorBotAppId) return draft;
  if (checked) {
    const nextMembers = draft.memberBotAppIds.includes(botId)
      ? draft.memberBotAppIds
      : [...draft.memberBotAppIds, botId];
    const nextKickoff = draft.kickoffBotAppId || nextMembers[0] || '';
    return {
      ...draft,
      memberBotAppIds: nextMembers,
      kickoffBotAppId: nextKickoff,
    };
  }
  const nextMembers = draft.memberBotAppIds.filter(id => id !== botId);
  const nextKickoff =
    draft.kickoffBotAppId === botId ? (nextMembers[0] ?? '') : draft.kickoffBotAppId;
  return {
    ...draft,
    memberBotAppIds: nextMembers,
    kickoffBotAppId: nextKickoff,
  };
}

/**
 * Counts how many fields inside "高级过滤与模板设置" differ from the
 * "PR 自动拉群评审" preset defaults, so existing custom rules show a clear badge.
 */
export function countCustomizedAdvancedFields(draft: RuleDraft): number {
  let count = 0;
  if (splitCsv(draft.baseBranchesText).length > 0) count++;
  if (!(draft.triggerOpened && draft.triggerReady)) count++;
  if (draft.ignoreDrafts !== true) count++;
  if (splitCsv(draft.authorAllowlistText).length > 0) count++;
  if (splitCsv(draft.authorDenylistText).length > 0) count++;
  if (splitCsv(draft.labelAllowlistText).length > 0) count++;
  if (splitCsv(draft.labelDenylistText).length > 0) count++;
  if (draft.chatMode !== 'group') count++;
  const groupTpl = draft.groupNameTemplate.trim();
  if (groupTpl && groupTpl !== PRESET_GROUP_NAME_TEMPLATE) count++;
  const kickoffTpl = draft.kickoffPromptTemplate.trim();
  if (kickoffTpl && kickoffTpl !== PRESET_KICKOFF_PROMPT_TEMPLATE) count++;
  if (draft.bindWorkingDir.trim().length > 0) count++;
  if (draft.setTopNotice !== true) count++;
  if (draft.postShareLinkToPr !== true) count++;
  if (draft.onNewCommit !== false) count++;
  if (draft.onPrClosed !== false) count++;
  if (draft.pollIntervalSecText.trim().length > 0) count++;
  return count;
}

export function validateRepoInput(
  raw: string,
): { ok: true; repo: string } | { ok: false; error: string } {
  const trimmed = raw.trim();
  if (!trimmed) {
    return { ok: false, error: '请输入仓库名（格式：owner/repo，例如 deepcoldy/botmux）' };
  }
  if (!REPO_SLUG_RE.test(trimmed)) {
    return { ok: false, error: '仓库名格式不正确，应为 owner/repo（例如 deepcoldy/botmux）' };
  }
  const [owner, repo] = trimmed.split('/');
  if (owner === '.' || owner === '..' || repo === '.' || repo === '..') {
    return { ok: false, error: '仓库名不能包含 . 或 .. 路径段' };
  }
  return { ok: true, repo: trimmed };
}

export function validateRuleDraft(
  draft: RuleDraft,
  existingRules: RepoRule[],
  editingIndex: number | null,
): string | null {
  const repoCheck = validateRepoInput(draft.repo);
  if (!repoCheck.ok) return repoCheck.error;

  const lowerRepo = repoCheck.repo.toLowerCase();
  const duplicateIdx = existingRules.findIndex(
    (r, i) => i !== editingIndex && r.repo.trim().toLowerCase() === lowerRepo,
  );
  if (duplicateIdx >= 0) {
    return `仓库 ${repoCheck.repo} 已存在监控规则，请直接编辑现有规则`;
  }

  const creator = draft.creatorBotAppId.trim();
  if (draft.enabled && !creator) {
    return '请选择建群 Bot';
  }
  if (draft.kickoffBotAppId.trim() && draft.kickoffBotAppId.trim() === creator) {
    return '首审触发 Bot 不能与建群 Bot 相同';
  }
  if (!draft.triggerOpened && !draft.triggerReady) {
    return '请至少保留一种触发时机（新开 PR 或 Draft 转为就绪）';
  }

  const bindDir = draft.bindWorkingDir.trim();
  if (bindDir && (!bindDir.startsWith('/') || bindDir.includes('\0'))) {
    return '绑定工作目录必须是绝对路径（以 / 开头）';
  }

  const pollText = draft.pollIntervalSecText.trim();
  if (pollText) {
    if (!/^\d+$/.test(pollText)) {
      return `自定义轮询间隔必须为 ${MIN_POLL_INTERVAL_SEC}–86400 之间的整数`;
    }
    const n = Number(pollText);
    if (!Number.isInteger(n) || n < MIN_POLL_INTERVAL_SEC || n > 86_400) {
      return `自定义轮询间隔必须为 ${MIN_POLL_INTERVAL_SEC}–86400 之间的整数`;
    }
  }

  return null;
}

export function validatePrSpecInput(
  raw: string,
): { ok: true; repo: string; prNumber: number } | { ok: false; error: string } {
  const spec = raw.trim();
  const idx = spec.lastIndexOf('#');
  if (idx <= 0) {
    return { ok: false, error: '请输入 owner/repo#123 格式的 PR 标识' };
  }
  const repo = spec.slice(0, idx).trim();
  const numRaw = spec.slice(idx + 1).trim();
  const repoCheck = validateRepoInput(repo);
  if (!repoCheck.ok) {
    return { ok: false, error: '仓库名格式不正确，应为 owner/repo#123' };
  }
  if (!/^\d+$/.test(numRaw)) {
    return { ok: false, error: 'PR 编号必须是正整数（格式：owner/repo#123）' };
  }
  const prNumber = Number(numRaw);
  if (!Number.isSafeInteger(prNumber) || prNumber < 1) {
    return { ok: false, error: 'PR 编号必须是正整数（格式：owner/repo#123）' };
  }
  return { ok: true, repo: repoCheck.repo, prNumber };
}

export function hasFullGitHubAppConfig(cfg?: RedactedPluginConfig): boolean {
  return Boolean(
    cfg?.github.app.appId && cfg?.github.app.installationId && cfg?.github.app.hasPrivateKey,
  );
}

export function shouldAutoDetectGhAuth(cfg?: RedactedPluginConfig): boolean {
  if (!cfg) return false;
  if (cfg.github.mode === 'gh_cli') return true;
  if (cfg.github.mode === 'auto' && !cfg.github.hasPat && !hasFullGitHubAppConfig(cfg)) {
    return true;
  }
  return false;
}

export type EffectiveAuthState =
  | 'gh_cli'
  | 'pat'
  | 'github_app'
  | 'incomplete_pat'
  | 'incomplete_app';

export function resolveEffectiveAuthState(cfg?: RedactedPluginConfig): EffectiveAuthState {
  if (!cfg) return 'gh_cli';
  const fullApp = hasFullGitHubAppConfig(cfg);
  if (cfg.github.mode === 'pat') {
    return cfg.github.hasPat ? 'pat' : 'incomplete_pat';
  }
  if (cfg.github.mode === 'github_app') {
    return fullApp ? 'github_app' : 'incomplete_app';
  }
  if (cfg.github.mode === 'gh_cli') {
    return 'gh_cli';
  }
  // mode === 'auto': precedence is GitHub App -> PAT -> gh_cli
  if (fullApp) return 'github_app';
  if (cfg.github.hasPat) return 'pat';
  return 'gh_cli';
}

export function formatGhAutoDetectedText(identity?: string): string {
  const trimmed = (identity ?? '').trim();
  if (trimmed && trimmed.toLowerCase() !== 'authenticated') {
    const handle = trimmed.startsWith('@') ? trimmed : `@${trimmed}`;
    return `已自动识别本机 GitHub 账号 ${handle}（来自 gh），免配置可直接使用`;
  }
  return '已自动识别本机 GitHub 账号（来自 gh），免配置可直接使用';
}

export function buildGlobalAdvancedSummary(opts: {
  pollIntervalSec: number;
  webhookEnabled: boolean;
  proxyUrl: string;
  port?: number;
  maxGroupCreatesPerRepoPerHour?: number;
}): string {
  const parts: string[] = [
    `轮询 ${opts.pollIntervalSec}s`,
    opts.webhookEnabled ? 'Webhook 已开启' : 'Webhook 未开启',
    opts.proxyUrl.trim() ? '已配置代理' : '无代理',
  ];
  if (opts.port !== undefined && opts.port !== DEFAULT_SERVICE_PORT) {
    parts.push(`端口 ${opts.port}`);
  }
  if (
    opts.maxGroupCreatesPerRepoPerHour !== undefined &&
    opts.maxGroupCreatesPerRepoPerHour !== DEFAULT_MAX_GROUP_CREATES_PER_HOUR
  ) {
    parts.push(`限流 ${opts.maxGroupCreatesPerRepoPerHour}/h`);
  }
  return parts.join(' · ');
}

export function computeLatestSyncTime(
  repos?: Record<string, RepoRuntimeState>,
): string | null {
  if (!repos) return null;
  let latestMs = -1;
  let latestIso: string | null = null;
  for (const state of Object.values(repos)) {
    if (!state?.lastPollAt) continue;
    const ms = Date.parse(state.lastPollAt);
    if (!Number.isNaN(ms) && ms > latestMs) {
      latestMs = ms;
      latestIso = state.lastPollAt;
    }
  }
  return latestIso;
}

export function formatDisplayTime(iso: string | null | undefined): string {
  if (!iso) return '尚未同步';
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return iso;
  try {
    return new Date(ms).toLocaleString();
  } catch {
    return iso;
  }
}

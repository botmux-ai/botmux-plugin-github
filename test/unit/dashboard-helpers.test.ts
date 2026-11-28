import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  PRESET_GROUP_NAME_TEMPLATE,
  PRESET_KICKOFF_PROMPT_TEMPLATE,
  buildBotOptions,
  buildGlobalAdvancedSummary,
  changeCreatorBot,
  computeLatestSyncTime,
  countCustomizedAdvancedFields,
  createPresetRuleDraft,
  draftToRule,
  formatGhAutoDetectedText,
  pickDefaultCreatorBotId,
  resolveBotDisplayName,
  resolveEffectiveAuthState,
  ruleToDraft,
  shouldAutoDetectGhAuth,
  toggleReviewerBot,
  validatePrSpecInput,
  validateRepoInput,
  validateRuleDraft,
} from '../../src/dashboard/helpers.ts';
import { createDefaultConfig, redactConfig, validateRepoRule } from '../../src/config/schema.ts';

describe('Dashboard helpers: Bot selection, 2-step preset rule generation & customization tracking', () => {
  it('formats Bot options with friendly Chinese names, prioritizes online bots, filters apiOnly, and disambiguates duplicate names', () => {
    const options = buildBotOptions(
      [
        { id: 'cli_offline_1', name: '助手', plugins: ['github'] },
        { id: 'cli_online_a1b2c3', name: '大管家', plugins: ['github'] },
        { id: 'cli_dup_999999', name: '助手', plugins: ['github'] },
        { id: 'cli_api_only', name: '只读机器人', plugins: [] },
      ],
      [
        { id: 'cli_offline_1', name: '助手', brand: 'feishu', online: false, apiOnly: false },
        { id: 'cli_online_a1b2c3', name: '大管家', brand: 'feishu', online: true, apiOnly: false },
        { id: 'cli_dup_999999', name: '助手', brand: 'lark', online: true, apiOnly: false },
        { id: 'cli_api_only', name: '只读机器人', brand: 'feishu', online: true, apiOnly: true },
      ],
    );

    assert.equal(options.length, 3);
    assert.equal(options[0]!.id, 'cli_online_a1b2c3');
    assert.equal(options[0]!.label, '大管家（飞书 · 在线）');
    assert.ok(!options[0]!.label.includes('cli_'), 'Unique Bot label should show name instead of raw cli_ ID');
    assert.equal(options[1]!.label, '助手（…999999）（Lark · 在线）');
    assert.equal(options[2]!.label, '助手（…line_1）（飞书 · 离线）');
    assert.equal(pickDefaultCreatorBotId(options), 'cli_online_a1b2c3');
    assert.equal(resolveBotDisplayName('cli_online_a1b2c3', options), '大管家');
    assert.equal(resolveBotDisplayName('cli_unknown', options), 'cli_unknown');
  });

  it('produces a schema-valid RepoRule from the 2-step preset with sensible defaults and synced reviewer/kickoff bots', () => {
    let draft = createPresetRuleDraft('cli_creator_1');
    assert.equal(countCustomizedAdvancedFields(draft), 0);
    assert.equal(draft.groupNameTemplate, PRESET_GROUP_NAME_TEMPLATE);
    assert.equal(draft.kickoffPromptTemplate, PRESET_KICKOFF_PROMPT_TEMPLATE);
    assert.equal(draft.setTopNotice, true);
    assert.equal(draft.postShareLinkToPr, true);
    assert.equal(draft.ignoreDrafts, true);
    assert.equal(draft.chatMode, 'group');

    draft = { ...draft, repo: 'deepcoldy/botmux' };
    draft = toggleReviewerBot(draft, 'cli_review_a', true);
    assert.deepEqual(draft.memberBotAppIds, ['cli_review_a']);
    assert.equal(draft.kickoffBotAppId, 'cli_review_a', 'First checked reviewer bot must auto-become kickoffBotAppId');

    draft = toggleReviewerBot(draft, 'cli_review_b', true);
    assert.deepEqual(draft.memberBotAppIds, ['cli_review_a', 'cli_review_b']);
    assert.equal(draft.kickoffBotAppId, 'cli_review_a', 'Checking second reviewer bot keeps first as kickoff');

    // Unchecking the current kickoff bot automatically shifts kickoff to remaining reviewer bot
    draft = toggleReviewerBot(draft, 'cli_review_a', false);
    assert.deepEqual(draft.memberBotAppIds, ['cli_review_b']);
    assert.equal(draft.kickoffBotAppId, 'cli_review_b');

    // Switching creatorBotAppId to cli_review_b strips it from members & kickoff
    const collided = changeCreatorBot(draft, 'cli_review_b');
    assert.equal(collided.creatorBotAppId, 'cli_review_b');
    assert.deepEqual(collided.memberBotAppIds, []);
    assert.equal(collided.kickoffBotAppId, '');

    assert.equal(validateRuleDraft(draft, [], null), null);
    const rule = draftToRule(draft);
    const validated = validateRepoRule(rule, 0);
    assert.equal(validated.repo, 'deepcoldy/botmux');
    assert.equal(validated.creatorBotAppId, 'cli_creator_1');
    assert.deepEqual(validated.memberBotAppIds, ['cli_review_b']);
    assert.equal(validated.kickoffBotAppId, 'cli_review_b');
    assert.equal(validated.groupNameTemplate, 'pr {{prNumber}} {{title}}');
    assert.deepEqual(validated.triggerOn, ['opened', 'ready_for_review']);
    assert.equal(validated.ignoreDrafts, true);
    assert.equal(validated.setTopNotice, true);
    assert.equal(validated.postShareLinkToPr, true);
    assert.equal(validated.onNewCommit, false);
    assert.equal(validated.onPrClosed, false);
    assert.deepEqual(validated.baseBranches, []);
  });

  it('accurately counts customized advanced fields and faithfully round-trips existing rules', () => {
    const existingRule = validateRepoRule(
      {
        repo: 'acme/service',
        enabled: true,
        creatorBotAppId: 'cli_creator',
        memberBotAppIds: ['cli_rev1'],
        kickoffBotAppId: 'cli_rev1',
        baseBranches: ['main', 'release'],
        authorDenylist: ['dependabot[bot]'],
        bindWorkingDir: '/srv/acme/service',
        groupNameTemplate: 'pr {{prNumber}} {{title}}',
        setTopNotice: true,
        postShareLinkToPr: true,
        onNewCommit: true,
        pollIntervalSec: 30,
      },
      0,
    );

    const draft = ruleToDraft(existingRule);
    assert.equal(
      countCustomizedAdvancedFields(draft),
      5,
      'baseBranches, authorDenylist, bindWorkingDir, onNewCommit, pollIntervalSec = 5 customized fields',
    );
    const roundTripped = validateRepoRule(draftToRule(draft), 0);
    assert.deepEqual(roundTripped, existingRule);
  });

  it('validates repo slugs, duplicate rules, PR specs, auth states, and global advanced summary', () => {
    assert.equal(validateRepoInput('deepcoldy/botmux').ok, true);
    assert.equal(validateRepoInput('invalid-repo').ok, false);
    assert.equal(validateRepoInput('../evil').ok, false);

    assert.equal(validatePrSpecInput('owner/repo#123').ok, true);
    assert.equal(validatePrSpecInput('owner/repo#12junk').ok, false);
    assert.equal(validatePrSpecInput('owner/repo#0').ok, false);

    const defaultRedacted = redactConfig(createDefaultConfig());
    assert.equal(shouldAutoDetectGhAuth(defaultRedacted), true);
    assert.equal(resolveEffectiveAuthState(defaultRedacted), 'gh_cli');
    assert.equal(
      formatGhAutoDetectedText('@shenhan'),
      '已自动识别本机 GitHub 账号 @shenhan（来自 gh），免配置可直接使用',
    );
    assert.equal(
      formatGhAutoDetectedText('shenhan'),
      '已自动识别本机 GitHub 账号 @shenhan（来自 gh），免配置可直接使用',
    );

    assert.equal(
      buildGlobalAdvancedSummary({
        pollIntervalSec: 60,
        webhookEnabled: false,
        proxyUrl: '',
        port: 18940,
        maxGroupCreatesPerRepoPerHour: 20,
      }),
      '轮询 60s · Webhook 未开启 · 无代理',
    );
    assert.equal(
      buildGlobalAdvancedSummary({
        pollIntervalSec: 30,
        webhookEnabled: true,
        proxyUrl: 'http://proxy.internal:8080',
        port: 19000,
        maxGroupCreatesPerRepoPerHour: 50,
      }),
      '轮询 30s · Webhook 已开启 · 已配置代理 · 端口 19000 · 限流 50/h',
    );

    assert.equal(
      computeLatestSyncTime({
        'a/b': { lastPollAt: '2026-11-28T10:00:00Z', knownPrs: {} },
        'c/d': { lastPollAt: '2026-11-28T12:30:00Z', knownPrs: {} },
      }),
      '2026-11-28T12:30:00Z',
    );
  });
});

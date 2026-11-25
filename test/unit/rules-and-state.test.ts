import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { PullRequestInfo, RepoRule } from '../../src/types.ts';
import {
  applyConfigPatch,
  ConfigValidationError,
  createDefaultConfig,
  redactConfig,
} from '../../src/config/schema.ts';
import { evaluateRepoRule } from '../../src/engine/rules.ts';
import { StateStore } from '../../src/state/store.ts';
import { SecretRegistry } from '../../src/security/redact.ts';

function makeRule(overrides: Partial<RepoRule> = {}): RepoRule {
  return {
    id: 'acme/app',
    repo: 'acme/app',
    enabled: true,
    baseBranches: ['main'],
    triggerOn: ['opened', 'ready_for_review'],
    ignoreDrafts: true,
    authorAllowlist: [],
    authorDenylist: ['dependabot[bot]'],
    labelAllowlist: [],
    labelDenylist: ['wip'],
    creatorBotAppId: 'cli_creator111',
    memberBotAppIds: ['cli_reviewer222'],
    kickoffBotAppId: 'cli_reviewer222',
    chatMode: 'group',
    groupNameTemplate: 'PR #{{prNumber}} {{repo}} - {{title}}',
    kickoffPromptTemplate: 'Review {{prKey}}.',
    setTopNotice: true,
    postShareLinkToPr: false,
    onNewCommit: false,
    onPrClosed: false,
    ...overrides,
  };
}

function makePr(overrides: Partial<PullRequestInfo> = {}): PullRequestInfo {
  return {
    repo: 'acme/app',
    number: 10,
    title: 'Feature',
    body: 'Body',
    state: 'open',
    draft: false,
    merged: false,
    htmlUrl: 'https://github.com/acme/app/pull/10',
    author: 'Octocat',
    baseBranch: 'main',
    headBranch: 'feat/a',
    headSha: 'd'.repeat(40),
    headRepoFullName: 'acme/app',
    labels: ['Backend'],
    isFork: false,
    maintainerCanModify: true,
    createdAt: '2026-11-25T00:00:00Z',
    updatedAt: '2026-11-25T00:00:00Z',
    ...overrides,
  };
}

describe('Config validation & write-only secret tri-state merging', () => {
  it('enforces creatorBotAppId !== kickoffBotAppId and valid repo slugs', () => {
    const base = createDefaultConfig();
    assert.throws(
      () =>
        applyConfigPatch(base, {
          repos: [
            makeRule({
              creatorBotAppId: 'cli_samebot',
              kickoffBotAppId: 'cli_samebot',
            }),
          ],
        }),
      ConfigValidationError,
    );

    assert.throws(
      () =>
        applyConfigPatch(base, {
          repos: [makeRule({ repo: '../escape/repo' })],
        }),
      ConfigValidationError,
    );
  });

  it('preserves write-only secrets on partial updates, rejects masked sentinels, clears explicitly, and drops proxy password on proxy host change', () => {
    const initial = applyConfigPatch(createDefaultConfig(), {
      github: { pat: 'github_pat_liveTokenValue1234567890abcdef' },
      proxy: { url: 'http://proxy-a.example.com:8080', username: 'alice', password: 'proxy-a-password' },
      webhook: { enabled: true, secret: 'whsec_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6' },
    });

    const redacted = redactConfig(initial);
    assert.equal(redacted.github.hasPat, true);
    assert.equal(redacted.proxy.hasPassword, true);
    assert.equal(redacted.webhook.hasSecret, true);
    assert.ok(!JSON.stringify(redacted).includes('github_pat_liveTokenValue'));
    assert.ok(!JSON.stringify(redacted).includes('proxy-a-password'));
    assert.ok(!JSON.stringify(redacted).includes('whsec_A1b2C3'));

    // Partial unrelated update preserves all stored secrets
    const updated = applyConfigPatch(initial, {
      service: { pollIntervalSec: 45 },
    });
    assert.equal(updated.github.pat, initial.github.pat);
    assert.equal(updated.proxy.password, 'proxy-a-password');
    assert.equal(updated.webhook.secret, initial.webhook.secret);

    // Masked placeholder rejected
    assert.throws(
      () => applyConfigPatch(updated, { github: { pat: '[REDACTED]' } }),
      ConfigValidationError,
    );

    // Proxy host change automatically drops stored proxy-a password!
    const changedProxy = applyConfigPatch(updated, {
      proxy: { url: 'http://proxy-b.example.com:8080' },
    });
    assert.equal(changedProxy.proxy.password, undefined);
    assert.equal(changedProxy.proxy.username, undefined);

    // Explicit clear removes PAT
    const cleared = applyConfigPatch(changedProxy, {
      github: { clearPat: true },
    });
    assert.equal(cleared.github.pat, undefined);
    assert.equal(redactConfig(cleared).github.hasPat, false);

    // Changing github.apiBaseUrl origin MUST automatically drop stored PAT & App private key!
    const movedOrigin = applyConfigPatch(initial, {
      github: { apiBaseUrl: 'https://ghes.other-origin.example/api/v3' },
    });
    assert.equal(movedOrigin.github.pat, undefined, 'Stored PAT must drop on apiBaseUrl origin change');
    assert.equal(movedOrigin.github.app.privateKeyPem, undefined);

    // Embedded credentials in malformed proxy URL must STILL fail closed (not be stripped first!)
    assert.throws(
      () =>
        applyConfigPatch(createDefaultConfig(), {
          proxy: { url: 'http://user:pass@proxy.local:8080/bad-path?x=1' },
        }),
      ConfigValidationError,
    );

    // Bad percent encoding in proxy URL must return ConfigValidationError, not uncaught URIError
    assert.throws(
      () =>
        applyConfigPatch(createDefaultConfig(), {
          proxy: { url: 'http://user:%ZZ@proxy.local:8080' },
        }),
      ConfigValidationError,
    );

    // IPv6 proxy URL with credentials must NOT double-bracket!
    const ipv6Proxy = applyConfigPatch(createDefaultConfig(), {
      proxy: { url: 'http://u:p@[::1]:8080' },
    });
    assert.equal(ipv6Proxy.proxy.url, 'http://[::1]:8080');
    assert.equal(redactConfig(ipv6Proxy).proxy.url, 'http://[::1]:8080');
  });
});

describe('Repository rule matcher', () => {
  it('matches case-insensitive authors and labels and honors drafts/baseBranches/triggerOn', () => {
    const rule = makeRule({
      authorAllowlist: ['octocat'],
      labelAllowlist: ['backend'],
    });
    assert.equal(evaluateRepoRule(rule, makePr(), 'opened').matched, true);
    assert.equal(evaluateRepoRule(rule, makePr({ draft: true }), 'opened').matched, false);
    assert.equal(evaluateRepoRule(rule, makePr({ baseBranch: 'dev' }), 'opened').matched, false);
    assert.equal(
      evaluateRepoRule(rule, makePr({ author: 'Dependabot[bot]' }), 'opened').matched,
      false,
    );
    assert.equal(
      evaluateRepoRule(rule, makePr({ labels: ['Backend', 'WIP'] }), 'opened').matched,
      false,
    );
    assert.equal(
      evaluateRepoRule(makeRule({ triggerOn: ['ready_for_review'] }), makePr(), 'opened').matched,
      false,
    );
    assert.equal(
      evaluateRepoRule(makeRule({ triggerOn: ['ready_for_review'] }), makePr(), 'ready_for_review').matched,
      true,
    );
  });
});

describe('Atomic StateStore & redacted event log', () => {
  it('persists state atomically with 0600 permissions and redacts secrets in events.jsonl', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-gh-state-'));
    try {
      const reg = new SecretRegistry();
      const secret = 'github_pat_verySecretToken1234567890abcd';
      reg.register(secret);
      const store = new StateStore(tmp, reg);

      await store.update(s => {
        s.prGroups['acme/app#10'] = {
          status: 'active',
          repo: 'acme/app',
          prNumber: 10,
          chatId: 'oc_123456',
          groupName: 'PR #10 acme/app - Feature',
          creatorLarkAppId: 'cli_creator111',
          topNoticeSet: true,
          lastHeadSha: 'd'.repeat(40),
          createdAt: '2026-11-25T00:00:00Z',
          updatedAt: '2026-11-25T00:00:00Z',
        };
      });

      const st = await fsp.stat(store.statePath);
      assert.equal(st.mode & 0o777, 0o600);
      const loaded = await store.load();
      assert.equal(loaded.prGroups['acme/app#10']?.chatId, 'oc_123456');

      await store.appendEvent({
        level: 'error',
        kind: 'test_err',
        message: `Auth error with token ${secret}`,
      });
      const eventsRaw = await fsp.readFile(store.eventLogPath, 'utf8');
      assert.ok(!eventsRaw.includes(secret), 'events.jsonl must redact secrets');
      assert.ok(eventsRaw.includes('[REDACTED]'));
    } finally {
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });
});

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHmac } from 'node:crypto';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { PullRequestInfo, RepoRule } from '../../src/types.ts';
import { applyConfigPatch, createDefaultConfig, redactConfig } from '../../src/config/schema.ts';
import { ensureControlToken, savePluginConfig } from '../../src/config/store.ts';
import { StateStore, StateCorruptError } from '../../src/state/store.ts';
import { GitHubClient } from '../../src/github/client.ts';
import { HostBridge } from '../../src/host/bridge.ts';
import { GitHubWatcher } from '../../src/engine/watcher.ts';
import { startGitHubService } from '../../src/service/runner.ts';
import { acquireSecureLock, SecurityFsError } from '../../src/security/fs.ts';
import { loopbackRequest } from '../../src/security/net.ts';
import { verifyDaemonIpcHeaders } from '../../src/host/discovery.ts';

const rootDir = resolve(import.meta.dirname, '..', '..');
const WH_SECRET = 'whsec_Round2Secret_1234567890ABCDEFGH';

function makeRawPr(opts: {
  repo?: string;
  number: number;
  title?: string;
  headSha?: string;
  draft?: boolean;
  state?: 'open' | 'closed';
  merged?: boolean;
}) {
  const repo = opts.repo ?? 'acme/r2';
  return {
    number: opts.number,
    title: opts.title ?? `PR #${opts.number}`,
    body: `Body for #${opts.number}`,
    state: opts.state ?? 'open',
    draft: opts.draft === true,
    merged: opts.merged === true,
    html_url: `https://github.com/${repo}/pull/${opts.number}`,
    user: { login: 'alice' },
    base: { ref: 'main', repo: { full_name: repo } },
    head: {
      ref: `feat/pr-${opts.number}`,
      sha: opts.headSha ?? 'a'.repeat(40),
      repo: { full_name: repo, fork: false },
    },
    labels: [],
    maintainer_can_modify: true,
    created_at: '2026-11-26T00:00:00Z',
    updated_at: '2026-11-26T00:01:00Z',
  };
}

function makePrInfo(opts: {
  repo?: string;
  number: number;
  headSha?: string;
  state?: 'open' | 'closed';
}): PullRequestInfo {
  const repo = opts.repo ?? 'acme/r2';
  return {
    repo,
    number: opts.number,
    title: `PR #${opts.number}`,
    body: `Body for #${opts.number}`,
    state: opts.state ?? 'open',
    draft: false,
    merged: false,
    htmlUrl: `https://github.com/${repo}/pull/${opts.number}`,
    author: 'alice',
    baseBranch: 'main',
    headBranch: `feat/pr-${opts.number}`,
    headSha: opts.headSha ?? 'a'.repeat(40),
    headRepoFullName: repo,
    labels: [],
    isFork: false,
    maintainerCanModify: true,
    createdAt: '2026-11-26T00:00:00Z',
    updatedAt: '2026-11-26T00:01:00Z',
  };
}

function makeRule(overrides: Partial<RepoRule> = {}): RepoRule {
  return {
    id: 'acme/r2',
    repo: 'acme/r2',
    enabled: true,
    baseBranches: ['main'],
    triggerOn: ['opened', 'ready_for_review'],
    ignoreDrafts: true,
    authorAllowlist: [],
    authorDenylist: [],
    labelAllowlist: [],
    labelDenylist: [],
    creatorBotAppId: 'cli_creator1',
    memberBotAppIds: ['cli_reviewer2'],
    kickoffBotAppId: 'cli_reviewer2',
    chatMode: 'group',
    groupNameTemplate: 'PR #{{prNumber}} {{repo}} - {{title}}',
    kickoffPromptTemplate: 'Review {{prKey}}.',
    setTopNotice: true,
    postShareLinkToPr: false,
    onNewCommit: true,
    onPrClosed: true,
    ...overrides,
  };
}

function signWebhook(body: Buffer, secret = WH_SECRET): string {
  return `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;
}

async function waitFor(pred: () => Promise<boolean> | boolean, timeoutMs = 4000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await pred()) return;
    await new Promise(r => setTimeout(r, 20));
  }
  throw new Error(`Timed out after ${timeoutMs}ms`);
}

describe('PR #1 Round-2 Independent Review Regressions (5x P1, 7x P2, 1x P3)', () => {
  it('[P1-1] empty GET while delayed IPC create is still running keeps outcomeUnknown fail-closed and adopts delayed chat without double-create', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-r2-p1-1-'));
    const pluginHome = join(tmp, 'plugin');
    const botmuxHome = join(tmp, 'botmux');
    const dataDir = join(tmp, 'data');
    const daemonsDir = join(dataDir, 'dashboard-daemons');
    await fsp.mkdir(daemonsDir, { recursive: true, mode: 0o700 });
    await fsp.mkdir(botmuxHome, { recursive: true, mode: 0o700 });

    const dashSecret = 'p'.repeat(43);
    await fsp.writeFile(join(botmuxHome, '.dashboard-secret'), `${dashSecret}\n`, { mode: 0o600 });
    await fsp.writeFile(
      join(botmuxHome, 'bots.json'),
      JSON.stringify([
        { larkAppId: 'cli_creator1', larkAppSecret: 's1', brand: 'feishu' },
        { larkAppId: 'cli_reviewer2', larkAppSecret: 's2', brand: 'feishu' },
      ]),
      { mode: 0o600 },
    );

    let nowMs = 1_700_000_000_000;
    let createCalls = 0;
    const visibleChats: Array<{ chatId: string; name: string; kickoffPrompt: string }> = [];
    let delayedCommitTimer: ReturnType<typeof setTimeout> | null = null;
    let daemonPort = 0;
    const seenNonces = new Map<string, number>();

    const daemonServer = http.createServer((req, res) => {
      verifyDaemonIpcHeaders(req.headers, dashSecret, req.method ?? 'GET', req.url ?? '/', daemonPort, seenNonces, nowMs);
      const chunks: Buffer[] = [];
      req.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      req.on('end', () => {
        const body = chunks.length > 0 ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
        if (req.method === 'GET' && req.url === '/api/groups') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ chats: visibleChats.map(c => ({ chatId: c.chatId, name: c.name, chatStatus: 'normal' })) }));
          return;
        }
        if (req.method === 'POST' && req.url === '/api/groups/create') {
          createCalls++;
          assert.ok(typeof body.idempotencyKey === 'string' && body.idempotencyKey.length >= 8);
          const chatId = `oc_delayed_${createCalls}`;
          // Daemon drops socket immediately, but continues creating the group in background (visible after 150ms!)
          delayedCommitTimer = setTimeout(() => {
            visibleChats.push({ chatId, name: body.name, kickoffPrompt: body.kickoffPrompt });
          }, 150);
          req.socket.destroy();
          return;
        }
        const listMsg = /^\/api\/groups\/(oc_[^/]+)\/messages$/.exec(req.url ?? '');
        if (req.method === 'GET' && listMsg) {
          const g = visibleChats.find(c => c.chatId === listMsg[1]);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, messages: g ? [{ messageId: 'om_del_1', preview: g.kickoffPrompt, deleted: false }] : [] }));
          return;
        }
        const getMsg = /^\/api\/groups\/(oc_[^/]+)\/messages\/(om_[^/]+)$/.exec(req.url ?? '');
        if (req.method === 'GET' && getMsg) {
          const g = visibleChats.find(c => c.chatId === getMsg[1]);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, messageId: getMsg[2], chatId: getMsg[1], deleted: false, text: g?.kickoffPrompt ?? '' }));
          return;
        }
        if (req.method === 'POST' && req.url?.endsWith('/top-notice')) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
          return;
        }
        res.writeHead(404);
        res.end('{}');
      });
    });

    await new Promise<void>(r => daemonServer.listen(0, '127.0.0.1', () => r()));
    daemonPort = (daemonServer.address() as { port: number }).port;
    await fsp.writeFile(
      join(daemonsDir, 'cli_creator1.json'),
      JSON.stringify({ larkAppId: 'cli_creator1', ipcPort: daemonPort, lastHeartbeat: nowMs, resolvedAllowedUsers: [] }),
      { mode: 0o600 },
    );

    const ghClient = new GitHubClient({
      auth: { mode: 'pat', apiBaseUrl: 'http://127.0.0.1:1', pat: 'github_pat_p11_token1234567890abcdef', app: { appId: '', installationId: '' } },
      allowInsecureLocalForTests: true,
    });

    try {
      const stateStore = new StateStore(pluginHome);
      const bridge = new HostBridge({
        stateStore,
        discovery: { botmuxHome, dataDir, now: () => nowMs },
        unknownOutcomeSettleMs: 120_000,
        now: () => nowMs,
      });
      const rule = makeRule();
      const pr1 = makePrInfo({ number: 1 });

      // 1. First create drops socket -> outcomeUnknown=true persisted
      await assert.rejects(() => bridge.ensurePrReviewGroup({ rule, pr: pr1, githubClient: ghClient }));
      assert.equal(createCalls, 1);

      // 2. Retry immediately while GET /api/groups is STILL EMPTY (group still creating on daemon):
      //    MUST fail closed, MUST NOT clear outcomeUnknown, MUST NOT call POST /api/groups/create a 2nd time!
      nowMs += 50;
      await assert.rejects(
        () => bridge.ensurePrReviewGroup({ rule, pr: pr1, githubClient: ghClient }),
        /safety settle window/i,
      );
      assert.equal(createCalls, 1, 'Empty GET during safety window MUST NOT re-POST create!');
      assert.equal((await stateStore.load()).prGroups['acme/r2#1']?.createAttempt?.outcomeUnknown, true);

      // 3. Wait until delayed chat appears in GET /api/groups -> next retry adopts oc_delayed_1 with ZERO 2nd create!
      await waitFor(() => visibleChats.length === 1);
      nowMs += 200;
      const adopted = await bridge.ensurePrReviewGroup({ rule, pr: pr1, githubClient: ghClient });
      assert.equal(adopted.reusedExisting, true);
      assert.equal(adopted.record.chatId, 'oc_delayed_1');
      assert.equal(createCalls, 1, 'Total createCalls must remain strictly 1');
    } finally {
      if (delayedCommitTimer) clearTimeout(delayedCommitTimer);
      await new Promise<void>(r => daemonServer.close(() => r()));
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[P1-2] CLI parses --dry-run=true/--dry-run=false explicitly and rejects invalid boolean values with exit code 1', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-r2-p1-2-'));
    const pluginHome = join(tmp, 'plugin');
    await ensureControlToken(pluginHome);

    const received: Array<{ path: string; body: Record<string, unknown> }> = [];
    const ctrlServer = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      req.on('end', () => {
        const body = chunks.length > 0 ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
        received.push({ path: req.url ?? '', body });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        if (req.url === '/api/sync') {
          res.end(JSON.stringify({ ok: true, dryRun: body.dryRun, mode: 'active', actions: [], errors: [] }));
        } else {
          res.end(JSON.stringify({ ok: true, dryRun: body.dryRun, repo: body.repo, prNumber: body.prNumber, action: 'would_create' }));
        }
      });
    });
    await new Promise<void>(r => ctrlServer.listen(0, '127.0.0.1', () => r()));
    const ctrlPort = (ctrlServer.address() as { port: number }).port;

    const cfg = applyConfigPatch(createDefaultConfig(), {
      service: { port: ctrlPort },
      repos: [makeRule()],
    });
    await savePluginConfig(pluginHome, cfg);
    const cliApi = { config: { path: join(pluginHome, 'config.json') } };

    try {
      const cliMod = await import(pathToFileURL(join(rootDir, 'dist', 'cli', 'index.js')).href);
      const cli = cliMod.default;

      assert.equal(await cli['github:sync'].run({ args: ['--dry-run=true', '--json'], api: cliApi }, cliApi), 0);
      assert.equal(await cli['github:open-pr'].run({ args: ['acme/r2#12', '--dry-run=true', '--json'], api: cliApi }, cliApi), 0);
      assert.equal(await cli['github:sync'].run({ args: ['--dry-run=false', '--json'], api: cliApi }, cliApi), 0);
      // Invalid boolean value AND misspelled unknown flags MUST fail with exit code 1 and NEVER hit the live service!
      assert.equal(await cli['github:sync'].run({ args: ['--dry-run=maybe', '--json'], api: cliApi }, cliApi), 1);
      assert.equal(await cli['github:sync'].run({ args: ['--dryrun', '--json'], api: cliApi }, cliApi), 1);
      assert.equal(await cli['github:open-pr'].run({ args: ['acme/r2#12', '-n', '--json'], api: cliApi }, cliApi), 1);
      assert.equal(await cli['github:open-pr'].run({ args: ['acme/r2#12', '--dry-run=invalid', '--json'], api: cliApi }, cliApi), 1);

      assert.equal(received.length, 3);
      assert.equal(received[0]!.body.dryRun, true, '--dry-run=true MUST set dryRun: true');
      assert.equal(received[1]!.body.dryRun, true, 'open-pr --dry-run=true MUST set dryRun: true');
      assert.equal(received[2]!.body.dryRun, false, '--dry-run=false MUST set dryRun: false');
    } finally {
      await new Promise<void>(r => ctrlServer.close(() => r()));
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[P1-3] hourly group-creation cap skip_rate_limited does NOT commit knownPrs or ETag and retries after 1 hour', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-r2-p1-3-'));
    const pluginHome = join(tmp, 'plugin');
    const botmuxHome = join(tmp, 'botmux');
    const dataDir = join(tmp, 'data');
    const daemonsDir = join(dataDir, 'dashboard-daemons');
    await fsp.mkdir(daemonsDir, { recursive: true, mode: 0o700 });
    await fsp.mkdir(botmuxHome, { recursive: true, mode: 0o700 });

    let nowMs = 1_700_000_000_000;
    const dashSecret = 'q'.repeat(43);
    await fsp.writeFile(join(botmuxHome, '.dashboard-secret'), `${dashSecret}\n`, { mode: 0o600 });
    await fsp.writeFile(
      join(botmuxHome, 'bots.json'),
      JSON.stringify([
        { larkAppId: 'cli_creator1', larkAppSecret: 's1', brand: 'feishu' },
        { larkAppId: 'cli_reviewer2', larkAppSecret: 's2', brand: 'feishu' },
      ]),
      { mode: 0o600 },
    );

    let openPrs: Array<ReturnType<typeof makeRawPr>> = [];
    let etag = '"cap-v0"';
    const createdGroups: Array<{ chatId: string; name: string; kickoffPrompt: string }> = [];

    const ghServer = http.createServer((req, res) => {
      if (req.headers['if-none-match'] === etag) {
        res.writeHead(304, { ETag: etag });
        res.end();
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json', ETag: etag });
      res.end(JSON.stringify(openPrs));
    });

    let daemonPort = 0;
    const seenNonces = new Map<string, number>();
    const daemonServer = http.createServer((req, res) => {
      verifyDaemonIpcHeaders(req.headers, dashSecret, req.method ?? 'GET', req.url ?? '/', daemonPort, seenNonces, nowMs);
      const chunks: Buffer[] = [];
      req.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      req.on('end', () => {
        const body = chunks.length > 0 ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
        if (req.method === 'GET' && req.url === '/api/groups') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ chats: createdGroups.map(g => ({ chatId: g.chatId, name: g.name, chatStatus: 'normal' })) }));
          return;
        }
        if (req.method === 'POST' && req.url === '/api/groups/create') {
          const chatId = `oc_cap_${createdGroups.length + 1}`;
          const kickoffMessageId = `om_cap_${createdGroups.length + 1}`;
          createdGroups.push({ chatId, name: body.name, kickoffPrompt: body.kickoffPrompt });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, chatId, kickoffMessageId, kickoffError: null }));
          return;
        }
        const readMsg = /^\/api\/groups\/(oc_[^/]+)\/messages\/(om_[^/]+)$/.exec(req.url ?? '');
        if (req.method === 'GET' && readMsg) {
          const g = createdGroups.find(x => x.chatId === readMsg[1]);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, messageId: readMsg[2], chatId: readMsg[1], deleted: false, text: g?.kickoffPrompt ?? '' }));
          return;
        }
        if (req.method === 'POST' && req.url?.endsWith('/top-notice')) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
          return;
        }
        res.writeHead(404);
        res.end('{}');
      });
    });

    await Promise.all([
      new Promise<void>(r => ghServer.listen(0, '127.0.0.1', () => r())),
      new Promise<void>(r => daemonServer.listen(0, '127.0.0.1', () => r())),
    ]);
    const ghPort = (ghServer.address() as { port: number }).port;
    daemonPort = (daemonServer.address() as { port: number }).port;
    const refreshDaemonHeartbeat = () =>
      fsp.writeFile(
        join(daemonsDir, 'cli_creator1.json'),
        JSON.stringify({ larkAppId: 'cli_creator1', ipcPort: daemonPort, lastHeartbeat: nowMs, resolvedAllowedUsers: [] }),
        { mode: 0o600 },
      );
    await refreshDaemonHeartbeat();

    try {
      const stateStore = new StateStore(pluginHome);
      const cfg = applyConfigPatch(
        createDefaultConfig(),
        {
          github: { mode: 'pat', apiBaseUrl: `http://127.0.0.1:${ghPort}`, pat: 'github_pat_cap1234567890abcdef' },
          service: { maxGroupCreatesPerRepoPerHour: 1 },
          repos: [makeRule()],
        },
        { allowInsecureLocalApiForTests: true },
      );
      const watcher = new GitHubWatcher({
        config: cfg,
        stateStore,
        discovery: { botmuxHome, dataDir, now: () => nowMs },
        allowInsecureLocalApiForTests: true,
        now: () => nowMs,
      });

      // Empty baseline
      await watcher.sync();

      // Both PR #1 and PR #2 open together -> cap=1 creates PR #1 and defers PR #2!
      openPrs = [makeRawPr({ number: 1 }), makeRawPr({ number: 2 })];
      etag = '"cap-v1"';
      const poll1 = await watcher.sync();
      assert.equal(createdGroups.length, 1);
      assert.ok(poll1.actions.some(a => a.prNumber === 2 && a.action === 'skip_rate_limited'));

      const stAfterCap = await stateStore.load();
      assert.equal(stAfterCap.repos['acme/r2']?.knownPrs['2'], undefined, 'Capped PR #2 MUST NOT be committed to knownPrs');
      assert.equal(stAfterCap.repos['acme/r2']?.etag, undefined, 'ETag MUST NOT advance while a PR is deferred by cap');

      // Advance fake clock by 1 hour + 1 second (ETag unchanged!) -> next poll creates PR #2's group!
      nowMs += 3_601_000;
      await refreshDaemonHeartbeat();
      const pollAfterHour = await watcher.sync();
      assert.equal(pollAfterHour.ok, true);
      assert.equal(createdGroups.length, 2, 'Deferred PR #2 MUST be created once hourly cap expires');
      assert.equal((await stateStore.load()).prGroups['acme/r2#2']?.status, 'active');
    } finally {
      await Promise.all([
        new Promise<void>(r => ghServer.close(() => r())),
        new Promise<void>(r => daemonServer.close(() => r())),
      ]);
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[P1-4 & P1-5] saveSettings fails closed on invalid existing config (never wipes PAT/rules) and preserves proxy.url userinfo credentials on unrelated saves', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-r2-p1-45-'));
    const pluginHome = join(tmp, 'plugin');
    await fsp.mkdir(pluginHome, { recursive: true, mode: 0o700 });
    const settingsMod = await import(pathToFileURL(join(rootDir, 'dist', 'server', 'settings.js')).href);

    try {
      // P1-4: Existing config has PAT + 1 enabled rule + invalid service.port=0 -> saveSettings MUST fail closed!
      let brokenStored: Record<string, unknown> = {
        schemaVersion: 1,
        github: { mode: 'pat', apiBaseUrl: 'https://api.github.com', pat: 'github_pat_keepMeSafe1234567890abcdef', app: { appId: '', installationId: '' } },
        proxy: { url: '' },
        webhook: { enabled: false },
        service: { port: 0, pollIntervalSec: 60 },
        repos: [makeRule()],
      };
      let replaceCalled = false;
      const brokenApi = {
        config: {
          path: join(pluginHome, 'config.json'),
          get: () => brokenStored,
          set: () => {},
          replace: (v: Record<string, unknown>) => {
            replaceCalled = true;
            brokenStored = v;
          },
        },
      };
      const resBroken = await settingsMod.saveSettings(
        brokenApi,
        { action: 'saveConfig', patch: { service: { pollIntervalSec: 120 } } },
      );
      assert.equal(resBroken.ok, false, 'Invalid existing config MUST fail closed');
      assert.equal(replaceCalled, false, 'Must NEVER overwrite invalid existing config with defaults');

      // P1-5: Existing config has credentials ONLY inside proxy.url userinfo -> Dashboard saves redacted proxy + pollIntervalSec -> credentials preserved!
      let proxyStored: Record<string, unknown> = {
        schemaVersion: 1,
        github: { mode: 'auto', apiBaseUrl: 'https://api.github.com', app: { appId: '', installationId: '' } },
        proxy: { url: 'http://alice:secretPass123@proxy.example:8080' },
        webhook: { enabled: false },
        service: { port: 18940, pollIntervalSec: 60 },
        repos: [],
      };
      const proxyApi = {
        config: {
          path: join(pluginHome, 'proxy-config.json'),
          get: () => proxyStored,
          set: () => {},
          replace: (v: Record<string, unknown>) => {
            proxyStored = v;
          },
        },
      };

      const initialGet = await settingsMod.getSettings(proxyApi);
      assert.equal(initialGet.config.proxy.url, 'http://proxy.example:8080');
      assert.equal(initialGet.config.proxy.username, 'alice');
      assert.equal(initialGet.config.proxy.hasPassword, true);

      // Simulate Dashboard submitting redacted URL + blank username + omitted password
      const saved = await settingsMod.saveSettings(proxyApi, {
        action: 'saveConfig',
        patch: {
          proxy: { url: 'http://proxy.example:8080', username: '' },
          service: { pollIntervalSec: 120 },
        },
      });
      assert.equal(saved.ok, true);
      assert.equal(saved.config.proxy.hasPassword, true, 'Proxy password from original URL userinfo MUST be preserved');
      assert.equal(saved.config.proxy.username, 'alice', 'Proxy username from original URL userinfo MUST be preserved');
      const savedProxy = (proxyStored as { proxy: { url: string; username?: string; password?: string } }).proxy;
      assert.equal(savedProxy.url, 'http://proxy.example:8080');
      assert.equal(savedProxy.username, 'alice');
      assert.equal(savedProxy.password, 'secretPass123');
      assert.equal(redactConfig(proxyStored as never).proxy.hasPassword, true);

      // Partial patch WITHOUT proxy.url can still clearPassword or edit username on a URL-userinfo config!
      const rawUserinfoCfg = applyConfigPatch(createDefaultConfig(), { service: { pollIntervalSec: 60 } });
      rawUserinfoCfg.proxy = { url: 'http://alice:oldSecret@proxy.example:8080' };
      const clearedPw = applyConfigPatch(rawUserinfoCfg, { proxy: { clearPassword: true } });
      assert.equal(clearedPw.proxy.password, undefined);
      assert.equal(clearedPw.proxy.username, 'alice');
      assert.equal(clearedPw.proxy.url, 'http://proxy.example:8080');
      const renamedUser = applyConfigPatch(rawUserinfoCfg, { proxy: { username: 'bob' } });
      assert.equal(renamedUser.proxy.username, 'bob');
      assert.equal(renamedUser.proxy.password, 'oldSecret');

      // Wrong-typed config section (e.g. proxy as string or repos as object) MUST fail closed!
      let wrongSectionStored: Record<string, unknown> = {
        schemaVersion: 1,
        github: { pat: 'github_pat_safe1234567890abcdef' },
        proxy: 'http://alice:secret@proxy.example:8080',
        repos: { '0': makeRule() },
      };
      const wrongSectionRes = await settingsMod.saveSettings(
        {
          config: {
            path: join(pluginHome, 'wrong-section.json'),
            get: () => wrongSectionStored,
            set: () => {},
            replace: (v: Record<string, unknown>) => {
              wrongSectionStored = v;
            },
          },
        },
        { action: 'saveConfig', patch: { service: { pollIntervalSec: 90 } } },
      );
      assert.equal(wrongSectionRes.ok, false);
    } finally {
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[P2-1] corrupt state.json fails closed with StateCorruptError and never overwrites original file', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-r2-p2-1-'));
    try {
      const store = new StateStore(tmp);
      await store.update(s => {
        s.prGroups['acme/r2#1'] = {
          status: 'active',
          repo: 'acme/r2',
          prNumber: 1,
          chatId: 'oc_original',
          groupName: 'PR #1',
          creatorLarkAppId: 'cli_creator1',
          topNoticeSet: true,
          lastHeadSha: 'a'.repeat(40),
          createdAt: '2026-11-26T00:00:00Z',
          updatedAt: '2026-11-26T00:00:00Z',
        };
      });
      // Corrupt state.json on disk
      const corruptBytes = '{"schemaVersion":1,"prGroups": CORRUPT_JSON';
      await fsp.writeFile(store.statePath, corruptBytes, { mode: 0o600 });

      await assert.rejects(() => store.load(), StateCorruptError);
      await assert.rejects(
        () =>
          store.update(s => {
            s.prGroups['acme/r2#2'] = {} as never;
          }),
        StateCorruptError,
      );
      // Original corrupt file MUST remain untouched on disk (not overwritten with empty state!)
      assert.equal(await fsp.readFile(store.statePath, 'utf8'), corruptBytes);

      // Valid JSON object with wrong-typed top-level prGroups MUST ALSO fail closed with StateCorruptError!
      const badTyped = JSON.stringify({ schemaVersion: 1, prGroups: 'corrupt', repos: [] });
      await fsp.writeFile(store.statePath, badTyped, { mode: 0o600 });
      await assert.rejects(() => store.load(), StateCorruptError);
    } finally {
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[P2-2] manual sync waiting on in-flight poll re-reads live disabled rule after reload and creates zero groups', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-r2-p2-2-'));
    const pluginHome = join(tmp, 'plugin');

    let ghCalls = 0;
    let releaseBlockedPoll!: () => void;
    const pollGate = new Promise<void>(r => {
      releaseBlockedPoll = r;
    });
    let pollStarted!: () => void;
    const reachedPoll = new Promise<void>(r => {
      pollStarted = r;
    });

    const ghServer = http.createServer(async (_req, res) => {
      ghCalls++;
      if (ghCalls === 1) {
        pollStarted();
        await pollGate;
      }
      if (!res.destroyed) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify([makeRawPr({ number: 9 })]));
      }
    });
    await new Promise<void>(r => ghServer.listen(0, '127.0.0.1', () => r()));
    const ghPort = (ghServer.address() as { port: number }).port;

    try {
      const stateStore = new StateStore(pluginHome);
      await stateStore.update(s => {
        s.repos['acme/r2'] = { baselineCapturedAt: '2026-11-26T00:00:00Z', knownPrs: {} };
      });
      const activeCfg = applyConfigPatch(
        createDefaultConfig(),
        {
          github: { mode: 'pat', apiBaseUrl: `http://127.0.0.1:${ghPort}`, pat: 'github_pat_p22_token1234567890abcdef' },
          repos: [makeRule()],
        },
        { allowInsecureLocalApiForTests: true },
      );
      const dormantCfg = applyConfigPatch(
        activeCfg,
        { repos: [makeRule({ enabled: false })] },
        { allowInsecureLocalApiForTests: true },
      );

      const watcher = new GitHubWatcher({ config: activeCfg, stateStore, allowInsecureLocalApiForTests: true });
      await watcher.start();
      await reachedPoll;

      // Launch manual sync while initial poll is blocked in-flight
      const manualSyncPromise = watcher.sync();
      await new Promise(r => setTimeout(r, 30));

      // Disable repo and reload -> mode becomes dormant!
      assert.equal(await watcher.reloadConfig(dormantCfg), 'dormant');
      releaseBlockedPoll();

      const manualRes = await manualSyncPromise;
      assert.equal(manualRes.mode, 'dormant');
      assert.deepEqual(manualRes.actions, [], 'Manual sync MUST NOT create groups after repo was disabled during wait');
      assert.equal(ghCalls, 1, 'Manual sync MUST NOT initiate a fresh GitHub call after repo was disabled');
      await watcher.stop();
    } finally {
      await new Promise<void>(r => ghServer.close(() => r()));
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[P2-3] postShareLinkToPr paginates past comment #100 to detect existing marker on page 2 without duplicate posting', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-r2-p2-3-'));
    const pluginHome = join(tmp, 'plugin');
    const botmuxHome = join(tmp, 'botmux');
    const dataDir = join(tmp, 'data');
    const daemonsDir = join(dataDir, 'dashboard-daemons');
    await fsp.mkdir(daemonsDir, { recursive: true, mode: 0o700 });
    await fsp.mkdir(botmuxHome, { recursive: true, mode: 0o700 });
    const dashSecret = 'r'.repeat(43);
    await fsp.writeFile(join(botmuxHome, '.dashboard-secret'), `${dashSecret}\n`, { mode: 0o600 });
    await fsp.writeFile(join(botmuxHome, 'bots.json'), JSON.stringify([{ larkAppId: 'cli_creator1', larkAppSecret: 's1', brand: 'feishu' }]), { mode: 0o600 });

    const marker = '<!-- botmux-plugin-github:share-link:oc_c101 -->';
    const pagesVisited: number[] = [];
    let postCommentCalls = 0;

    const ghServer = http.createServer((req, res) => {
      if (req.method === 'GET' && req.url?.includes('/issues/33/comments')) {
        const u = new URL(req.url, 'http://127.0.0.1');
        const page = Number(u.searchParams.get('page') ?? '1');
        pagesVisited.push(page);
        if (page === 1) {
          const page1 = Array.from({ length: 100 }, (_, i) => ({
            id: i + 1,
            body: `Normal comment #${i + 1}`,
            html_url: `https://github.com/acme/r2/pull/33#issuecomment-${i + 1}`,
            user: { login: 'reviewer' },
          }));
          res.writeHead(200, {
            'Content-Type': 'application/json',
            Link: '<http://127.0.0.1/issues/33/comments?per_page=100&page=2>; rel="next"',
          });
          res.end(JSON.stringify(page1));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify([
            {
              id: 101,
              body: `Join review group\n${marker}`,
              html_url: 'https://github.com/acme/r2/pull/33#issuecomment-101',
              user: { login: 'bot' },
            },
          ]),
        );
        return;
      }
      if (req.method === 'POST' && req.url?.includes('/issues/33/comments')) {
        postCommentCalls++;
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: 999, body: '' }));
        return;
      }
      res.writeHead(404);
      res.end('{}');
    });

    let daemonPort = 0;
    const seenNonces = new Map<string, number>();
    const daemonServer = http.createServer((req, res) => {
      verifyDaemonIpcHeaders(req.headers, dashSecret, req.method ?? 'GET', req.url ?? '/', daemonPort, seenNonces);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    });

    await Promise.all([
      new Promise<void>(r => ghServer.listen(0, '127.0.0.1', () => r())),
      new Promise<void>(r => daemonServer.listen(0, '127.0.0.1', () => r())),
    ]);
    const ghPort = (ghServer.address() as { port: number }).port;
    daemonPort = (daemonServer.address() as { port: number }).port;
    await fsp.writeFile(
      join(daemonsDir, 'cli_creator1.json'),
      JSON.stringify({ larkAppId: 'cli_creator1', ipcPort: daemonPort, lastHeartbeat: Date.now(), resolvedAllowedUsers: [] }),
      { mode: 0o600 },
    );

    try {
      const stateStore = new StateStore(pluginHome);
      await stateStore.update(s => {
        s.prGroups['acme/r2#33'] = {
          status: 'creating',
          repo: 'acme/r2',
          prNumber: 33,
          chatId: 'oc_c101',
          groupName: 'PR #33 acme/r2 - Comments test',
          creatorLarkAppId: 'cli_creator1',
          shareLink: 'https://applink.feishu.cn/client/chat/open?openChatId=oc_c101',
          kickoffMessageId: 'om_33',
          kickoffVerified: true,
          topNoticeSet: true,
          shareLinkPosted: false,
          lastHeadSha: 'a'.repeat(40),
          createdAt: '2026-11-26T00:00:00Z',
          updatedAt: '2026-11-26T00:00:00Z',
        };
      });

      const ghClient = new GitHubClient({
        auth: { mode: 'pat', apiBaseUrl: `http://127.0.0.1:${ghPort}`, pat: 'github_pat_p23_token1234567890abcdef', app: { appId: '', installationId: '' } },
        allowInsecureLocalForTests: true,
      });
      const bridge = new HostBridge({ stateStore, discovery: { botmuxHome, dataDir } });

      const res = await bridge.ensurePrReviewGroup({
        rule: makeRule({ postShareLinkToPr: true }),
        pr: makePrInfo({ number: 33 }),
        githubClient: ghClient,
      });
      assert.equal(res.record.shareLinkPosted, true);
      assert.equal(res.record.shareLinkCommentId, 101);
      assert.deepEqual(pagesVisited, [1, 2], 'Must paginate to page 2 to discover existing share-link marker');
      assert.equal(postCommentCalls, 0, 'Must NOT post a duplicate comment when marker exists on page 2');
    } finally {
      await Promise.all([
        new Promise<void>(r => ghServer.close(() => r())),
        new Promise<void>(r => daemonServer.close(() => r())),
      ]);
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[P2-4] Dashboard rejects malformed PR spec owner/repo#12junk without calling /api/open-pr', async () => {
    const dashMod = await import(pathToFileURL(join(rootDir, 'dist', 'dashboard', 'index.js')).href);
    const states: unknown[] = [];
    let openPrCalled = false;

    const findElements = (node: unknown, pred: (el: { type: unknown; props: Record<string, unknown>; children: unknown[] }) => boolean): Array<{ type: unknown; props: Record<string, unknown>; children: unknown[] }> => {
      const out: Array<{ type: unknown; props: Record<string, unknown>; children: unknown[] }> = [];
      if (!node || typeof node !== 'object') return out;
      if (Array.isArray(node)) {
        for (const item of node) out.push(...findElements(item, pred));
        return out;
      }
      const el = node as { type?: unknown; props?: Record<string, unknown>; children?: unknown[] };
      if (el.type !== undefined) {
        const entry = { type: el.type, props: el.props ?? {}, children: el.children ?? [] };
        if (pred(entry)) out.push(entry);
        for (const ch of entry.children) out.push(...findElements(ch, pred));
      }
      return out;
    };

    const renderOnce = () => {
      let hookIdx = 0;
      const mockReact = {
        createElement: (type: unknown, props: Record<string, unknown> | null, ...children: unknown[]) => ({
          type,
          props: props ?? {},
          children,
        }),
        useState: <T,>(init: T | (() => T)) => {
          const i = hookIdx++;
          if (i >= states.length) {
            states[i] = typeof init === 'function' ? (init as () => T)() : init;
          }
          const setter = (next: T | ((prev: T) => T)) => {
            states[i] = typeof next === 'function' ? (next as (prev: T) => T)(states[i] as T) : next;
          };
          return [states[i] as T, setter] as [T, (next: T | ((prev: T) => T)) => void];
        },
        useEffect: () => {},
        useCallback: <T,>(fn: T) => fn,
        useMemo: <T,>(fn: () => T) => fn(),
      };

      return dashMod.default({
        pluginId: 'github',
        api: {
          react: mockReact,
          getSettings: async () => ({ ok: true }),
          saveSettings: async (v: Record<string, unknown>) => {
            if (v.action === 'openPr') openPrCalled = true;
            return { ok: true };
          },
          listBots: async () => [],
          serviceFetch: async (path: string) => {
            if (path === '/api/open-pr') openPrCalled = true;
            return { ok: true, status: 200, json: async () => ({ ok: true }) };
          },
        },
      });
    };

    const tree1 = renderOnce();
    const prInputs = findElements(tree1, el => el.type === 'input' && el.props.placeholder === 'owner/repo#123');
    assert.equal(prInputs.length, 1);
    (prInputs[0]!.props.onChange as (e: { target: { value: string } }) => void)({ target: { value: 'owner/repo#12junk' } });

    const tree2 = renderOnce();
    const openBtns = findElements(
      tree2,
      el => el.type === 'button' && el.props['data-action'] === 'open-pr',
    );
    assert.equal(openBtns.length, 1);
    await (openBtns[0]!.props.onClick as () => Promise<void>)();

    assert.equal(openPrCalled, false, 'Dashboard MUST reject owner/repo#12junk without invoking /api/open-pr');
    const tree3 = renderOnce();
    const hasErrText = JSON.stringify(tree3).includes('PR 编号必须是正整数');
    assert.equal(hasErrText, true);
  });

  it('[P2-5] per-PR lock is NOT stolen from a live owner PID even when fake clock advances past staleMs (90s+)', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-r2-p2-5-'));
    try {
      let fakeNow = 1_700_000_000_000;
      const lockPath = join(tmp, 'pr.lock');
      const lock1 = await acquireSecureLock(lockPath, {
        timeoutMs: 1_000,
        staleMs: 90_000,
        heartbeatIntervalMs: 0,
        now: () => fakeNow,
      });

      // Jump clock 120 seconds past staleMs while owner PID (process.pid) is STILL ALIVE!
      fakeNow += 120_000;
      await assert.rejects(
        () =>
          acquireSecureLock(lockPath, {
            timeoutMs: 150,
            staleMs: 90_000,
            pollMs: 25,
            heartbeatIntervalMs: 0,
            now: () => fakeNow,
          }),
        (err: unknown) => err instanceof SecurityFsError && err.code === 'LOCK_TIMEOUT',
      );
      assert.equal(await lock1.verifyOwned(), true, 'Live owner must still own the lock');
      await lock1.release();

      // Concurrent renew() + release() MUST NOT resurrect an orphaned lockfile!
      const lock3 = await acquireSecureLock(lockPath, { timeoutMs: 500, heartbeatIntervalMs: 0, now: () => fakeNow });
      await Promise.all([lock3.renew(), lock3.release()]);
      const existsAfterRace = await fsp.stat(lockPath).then(() => true, () => false);
      assert.equal(existsAfterRace, false, 'Concurrent renew() + release() must NEVER resurrect lockfile');
    } finally {
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[P2-6] definite CLI pre-create error clears outcomeUnknown so retry succeeds, while ambiguous CLI failure stays fail-closed', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-r2-p2-6-'));
    const pluginHome = join(tmp, 'plugin');
    const botmuxHome = join(tmp, 'botmux');
    const dataDir = join(tmp, 'data');
    await fsp.mkdir(botmuxHome, { recursive: true, mode: 0o700 });
    await fsp.mkdir(dataDir, { recursive: true, mode: 0o700 });
    await fsp.writeFile(join(botmuxHome, 'bots.json'), JSON.stringify([{ larkAppId: 'cli_creator1', larkAppSecret: 's1', brand: 'feishu' }]), { mode: 0o600 });

    const ghClient = new GitHubClient({
      auth: { mode: 'pat', apiBaseUrl: 'http://127.0.0.1:1', pat: 'github_pat_p26_token1234567890abcdef', app: { appId: '', installationId: '' } },
      allowInsecureLocalForTests: true,
    });

    try {
      const stateStore = new StateStore(pluginHome);
      let cliCalls = 0;
      const bridge = new HostBridge({
        stateStore,
        discovery: { botmuxHome, dataDir },
        cliExec: async () => {
          cliCalls++;
          if (cliCalls === 1) {
            return {
              exitCode: 1,
              stdout: '',
              stderr: '--working-dir Directory does not exist: /definitely-absent\n',
            };
          }
          return {
            exitCode: 0,
            stdout: 'oc_cli_retry_ok\n{"success":true,"chatCreated":true,"chatId":"oc_cli_retry_ok"}\n',
            stderr: '',
          };
        },
      });

      const rule = makeRule({ kickoffBotAppId: undefined, setTopNotice: false });
      const pr60 = makePrInfo({ number: 60 });

      // Attempt 1: definite pre-create failure -> clears createAttempt.outcomeUnknown!
      await assert.rejects(() => bridge.ensurePrReviewGroup({ rule, pr: pr60, githubClient: ghClient }), /working-dir/);
      assert.equal((await stateStore.load()).prGroups['acme/r2#60']?.createAttempt, undefined);

      // Attempt 2: retry succeeds cleanly!
      const okRes = await bridge.ensurePrReviewGroup({ rule, pr: pr60, githubClient: ghClient });
      assert.equal(okRes.record.chatId, 'oc_cli_retry_ok');
      assert.equal(cliCalls, 2);

      // Ambiguous CLI failure (no proof chat.create wasn't called) MUST remain fail-closed!
      let ambCalls = 0;
      const ambBridge = new HostBridge({
        stateStore,
        discovery: { botmuxHome, dataDir },
        cliExec: async () => {
          ambCalls++;
          return { exitCode: 137, stdout: '', stderr: 'Killed' };
        },
      });
      const pr61 = makePrInfo({ number: 61 });
      await assert.rejects(() => ambBridge.ensurePrReviewGroup({ rule, pr: pr61, githubClient: ghClient }));
      assert.equal((await stateStore.load()).prGroups['acme/r2#61']?.createAttempt?.outcomeUnknown, true);
      await assert.rejects(
        () => ambBridge.ensurePrReviewGroup({ rule, pr: pr61, githubClient: ghClient }),
        /unknown outcome/i,
      );
      assert.equal(ambCalls, 1, 'Ambiguous CLI failure must stay fail-closed on retry');
    } finally {
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[P2-7] active->active reload does NOT silently drop an already-202-accepted queued webhook', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-r2-p2-7-'));
    const pluginHome = join(tmp, 'plugin');
    const botmuxHome = join(tmp, 'botmux');
    const dataDir = join(tmp, 'data');
    const daemonsDir = join(dataDir, 'dashboard-daemons');
    await fsp.mkdir(daemonsDir, { recursive: true, mode: 0o700 });
    await fsp.mkdir(botmuxHome, { recursive: true, mode: 0o700 });
    const dashSecret = 'w'.repeat(43);
    await fsp.writeFile(join(botmuxHome, '.dashboard-secret'), `${dashSecret}\n`, { mode: 0o600 });
    await fsp.writeFile(join(botmuxHome, 'bots.json'), JSON.stringify([{ larkAppId: 'cli_creator1', larkAppSecret: 's1', brand: 'feishu' }]), { mode: 0o600 });

    let closeMessagesSent = 0;
    let daemonPort = 0;
    const seenNonces = new Map<string, number>();
    const daemonServer = http.createServer((req, res) => {
      verifyDaemonIpcHeaders(req.headers, dashSecret, req.method ?? 'GET', req.url ?? '/', daemonPort, seenNonces);
      const chunks: Buffer[] = [];
      req.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      req.on('end', () => {
        const body = chunks.length > 0 ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
        if (req.method === 'POST' && req.url === '/api/groups/oc_70/messages') {
          closeMessagesSent++;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, chatId: 'oc_70', messageId: 'om_cl70', requestId: body.requestId, replayed: false }));
          return;
        }
        res.writeHead(404);
        res.end('{}');
      });
    });
    const ghServer = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json', ETag: '"e70"' });
      res.end('[]');
    });
    await Promise.all([
      new Promise<void>(r => daemonServer.listen(0, '127.0.0.1', () => r())),
      new Promise<void>(r => ghServer.listen(0, '127.0.0.1', () => r())),
    ]);
    daemonPort = (daemonServer.address() as { port: number }).port;
    const ghPort = (ghServer.address() as { port: number }).port;
    await fsp.writeFile(
      join(daemonsDir, 'cli_creator1.json'),
      JSON.stringify({ larkAppId: 'cli_creator1', ipcPort: daemonPort, lastHeartbeat: Date.now(), resolvedAllowedUsers: [] }),
      { mode: 0o600 },
    );

    const stateStore = new StateStore(pluginHome);
    await stateStore.update(s => {
      s.repos['acme/r2'] = {
        baselineCapturedAt: '2026-11-26T00:00:00Z',
        knownPrs: { '70': { headSha: 'a'.repeat(40), draft: false, state: 'open', updatedAt: '2026-11-26T00:00:00Z' } },
      };
      s.prGroups['acme/r2#70'] = {
        status: 'active',
        repo: 'acme/r2',
        prNumber: 70,
        chatId: 'oc_70',
        groupName: 'PR #70',
        creatorLarkAppId: 'cli_creator1',
        kickoffMessageId: 'om_k70',
        kickoffVerified: true,
        topNoticeSet: true,
        lifecycleGeneration: 1,
        lastHeadSha: 'a'.repeat(40),
        createdAt: '2026-11-26T00:00:00Z',
        updatedAt: '2026-11-26T00:00:00Z',
      };
    });

    const cfg1 = applyConfigPatch(
      createDefaultConfig(),
      {
        github: { mode: 'pat', apiBaseUrl: `http://127.0.0.1:${ghPort}`, pat: 'github_pat_p27_token1234567890abcdef' },
        webhook: { enabled: true, secret: WH_SECRET },
        service: { pollIntervalSec: 60 },
        repos: [makeRule({ onPrClosed: true })],
      },
      { allowInsecureLocalApiForTests: true },
    );
    await savePluginConfig(pluginHome, cfg1, { allowInsecureLocalApiForTests: true });

    const svc = await startGitHubService({
      pluginHome,
      port: 0,
      discovery: { botmuxHome, dataDir },
      allowInsecureLocalApiForTests: true,
    });

    try {
      // Queue a blocker on PR #70 first
      let releaseBlocker!: () => void;
      const blocker = new Promise<void>(r => {
        releaseBlocker = r;
      });
      const q = (svc.watcher as unknown as { queue: { enqueue: (k: string, fn: () => Promise<void>) => Promise<void> } }).queue;
      const blockerDone = q.enqueue('acme/r2#70', async () => blocker);

      // Deliver signed `closed` webhook while PR #70 is blocked -> HTTP 202 Accepted!
      const body = Buffer.from(
        JSON.stringify({
          action: 'closed',
          repository: { full_name: 'acme/r2' },
          pull_request: makeRawPr({ number: 70, state: 'closed', merged: true }),
        }),
        'utf8',
      );
      const whResp = await loopbackRequest({
        port: svc.port,
        method: 'POST',
        path: '/webhooks/github',
        headers: {
          Host: `127.0.0.1:${svc.port}`,
          'Content-Type': 'application/json',
          'X-GitHub-Event': 'pull_request',
          'X-GitHub-Delivery': 'd-close-70-active-reload',
          'X-Hub-Signature-256': signWebhook(body),
        },
        body,
      });
      assert.equal(whResp.status, 202);

      // Perform active->active reload (changing pollIntervalSec 60 -> 61) while webhook is still queued!
      const cfg2 = applyConfigPatch(cfg1, { service: { pollIntervalSec: 61 } }, { allowInsecureLocalApiForTests: true });
      await savePluginConfig(pluginHome, cfg2, { allowInsecureLocalApiForTests: true });
      const reloadRes = await svc.reload();
      assert.equal(reloadRes.ok, true);
      assert.equal(reloadRes.mode, 'active');

      // Release blocker -> already-202-accepted `closed` webhook MUST still execute to full completion!
      releaseBlocker();
      await blockerDone;
      await waitFor(async () => Boolean((await stateStore.load()).processedDeliveries['d-close-70-active-reload']));
      const st = await stateStore.load();
      assert.equal(st.prGroups['acme/r2#70']?.status, 'closed');
      assert.equal(st.repos['acme/r2']?.knownPrs['70']?.state, 'closed');
      assert.ok(st.processedDeliveries['d-close-70-active-reload']);
      assert.equal(closeMessagesSent, 1);
    } finally {
      await svc.close();
      await Promise.all([
        new Promise<void>(r => daemonServer.close(() => r())),
        new Promise<void>(r => ghServer.close(() => r())),
      ]);
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[P3] exact 100-PR repo with empty page 2 persists pageCount=1 and stops hitting page 2 on subsequent 304 polls', async () => {
    let page1Calls = 0;
    let page2Calls = 0;
    const hundredPrs = Array.from({ length: 100 }, (_, i) => makeRawPr({ number: i + 1 }));

    const ghServer = http.createServer((req, res) => {
      if (req.url?.includes('&page=1')) {
        page1Calls++;
        if (req.headers['if-none-match'] === '"exact-100-p1"') {
          res.writeHead(304, { ETag: '"exact-100-p1"' });
          res.end();
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json', ETag: '"exact-100-p1"' });
        res.end(JSON.stringify(hundredPrs));
        return;
      }
      if (req.url?.includes('&page=2')) {
        page2Calls++;
        res.writeHead(200, { 'Content-Type': 'application/json', ETag: '"empty-p2"' });
        res.end('[]');
        return;
      }
      res.writeHead(404);
      res.end('{}');
    });
    await new Promise<void>(r => ghServer.listen(0, '127.0.0.1', () => r()));
    const ghPort = (ghServer.address() as { port: number }).port;

    try {
      const client = new GitHubClient({
        auth: { mode: 'pat', apiBaseUrl: `http://127.0.0.1:${ghPort}`, pat: 'github_pat_p3_exact100_1234567890', app: { appId: '', installationId: '' } },
        allowInsecureLocalForTests: true,
      });

      const r1 = await client.listOpenPullRequests('acme', 'r2');
      assert.equal(r1.pulls.length, 100);
      assert.equal(r1.pageCount, 1, 'Empty terminal page 2 MUST NOT be counted in pageCount');
      assert.equal(page1Calls, 1);
      assert.equal(page2Calls, 1);

      const r2 = await client.listOpenPullRequests('acme', 'r2', {
        persistedEtag: r1.etag,
        persistedEtagKey: r1.etagKey,
        previousPageCount: r1.pageCount,
      });
      assert.equal(r2.notModified, true);
      assert.equal(r2.pageCount, 1);

      const r3 = await client.listOpenPullRequests('acme', 'r2', {
        persistedEtag: r2.etag,
        persistedEtagKey: r2.etagKey,
        previousPageCount: r2.pageCount,
      });
      assert.equal(r3.notModified, true);
      assert.equal(page1Calls, 3);
      assert.equal(page2Calls, 1, 'Subsequent 304 polls on exact-100 repo MUST NOT hit empty page 2');
    } finally {
      await new Promise<void>(r => ghServer.close(() => r()));
    }
  });
});

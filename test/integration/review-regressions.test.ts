import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHmac } from 'node:crypto';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { PullRequestInfo, RepoRule } from '../../src/types.ts';
import { applyConfigPatch, createDefaultConfig } from '../../src/config/schema.ts';
import { ensureControlToken, savePluginConfig } from '../../src/config/store.ts';
import { StateStore } from '../../src/state/store.ts';
import { GitHubClient } from '../../src/github/client.ts';
import { HostBridge } from '../../src/host/bridge.ts';
import { GitHubWatcher } from '../../src/engine/watcher.ts';
import { PerPrSerialQueue } from '../../src/engine/queue.ts';
import { DeliveryDedupCache } from '../../src/engine/webhook.ts';
import { startGitHubService } from '../../src/service/runner.ts';
import { loopbackRequest } from '../../src/security/net.ts';
import { verifyDaemonIpcHeaders } from '../../src/host/discovery.ts';

const rootDir = resolve(import.meta.dirname, '..', '..');
const WH_SECRET = 'whsec_RegTestSecret_1234567890ABCDEFGH';

function makeRawPr(opts: {
  repo: string;
  number: number;
  title?: string;
  headSha?: string;
  draft?: boolean;
  state?: 'open' | 'closed';
  merged?: boolean;
}) {
  return {
    number: opts.number,
    title: opts.title ?? `PR #${opts.number}`,
    body: `Body for #${opts.number}`,
    state: opts.state ?? 'open',
    draft: opts.draft === true,
    merged: opts.merged === true,
    html_url: `https://github.com/${opts.repo}/pull/${opts.number}`,
    user: { login: 'alice' },
    base: { ref: 'main', repo: { full_name: opts.repo } },
    head: {
      ref: `feat/pr-${opts.number}`,
      sha: opts.headSha ?? 'a'.repeat(40),
      repo: { full_name: opts.repo, fork: false },
    },
    labels: [],
    maintainer_can_modify: true,
    created_at: '2026-11-25T00:00:00Z',
    updated_at: '2026-11-25T00:01:00Z',
  };
}

function makePrInfo(opts: {
  repo?: string;
  number: number;
  title?: string;
  headSha?: string;
  draft?: boolean;
  state?: 'open' | 'closed';
  merged?: boolean;
}): PullRequestInfo {
  const repo = opts.repo ?? 'acme/reg';
  return {
    repo,
    number: opts.number,
    title: opts.title ?? `PR #${opts.number}`,
    body: `Body for #${opts.number}`,
    state: opts.state ?? 'open',
    draft: opts.draft === true,
    merged: opts.merged === true,
    htmlUrl: `https://github.com/${repo}/pull/${opts.number}`,
    author: 'alice',
    baseBranch: 'main',
    headBranch: `feat/pr-${opts.number}`,
    headSha: opts.headSha ?? 'a'.repeat(40),
    headRepoFullName: repo,
    labels: [],
    isFork: false,
    maintainerCanModify: true,
    createdAt: '2026-11-25T00:00:00Z',
    updatedAt: '2026-11-25T00:01:00Z',
  };
}

function makeRule(overrides: Partial<RepoRule> = {}): RepoRule {
  return {
    id: 'acme/reg',
    repo: 'acme/reg',
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

async function waitFor(pred: () => Promise<boolean> | boolean, timeoutMs = 4000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await pred()) return;
    await new Promise(r => setTimeout(r, 25));
  }
  throw new Error(`Timed out after ${timeoutMs}ms`);
}

function signWebhook(body: Buffer, secret = WH_SECRET): string {
  return `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;
}

describe('PR #1 Review Regressions (P1 + P2 + P3)', () => {
  it('[P1 #1] webhook does not prematurely commit knownPrs on pre-create failure OR unknown-PR synchronize; subsequent poll recovers group', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-reg-1-'));
    const pluginHome = join(tmp, 'plugin');
    const botmuxHome = join(tmp, 'botmux');
    const dataDir = join(tmp, 'data');
    const daemonsDir = join(dataDir, 'dashboard-daemons');
    await fsp.mkdir(daemonsDir, { recursive: true, mode: 0o700 });
    await fsp.mkdir(botmuxHome, { recursive: true, mode: 0o700 });

    const dashSecret = 'a'.repeat(43);
    await fsp.writeFile(join(botmuxHome, '.dashboard-secret'), `${dashSecret}\n`, { mode: 0o600 });
    // Start with CORRUPT bots.json so loadBotsConfig fails before `creating` lock is persisted!
    await fsp.writeFile(join(botmuxHome, 'bots.json'), '{CORRUPT_JSON', { mode: 0o600 });

    let openPrs: Array<ReturnType<typeof makeRawPr>> = [];
    const createdGroups: Array<{ chatId: string; name: string; kickoffPrompt: string }> = [];
    let chatSeq = 0;
    let msgSeq = 0;

    const ghServer = http.createServer((req, res) => {
      if (req.url?.startsWith('/repos/acme/reg/pulls?')) {
        res.writeHead(200, { 'Content-Type': 'application/json', ETag: `"etag-${openPrs.length}"` });
        res.end(JSON.stringify(openPrs));
        return;
      }
      res.writeHead(404);
      res.end('{}');
    });

    const seenNonces = new Map<string, number>();
    let daemonPort = 0;
    const daemonServer = http.createServer((req, res) => {
      verifyDaemonIpcHeaders(req.headers, dashSecret, req.method ?? 'GET', req.url ?? '/', daemonPort, seenNonces);
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
          const chatId = `oc_rec_${++chatSeq}`;
          const kickoffMessageId = `om_rec_${++msgSeq}`;
          createdGroups.push({ chatId, name: body.name, kickoffPrompt: body.kickoffPrompt });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, chatId, kickoffMessageId, kickoffError: null }));
          return;
        }
        const readMatch = /^\/api\/groups\/(oc_[^/]+)\/messages\/(om_[^/]+)$/.exec(req.url ?? '');
        if (req.method === 'GET' && readMatch) {
          const g = createdGroups.find(x => x.chatId === readMatch[1]);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, messageId: readMatch[2], chatId: readMatch[1], deleted: false, text: g?.kickoffPrompt ?? '' }));
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
    await fsp.writeFile(
      join(daemonsDir, 'cli_creator1.json'),
      JSON.stringify({ larkAppId: 'cli_creator1', ipcPort: daemonPort, lastHeartbeat: Date.now(), resolvedAllowedUsers: [] }),
      { mode: 0o600 },
    );

    try {
      const stateStore = new StateStore(pluginHome);
      const cfg = applyConfigPatch(
        createDefaultConfig(),
        {
          github: { mode: 'pat', apiBaseUrl: `http://127.0.0.1:${ghPort}`, pat: 'github_pat_reg1_token1234567890abcdef' },
          repos: [makeRule()],
        },
        { allowInsecureLocalApiForTests: true },
      );
      const watcher = new GitHubWatcher({
        config: cfg,
        stateStore,
        discovery: { botmuxHome, dataDir },
        allowInsecureLocalApiForTests: true,
      });

      // Capture empty baseline first
      const baseSync = await watcher.sync();
      assert.equal(baseSync.actions[0]?.action, 'baseline_captured');

      // Case 1A: Deliver `opened` for PR #11 while bots.json is broken -> fails before creating lock!
      const pr11 = makePrInfo({ number: 11, headSha: '1'.repeat(40) });
      const adm1 = watcher.enqueueWebhookPrEvent({ deliveryId: 'd-11', action: 'opened', pr: pr11 });
      assert.equal(adm1.accepted, true);
      await waitFor(async () => (await stateStore.readRecentEvents(10)).some(e => e.kind === 'webhook_process_error'));

      // Verify knownPrs['11'] was NOT prematurely committed!
      const stateAfterFail = await stateStore.load();
      assert.equal(stateAfterFail.repos['acme/reg']?.knownPrs['11'], undefined);
      assert.equal(stateAfterFail.prGroups['acme/reg#11'], undefined);

      // Case 1B: Deliver `synchronize` for UNKNOWN PR #12 (lost `opened`) -> knownPrs['12'] MUST NOT be committed!
      const pr12 = makePrInfo({ number: 12, headSha: '2'.repeat(40) });
      const adm2 = watcher.enqueueWebhookPrEvent({ deliveryId: 'd-12', action: 'synchronize', pr: pr12 });
      assert.equal(adm2.accepted, true);
      await waitFor(async () => (await stateStore.load()).processedDeliveries['d-12'] !== undefined);
      const stateAfterSync = await stateStore.load();
      assert.equal(stateAfterSync.repos['acme/reg']?.knownPrs['12'], undefined);

      // Case 1C: Known draft PR #13 flips ready_for_review, then synchronize arrives BEFORE poll -> MUST NOT erase draft:true!
      await stateStore.update(s => {
        s.repos['acme/reg']!.knownPrs['13'] = {
          headSha: '3'.repeat(40),
          draft: true,
          state: 'open',
          updatedAt: '2026-11-25T00:00:00Z',
        };
      });
      const pr13ReadySync = makePrInfo({ number: 13, headSha: '4'.repeat(40), draft: false });
      const adm3 = watcher.enqueueWebhookPrEvent({ deliveryId: 'd-13-sync', action: 'synchronize', pr: pr13ReadySync });
      assert.equal(adm3.accepted, true);
      await waitFor(async () => (await stateStore.load()).processedDeliveries['d-13-sync'] !== undefined);
      assert.equal((await stateStore.load()).repos['acme/reg']?.knownPrs['13']?.draft, true, 'synchronize must NOT overwrite draft:true when ready_for_review has not created a group yet');

      // Now repair bots.json and expose PR #11, #12, #13 in open PR list -> authoritative poll MUST create groups for ALL THREE!
      await fsp.writeFile(
        join(botmuxHome, 'bots.json'),
        JSON.stringify([
          { larkAppId: 'cli_creator1', larkAppSecret: 's1', brand: 'feishu' },
          { larkAppId: 'cli_reviewer2', larkAppSecret: 's2', brand: 'feishu' },
        ]),
        { mode: 0o600 },
      );
      openPrs = [
        makeRawPr({ repo: 'acme/reg', number: 11, headSha: '1'.repeat(40) }),
        makeRawPr({ repo: 'acme/reg', number: 12, headSha: '2'.repeat(40) }),
        makeRawPr({ repo: 'acme/reg', number: 13, headSha: '4'.repeat(40), draft: false }),
      ];

      const recovered = await watcher.sync();
      assert.equal(recovered.ok, true);
      assert.equal(createdGroups.length, 3, 'Failed-webhook PR #11, unknown-sync PR #12, and draft-ready-sync PR #13 must ALL get groups on poll');
      const finalSt = await stateStore.load();
      assert.equal(finalSt.prGroups['acme/reg#11']?.status, 'active');
      assert.equal(finalSt.prGroups['acme/reg#12']?.status, 'active');
      assert.equal(finalSt.prGroups['acme/reg#13']?.status, 'active');
    } finally {
      await Promise.all([
        new Promise<void>(r => ghServer.close(() => r())),
        new Promise<void>(r => daemonServer.close(() => r())),
      ]);
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[P1 #2] enforces cross-instance per-PR mutex lock, refuses CLI fallback on IPC unknown outcome, and prevents CLI ECONNRESET duplicate replay', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-reg-2-'));
    const pluginHome = join(tmp, 'plugin');
    const botmuxHome = join(tmp, 'botmux');
    const dataDir = join(tmp, 'data');
    const daemonsDir = join(dataDir, 'dashboard-daemons');
    await fsp.mkdir(daemonsDir, { recursive: true, mode: 0o700 });
    await fsp.mkdir(botmuxHome, { recursive: true, mode: 0o700 });

    const dashSecret = 'b'.repeat(43);
    await fsp.writeFile(join(botmuxHome, '.dashboard-secret'), `${dashSecret}\n`, { mode: 0o600 });
    await fsp.writeFile(
      join(botmuxHome, 'bots.json'),
      JSON.stringify([
        { larkAppId: 'cli_creator1', larkAppSecret: 's1', brand: 'feishu' },
        { larkAppId: 'cli_reviewer2', larkAppSecret: 's2', brand: 'feishu' },
      ]),
      { mode: 0o600 },
    );

    const daemonGroups: Array<{ chatId: string; name: string; kickoffPrompt: string }> = [];
    let createCalls = 0;
    let dropCreateResponseOnce = false;
    let daemonPort = 0;
    const seenNonces = new Map<string, number>();

    const daemonServer = http.createServer((req, res) => {
      verifyDaemonIpcHeaders(req.headers, dashSecret, req.method ?? 'GET', req.url ?? '/', daemonPort, seenNonces);
      const chunks: Buffer[] = [];
      req.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      req.on('end', () => {
        const body = chunks.length > 0 ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
        if (req.method === 'GET' && req.url === '/api/groups') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ chats: daemonGroups.map(g => ({ chatId: g.chatId, name: g.name, chatStatus: 'normal' })) }));
          return;
        }
        if (req.method === 'POST' && req.url === '/api/groups/create') {
          createCalls++;
          const chatId = `oc_mutex_${createCalls}`;
          daemonGroups.push({ chatId, name: body.name, kickoffPrompt: body.kickoffPrompt });
          if (dropCreateResponseOnce) {
            dropCreateResponseOnce = false;
            // Group WAS created on daemon side, then socket resets before response arrives!
            req.socket.destroy();
            return;
          }
          setTimeout(() => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true, chatId, kickoffMessageId: `om_m_${createCalls}`, kickoffError: null }));
          }, 50);
          return;
        }
        const readMatch = /^\/api\/groups\/(oc_[^/]+)\/messages\/(om_[^/]+)$/.exec(req.url ?? '');
        if (req.method === 'GET' && readMatch) {
          const g = daemonGroups.find(x => x.chatId === readMatch[1]);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, messageId: readMatch[2], chatId: readMatch[1], deleted: false, text: g?.kickoffPrompt ?? '' }));
          return;
        }
        const listMsgMatch = /^\/api\/groups\/(oc_[^/]+)\/messages$/.exec(req.url ?? '');
        if (req.method === 'GET' && listMsgMatch) {
          const g = daemonGroups.find(x => x.chatId === listMsgMatch[1]);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, messages: g ? [{ messageId: 'om_m_existing', preview: g.kickoffPrompt, deleted: false }] : [] }));
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
    const writeDaemonDesc = () =>
      fsp.writeFile(
        join(daemonsDir, 'cli_creator1.json'),
        JSON.stringify({ larkAppId: 'cli_creator1', ipcPort: daemonPort, lastHeartbeat: Date.now(), resolvedAllowedUsers: [] }),
        { mode: 0o600 },
      );
    await writeDaemonDesc();

    const ghClient = new GitHubClient({
      auth: { mode: 'pat', apiBaseUrl: 'http://127.0.0.1:1', pat: 'github_pat_mutex1234567890abcdef', app: { appId: '', installationId: '' } },
      allowInsecureLocalForTests: true,
    });

    try {
      // Probe 2A: Two INDEPENDENT HostBridge + StateStore instances racing concurrently on PR #20 -> strictly 1 group!
      const bridgeA = new HostBridge({ stateStore: new StateStore(pluginHome), discovery: { botmuxHome, dataDir } });
      const bridgeB = new HostBridge({ stateStore: new StateStore(pluginHome), discovery: { botmuxHome, dataDir } });
      const rule = makeRule();
      const pr20 = makePrInfo({ number: 20 });

      const [rA, rB] = await Promise.all([
        bridgeA.ensurePrReviewGroup({ rule, pr: pr20, githubClient: ghClient }),
        bridgeB.ensurePrReviewGroup({ rule, pr: pr20, githubClient: ghClient }),
      ]);
      assert.equal(createCalls, 1, 'Cross-instance per-PR mutex MUST prevent duplicate group creation');
      assert.equal(daemonGroups.length, 1);
      assert.equal(rA.record.chatId, rB.record.chatId);

      // Probe 2B: IPC create creates group on daemon then drops socket (unknown outcome) -> daemon offline -> MUST refuse CLI fallback!
      let cliFallbackCalls = 0;
      const bridgeC = new HostBridge({
        stateStore: new StateStore(pluginHome),
        discovery: { botmuxHome, dataDir },
        cliExec: async () => {
          cliFallbackCalls++;
          return { exitCode: 0, stdout: 'oc_cli_dup\n', stderr: '' };
        },
      });
      dropCreateResponseOnce = true;
      const pr21 = makePrInfo({ number: 21 });
      await assert.rejects(() => bridgeC.ensurePrReviewGroup({ rule, pr: pr21, githubClient: ghClient }));
      assert.equal(createCalls, 2);

      // Take daemon descriptor offline -> retry MUST fail closed without calling CLI!
      await fsp.rm(join(daemonsDir, 'cli_creator1.json'));
      await assert.rejects(
        () => bridgeC.ensurePrReviewGroup({ rule, pr: pr21, githubClient: ghClient }),
        /unknown outcome/i,
      );
      assert.equal(cliFallbackCalls, 0, 'Must NEVER switch to CLI fallback when IPC create outcome is unknown');

      // Bring daemon descriptor back -> retry checks GET /api/groups, adopts oc_mutex_2, ZERO extra creates!
      await writeDaemonDesc();
      const recovered = await bridgeC.ensurePrReviewGroup({ rule, pr: pr21, githubClient: ghClient });
      assert.equal(recovered.reusedExisting, true);
      assert.equal(recovered.record.chatId, 'oc_mutex_2');
      assert.equal(createCalls, 2);

      // Probe 2C: CLI github:open-pr hitting ECONNRESET on live service POST /api/open-pr MUST NOT spawn duplicate in-process watcher!
      let ghSinglePrHits = 0;
      const resetService = http.createServer((req, _res) => {
        if (req.url === '/api/open-pr') {
          req.socket.destroy(); // Drop socket after accepting POST mutation!
        }
      });
      const dummyGh = http.createServer((_req, res) => {
        ghSinglePrHits++;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(makeRawPr({ repo: 'acme/reg', number: 22 })));
      });
      await Promise.all([
        new Promise<void>(r => resetService.listen(0, '127.0.0.1', () => r())),
        new Promise<void>(r => dummyGh.listen(0, '127.0.0.1', () => r())),
      ]);
      const resetPort = (resetService.address() as { port: number }).port;
      const dummyGhPort = (dummyGh.address() as { port: number }).port;

      const cliPluginHome = join(tmp, 'cli-home');
      await ensureControlToken(cliPluginHome);
      const cliCfg = applyConfigPatch(
        createDefaultConfig(),
        {
          github: { mode: 'pat', apiBaseUrl: `http://127.0.0.1:${dummyGhPort}`, pat: 'github_pat_cliReset1234567890abcdef' },
          service: { port: resetPort },
          repos: [makeRule()],
        },
        { allowInsecureLocalApiForTests: true },
      );
      await savePluginConfig(cliPluginHome, cliCfg, { allowInsecureLocalApiForTests: true });
      const prevAllow = process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API;
      process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API = '1';
      try {
        const cliMod = await import(pathToFileURL(join(rootDir, 'dist', 'cli', 'index.js')).href);
        const exitCode = await cliMod.default['github:open-pr'].run(
          { args: ['acme/reg#22', '--json'], api: { config: { path: join(cliPluginHome, 'config.json') } } },
          { config: { path: join(cliPluginHome, 'config.json') } },
        );
        assert.equal(exitCode, 1, 'CLI must fail closed on POST ECONNRESET');
        assert.equal(ghSinglePrHits, 0, 'CLI MUST NOT replay open-pr in-process after live service ECONNRESET');
      } finally {
        if (prevAllow === undefined) delete process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API;
        else process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API = prevAllow;
        await Promise.all([
          new Promise<void>(r => resetService.close(() => r())),
          new Promise<void>(r => dummyGh.close(() => r())),
        ]);
      }
    } finally {
      await new Promise<void>(r => daemonServer.close(() => r()));
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[P2 #3] dist/webhooks/index.json matches botmux#3830 route parser/matcher and runner enforces BOTMUX_PLUGIN_WEBHOOK_TOKEN Bearer isolation', async () => {
    // 1. Validate actual built dist/webhooks/index.json against botmux#3830 route matching rules
    const manifest = JSON.parse(await fsp.readFile(join(rootDir, 'dist', 'webhooks', 'index.json'), 'utf8'));
    assert.equal(manifest.schemaVersion, 1);
    assert.equal(manifest.maxBodyBytes, 1_048_576);
    assert.equal(manifest.routes.length, 1);
    assert.equal(manifest.routes[0].path, '/events');
    assert.equal(manifest.routes[0].endpoint, '/webhooks/github');
    assert.equal(manifest.routes[0].maxBodyBytes, 1_048_576);

    // Exact botmux#3830 subpath resolution: /webhook/plugin/github/events -> subpath '/events' -> upstream '/webhooks/github'
    const incomingSubpath = '/events';
    const matched = manifest.routes.find((r: { path: string }) => r.path === incomingSubpath);
    assert.ok(matched, 'Mount-relative route /events MUST match core subpath /events');
    assert.equal(matched.endpoint, '/webhooks/github');

    // 2. Verify live runner enforces BOTMUX_PLUGIN_WEBHOOK_TOKEN on webhook routes & rejects it on /api/*
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-reg-3-'));
    const pluginHome = join(tmp, 'plugin');
    const cfg = applyConfigPatch(createDefaultConfig(), {
      webhook: { enabled: true, secret: WH_SECRET },
      repos: [makeRule({ enabled: true })],
    });
    await savePluginConfig(pluginHome, cfg);
    const hostToken = 'wh_host_token_abcdef1234567890ABCDEF';

    const svc = await startGitHubService({
      pluginHome,
      port: 0,
      webhookHostToken: hostToken,
    });
    try {
      const body = Buffer.from(JSON.stringify({ zen: 'ok', repository: { full_name: 'acme/reg' } }), 'utf8');
      const baseHeaders = {
        Host: `127.0.0.1:${svc.port}`,
        'Content-Type': 'application/json',
        'X-GitHub-Event': 'ping',
        'X-GitHub-Delivery': 'ping-3830-1',
        'X-Hub-Signature-256': signWebhook(body),
      };

      // Missing Bearer -> 401
      const noAuth = await loopbackRequest({ port: svc.port, method: 'POST', path: '/webhooks/github', headers: baseHeaders, body });
      assert.equal(noAuth.status, 401);

      // Wrong Bearer -> 401
      const badAuth = await loopbackRequest({
        port: svc.port,
        method: 'POST',
        path: '/webhooks/github',
        headers: { ...baseHeaders, Authorization: 'Bearer wrong-token' },
        body,
      });
      assert.equal(badAuth.status, 401);

      // Correct BOTMUX_PLUGIN_WEBHOOK_TOKEN -> 200 ping OK
      const okAuth = await loopbackRequest({
        port: svc.port,
        method: 'POST',
        path: '/webhooks/github',
        headers: { ...baseHeaders, Authorization: `Bearer ${hostToken}` },
        body,
      });
      assert.equal(okAuth.status, 200);

      // Isolation: BOTMUX_PLUGIN_WEBHOOK_TOKEN MUST be rejected on /api/status control endpoint!
      const ctrlAttempt = await loopbackRequest({
        port: svc.port,
        method: 'GET',
        path: '/api/status',
        headers: { Host: `127.0.0.1:${svc.port}`, Authorization: `Bearer ${hostToken}` },
      });
      assert.equal(ctrlAttempt.status, 401);
    } finally {
      await svc.close();
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[P2 #4] close events are never masked by ETag: single-PR 500 blocks ETag advance, and page-1 304 still detects page-2 PR #101 closure', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-reg-4-'));
    const pluginHome = join(tmp, 'plugin');
    const botmuxHome = join(tmp, 'botmux');
    const dataDir = join(tmp, 'data');
    const daemonsDir = join(dataDir, 'dashboard-daemons');
    await fsp.mkdir(daemonsDir, { recursive: true, mode: 0o700 });
    await fsp.mkdir(botmuxHome, { recursive: true, mode: 0o700 });
    const dashSecret = 'c'.repeat(43);
    await fsp.writeFile(join(botmuxHome, '.dashboard-secret'), `${dashSecret}\n`, { mode: 0o600 });
    await fsp.writeFile(join(botmuxHome, 'bots.json'), JSON.stringify([{ larkAppId: 'cli_creator1', larkAppSecret: 's1', brand: 'feishu' }]), { mode: 0o600 });

    const page1Prs = Array.from({ length: 100 }, (_, i) => makeRawPr({ repo: 'acme/reg', number: i + 1 }));
    let page2Prs = [makeRawPr({ repo: 'acme/reg', number: 101 })];
    let page2Etag = '"p2-v1"';
    let pr101State: 'open' | 'closed' = 'open';
    let failSinglePrLookupOnce = false;
    let closeMessagesSent = 0;

    const ghServer = http.createServer((req, res) => {
      if (req.url?.includes('&page=1')) {
        if (req.headers['if-none-match'] === '"p1-v1"') {
          res.writeHead(304, { ETag: '"p1-v1"', Link: '<http://127.0.0.1/pulls?page=2>; rel="next"' });
          res.end();
          return;
        }
        res.writeHead(200, {
          'Content-Type': 'application/json',
          ETag: '"p1-v1"',
          Link: '<http://127.0.0.1/pulls?page=2>; rel="next"',
        });
        res.end(JSON.stringify(page1Prs));
        return;
      }
      if (req.url?.includes('&page=2')) {
        if (req.headers['if-none-match'] === page2Etag) {
          res.writeHead(304, { ETag: page2Etag });
          res.end();
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json', ETag: page2Etag });
        res.end(JSON.stringify(page2Prs));
        return;
      }
      if (req.url === '/repos/acme/reg/pulls/101') {
        if (failSinglePrLookupOnce) {
          failSinglePrLookupOnce = false;
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ message: 'Transient 500' }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(makeRawPr({ repo: 'acme/reg', number: 101, state: pr101State, merged: pr101State === 'closed' })));
        return;
      }
      res.writeHead(404);
      res.end('{}');
    });

    let daemonPort = 0;
    const seenNonces = new Map<string, number>();
    const daemonServer = http.createServer((req, res) => {
      verifyDaemonIpcHeaders(req.headers, dashSecret, req.method ?? 'GET', req.url ?? '/', daemonPort, seenNonces);
      const chunks: Buffer[] = [];
      req.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      req.on('end', () => {
        const body = chunks.length > 0 ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
        if (req.method === 'POST' && req.url === '/api/groups/oc_101/messages') {
          closeMessagesSent++;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, chatId: 'oc_101', messageId: `om_c_${closeMessagesSent}`, requestId: body.requestId, replayed: false }));
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
    await fsp.writeFile(
      join(daemonsDir, 'cli_creator1.json'),
      JSON.stringify({ larkAppId: 'cli_creator1', ipcPort: daemonPort, lastHeartbeat: Date.now(), resolvedAllowedUsers: [] }),
      { mode: 0o600 },
    );

    try {
      const stateStore = new StateStore(pluginHome);
      await stateStore.update(s => {
        s.prGroups['acme/reg#101'] = {
          status: 'active',
          repo: 'acme/reg',
          prNumber: 101,
          chatId: 'oc_101',
          groupName: 'PR #101 acme/reg - Page 2 PR',
          creatorLarkAppId: 'cli_creator1',
          kickoffMessageId: 'om_k_101',
          kickoffVerified: true,
          topNoticeSet: true,
          lifecycleGeneration: 1,
          lastHeadSha: 'a'.repeat(40),
          createdAt: '2026-11-25T00:00:00Z',
          updatedAt: '2026-11-25T00:00:00Z',
        };
      });

      const cfg = applyConfigPatch(
        createDefaultConfig(),
        {
          github: { mode: 'pat', apiBaseUrl: `http://127.0.0.1:${ghPort}`, pat: 'github_pat_reg4_token1234567890abcdef' },
          repos: [makeRule()],
        },
        { allowInsecureLocalApiForTests: true },
      );
      const watcher = new GitHubWatcher({ config: cfg, stateStore, discovery: { botmuxHome, dataDir }, allowInsecureLocalApiForTests: true });

      // 1. Baseline captures 101 open PRs across 2 pages
      const baseRes = await watcher.sync();
      assert.equal(baseRes.actions[0]?.action, 'baseline_captured');

      // 2. Close PR #101 on page 2 while page 1 ETag stays '"p1-v1"' (304!), and fail single-PR confirmation ONCE with 500!
      page2Prs = [];
      page2Etag = '"p2-v2"';
      pr101State = 'closed';
      failSinglePrLookupOnce = true;

      const failedClosePoll = await watcher.sync();
      assert.equal(failedClosePoll.ok, false, 'Single-PR close 500 MUST fail the poll');
      const stAfterErr = await stateStore.load();
      assert.equal(stAfterErr.repos['acme/reg']?.etag, undefined, 'ETag MUST NOT advance after close-confirmation failure');
      assert.equal(stAfterErr.prGroups['acme/reg#101']?.status, 'active');

      // 3. Next poll retries cleanly, confirms PR #101 closed, sends close notice, and marks group closed!
      const okClosePoll = await watcher.sync();
      assert.equal(okClosePoll.ok, true);
      assert.equal(closeMessagesSent, 1);
      assert.equal((await stateStore.load()).prGroups['acme/reg#101']?.status, 'closed');
    } finally {
      await Promise.all([
        new Promise<void>(r => ghServer.close(() => r())),
        new Promise<void>(r => daemonServer.close(() => r())),
      ]);
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[P2 #5] close -> reopen -> same-SHA second close lifecycle transitions cleanly by generation without status divergence', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-reg-5-'));
    const pluginHome = join(tmp, 'plugin');
    const botmuxHome = join(tmp, 'botmux');
    const dataDir = join(tmp, 'data');
    const daemonsDir = join(dataDir, 'dashboard-daemons');
    await fsp.mkdir(daemonsDir, { recursive: true, mode: 0o700 });
    await fsp.mkdir(botmuxHome, { recursive: true, mode: 0o700 });
    const dashSecret = 'd'.repeat(43);
    await fsp.writeFile(join(botmuxHome, '.dashboard-secret'), `${dashSecret}\n`, { mode: 0o600 });
    await fsp.writeFile(join(botmuxHome, 'bots.json'), JSON.stringify([{ larkAppId: 'cli_creator1', larkAppSecret: 's1', brand: 'feishu' }]), { mode: 0o600 });

    const sameSha = '5'.repeat(40);
    let prOpen = false;
    let closeMsgCount = 0;

    const ghServer = http.createServer((req, res) => {
      if (req.url?.startsWith('/repos/acme/reg/pulls?')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(prOpen ? [makeRawPr({ repo: 'acme/reg', number: 55, headSha: sameSha })] : []));
        return;
      }
      if (req.url === '/repos/acme/reg/pulls/55') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(makeRawPr({ repo: 'acme/reg', number: 55, headSha: sameSha, state: prOpen ? 'open' : 'closed' })));
        return;
      }
      res.writeHead(404);
      res.end('{}');
    });

    let daemonPort = 0;
    const seenNonces = new Map<string, number>();
    const daemonServer = http.createServer((req, res) => {
      verifyDaemonIpcHeaders(req.headers, dashSecret, req.method ?? 'GET', req.url ?? '/', daemonPort, seenNonces);
      const chunks: Buffer[] = [];
      req.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      req.on('end', () => {
        const body = chunks.length > 0 ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
        if (req.method === 'POST' && req.url === '/api/groups/oc_55/messages') {
          closeMsgCount++;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, chatId: 'oc_55', messageId: `om_cl_${closeMsgCount}`, requestId: body.requestId, replayed: false }));
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
    await fsp.writeFile(
      join(daemonsDir, 'cli_creator1.json'),
      JSON.stringify({ larkAppId: 'cli_creator1', ipcPort: daemonPort, lastHeartbeat: Date.now(), resolvedAllowedUsers: [] }),
      { mode: 0o600 },
    );

    try {
      const stateStore = new StateStore(pluginHome);
      await stateStore.update(s => {
        s.repos['acme/reg'] = {
          baselineCapturedAt: '2026-11-25T00:00:00Z',
          knownPrs: { '55': { headSha: sameSha, draft: false, state: 'closed', updatedAt: '2026-11-25T00:00:00Z' } },
        };
        s.prGroups['acme/reg#55'] = {
          status: 'closed',
          repo: 'acme/reg',
          prNumber: 55,
          chatId: 'oc_55',
          groupName: 'PR #55 acme/reg - Lifecycle',
          creatorLarkAppId: 'cli_creator1',
          kickoffMessageId: 'om_k55',
          kickoffVerified: true,
          topNoticeSet: true,
          lifecycleGeneration: 1,
          lastHeadSha: sameSha,
          createdAt: '2026-11-25T00:00:00Z',
          updatedAt: '2026-11-25T00:00:00Z',
        };
      });
      await stateStore.markEventProcessed('acme/reg', 55, sameSha, 'pr_closed', 1);

      const cfg = applyConfigPatch(
        createDefaultConfig(),
        {
          github: { mode: 'pat', apiBaseUrl: `http://127.0.0.1:${ghPort}`, pat: 'github_pat_reg5_token1234567890abcdef' },
          repos: [makeRule()],
        },
        { allowInsecureLocalApiForTests: true },
      );
      const watcher = new GitHubWatcher({ config: cfg, stateStore, discovery: { botmuxHome, dataDir }, allowInsecureLocalApiForTests: true });

      // 1. Reopen at SAME SHA via poll -> group MUST reactivate to `active` with generation=2!
      prOpen = true;
      const reopenPoll = await watcher.sync();
      assert.equal(reopenPoll.ok, true);
      const afterReopen = await stateStore.load();
      assert.equal(afterReopen.prGroups['acme/reg#55']?.status, 'active');
      assert.equal(afterReopen.prGroups['acme/reg#55']?.lifecycleGeneration, 2);

      // 2. Second close at SAME SHA via webhook -> generation=2 sends 2nd close notice AND lands status='closed'!
      prOpen = false;
      const adm = watcher.enqueueWebhookPrEvent({
        deliveryId: 'd-close-2',
        action: 'closed',
        pr: makePrInfo({ number: 55, headSha: sameSha, state: 'closed' }),
      });
      assert.equal(adm.accepted, true);
      await waitFor(async () => (await stateStore.load()).processedDeliveries['d-close-2'] !== undefined);

      const afterSecondClose = await stateStore.load();
      assert.equal(afterSecondClose.prGroups['acme/reg#55']?.status, 'closed');
      assert.equal(afterSecondClose.repos['acme/reg']?.knownPrs['55']?.state, 'closed');
      assert.equal(closeMsgCount, 1);
    } finally {
      await Promise.all([
        new Promise<void>(r => ghServer.close(() => r())),
        new Promise<void>(r => daemonServer.close(() => r())),
      ]);
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[P2 #6] unverified kickoff readback or failed top-notice stays creating (never active), and manual openPr resumes only remaining steps', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-reg-6-'));
    const pluginHome = join(tmp, 'plugin');
    const botmuxHome = join(tmp, 'botmux');
    const dataDir = join(tmp, 'data');
    const daemonsDir = join(dataDir, 'dashboard-daemons');
    await fsp.mkdir(daemonsDir, { recursive: true, mode: 0o700 });
    await fsp.mkdir(botmuxHome, { recursive: true, mode: 0o700 });
    const dashSecret = 'e'.repeat(43);
    await fsp.writeFile(join(botmuxHome, '.dashboard-secret'), `${dashSecret}\n`, { mode: 0o600 });
    await fsp.writeFile(join(botmuxHome, 'bots.json'), JSON.stringify([{ larkAppId: 'cli_creator1', larkAppSecret: 's1', brand: 'feishu' }]), { mode: 0o600 });

    let readbackFail = true;
    let topNoticeFail = true;
    let createCalls = 0;
    let topNoticeCalls = 0;
    let savedKickoffPrompt = '';

    const ghServer = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(makeRawPr({ repo: 'acme/reg', number: 66 })));
    });

    let daemonPort = 0;
    const seenNonces = new Map<string, number>();
    const daemonServer = http.createServer((req, res) => {
      verifyDaemonIpcHeaders(req.headers, dashSecret, req.method ?? 'GET', req.url ?? '/', daemonPort, seenNonces);
      const chunks: Buffer[] = [];
      req.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      req.on('end', () => {
        const body = chunks.length > 0 ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
        if (req.method === 'GET' && req.url === '/api/groups') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ chats: [] }));
          return;
        }
        if (req.method === 'POST' && req.url === '/api/groups/create') {
          createCalls++;
          savedKickoffPrompt = body.kickoffPrompt;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, chatId: 'oc_66', kickoffMessageId: 'om_66', kickoffError: null }));
          return;
        }
        if (req.method === 'GET' && req.url === '/api/groups/oc_66/messages/om_66') {
          if (readbackFail) {
            res.writeHead(500);
            res.end('{}');
            return;
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, messageId: 'om_66', chatId: 'oc_66', deleted: false, text: savedKickoffPrompt }));
          return;
        }
        if (req.method === 'POST' && req.url === '/api/groups/oc_66/top-notice') {
          topNoticeCalls++;
          if (topNoticeFail) {
            res.writeHead(500);
            res.end('{}');
            return;
          }
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
    await fsp.writeFile(
      join(daemonsDir, 'cli_creator1.json'),
      JSON.stringify({ larkAppId: 'cli_creator1', ipcPort: daemonPort, lastHeartbeat: Date.now(), resolvedAllowedUsers: [] }),
      { mode: 0o600 },
    );

    try {
      const stateStore = new StateStore(pluginHome);
      const cfg = applyConfigPatch(
        createDefaultConfig(),
        {
          github: { mode: 'pat', apiBaseUrl: `http://127.0.0.1:${ghPort}`, pat: 'github_pat_reg6_token1234567890abcdef' },
          repos: [makeRule()],
        },
        { allowInsecureLocalApiForTests: true },
      );
      const watcher = new GitHubWatcher({ config: cfg, stateStore, discovery: { botmuxHome, dataDir }, allowInsecureLocalApiForTests: true });

      // 1. Readback fails 500 -> top-notice MUST NOT be called and group MUST stay `creating`!
      const attempt1 = await watcher.openPr({ repo: 'acme/reg', prNumber: 66 });
      assert.equal(attempt1.ok, false);
      assert.equal(createCalls, 1);
      assert.equal(topNoticeCalls, 0, 'Must NOT pin top-notice while kickoff readback failed');
      assert.equal((await stateStore.load()).prGroups['acme/reg#66']?.status, 'creating');

      // 2. Readback recovers, top-notice fails 500 -> group MUST STILL stay `creating` (kickoffVerified=true, topNoticeSet=false)!
      readbackFail = false;
      const attempt2 = await watcher.openPr({ repo: 'acme/reg', prNumber: 66 });
      assert.equal(attempt2.ok, false);
      assert.equal(createCalls, 1, 'Resume must NOT create a second group');
      assert.equal(topNoticeCalls, 1);
      const st2 = await stateStore.load();
      assert.equal(st2.prGroups['acme/reg#66']?.status, 'creating');
      assert.equal(st2.prGroups['acme/reg#66']?.kickoffVerified, true);
      assert.equal(st2.prGroups['acme/reg#66']?.topNoticeSet, false);

      // 3. Top-notice recovers -> manual openPr resumes ONLY top-notice and marks `active`!
      topNoticeFail = false;
      const attempt3 = await watcher.openPr({ repo: 'acme/reg', prNumber: 66 });
      assert.equal(attempt3.ok, true);
      assert.equal(attempt3.action, 'resumed');
      assert.equal(createCalls, 1);
      assert.equal(topNoticeCalls, 2);
      assert.equal(attempt3.topNoticeSet, true);
      assert.equal((await stateStore.load()).prGroups['acme/reg#66']?.status, 'active');
    } finally {
      await Promise.all([
        new Promise<void>(r => ghServer.close(() => r())),
        new Promise<void>(r => daemonServer.close(() => r())),
      ]);
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[P2 #7] active->dormant hot-reload aborts in-flight poll generation so page 2 is never fetched', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-reg-7-'));
    const pluginHome = join(tmp, 'plugin');

    let page1Calls = 0;
    let page2Calls = 0;
    let releasePage1!: () => void;
    const page1Reached = new Promise<void>(resolveReached => {
      releasePage1 = resolveReached;
    });
    let allowPage1Finish!: () => void;
    const page1Gate = new Promise<void>(r => {
      allowPage1Finish = r;
    });

    const page1Items = Array.from({ length: 100 }, (_, i) => makeRawPr({ repo: 'acme/reg', number: i + 1 }));
    const ghServer = http.createServer(async (req, res) => {
      if (req.url?.includes('&page=1')) {
        page1Calls++;
        releasePage1();
        await page1Gate;
        if (!res.destroyed) {
          res.writeHead(200, {
            'Content-Type': 'application/json',
            Link: '<http://127.0.0.1/pulls?page=2>; rel="next"',
          });
          res.end(JSON.stringify(page1Items));
        }
        return;
      }
      if (req.url?.includes('&page=2')) {
        page2Calls++;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('[]');
        return;
      }
      res.writeHead(404);
      res.end('{}');
    });

    await new Promise<void>(r => ghServer.listen(0, '127.0.0.1', () => r()));
    const ghPort = (ghServer.address() as { port: number }).port;

    try {
      const stateStore = new StateStore(pluginHome);
      const activeCfg = applyConfigPatch(
        createDefaultConfig(),
        {
          github: { mode: 'pat', apiBaseUrl: `http://127.0.0.1:${ghPort}`, pat: 'github_pat_reg7_token1234567890abcdef' },
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

      // Wait until initial poll is blocked on page 1
      await page1Reached;
      assert.equal(page1Calls, 1);

      // Hot-reload active -> dormant BEFORE page 1 finishes
      const modeAfterReload = await watcher.reloadConfig(dormantCfg);
      assert.equal(modeAfterReload, 'dormant');

      // Release page 1 -> old generation MUST abort and NEVER request page 2!
      allowPage1Finish();
      await new Promise(r => setTimeout(r, 120));
      assert.equal(page2Calls, 0, 'Old poll generation MUST NOT fetch page 2 after active->dormant reload');
      await watcher.stop();
    } finally {
      await new Promise<void>(r => ghServer.close(() => r()));
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[P2 #8] webhook admission bounds global pending & inFlight deliveries and synchronously returns 429/503 (never fake 202)', async () => {
    // 1. Unit-level global pending cap + inFlight cap & expiry checks
    let nowMs = 1_700_000_000_000;
    const dedup = new DeliveryDedupCache({
      maxEntries: 8,
      maxInFlight: 3,
      inFlightTimeoutMs: 5_000,
      now: () => nowMs,
    });
    assert.equal(dedup.tryAcquire('d1'), 'acquired');
    assert.equal(dedup.tryAcquire('d2'), 'acquired');
    assert.equal(dedup.tryAcquire('d3'), 'acquired');
    assert.equal(dedup.tryAcquire('d4'), 'overloaded', 'inFlight must be bounded at maxInFlight');
    // Advance past inFlightTimeoutMs -> stuck entries expire and release capacity!
    nowMs += 6_000;
    assert.equal(dedup.inFlightSize(), 0);
    assert.equal(dedup.tryAcquire('d4'), 'acquired');

    const q = new PerPrSerialQueue({ maxConcurrency: 1, maxPendingPerKey: 1, maxGlobalPending: 2 });
    let releaseBlocker!: () => void;
    const blocker = new Promise<void>(r => {
      releaseBlocker = r;
    });
    const t1 = q.tryEnqueue('acme/reg#1', async () => blocker);
    const t2 = q.tryEnqueue('acme/reg#2', async () => {});
    const t3 = q.tryEnqueue('acme/reg#3', async () => {});
    const t4 = q.tryEnqueue('acme/reg#4', async () => {});
    assert.equal(t1.accepted, true);
    assert.equal(t2.accepted, true);
    assert.equal(t3.accepted, true);
    assert.equal(t4.accepted, false);
    assert.equal(t4.reason, 'global_full');
    releaseBlocker();
    await Promise.all([t1.promise, t2.promise, t3.promise]);

    // 2. Live HTTP webhook returns synchronous 429 (NOT fake 202!) when per-PR queue is full
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-reg-8-'));
    const pluginHome = join(tmp, 'plugin');
    const cfg = applyConfigPatch(createDefaultConfig(), {
      webhook: { enabled: true, secret: WH_SECRET },
      repos: [makeRule()],
    });
    await savePluginConfig(pluginHome, cfg);

    const svc = await startGitHubService({
      pluginHome,
      port: 0,
      maxPendingPerKey: 1,
      maxGlobalPending: 2,
      maxInFlightDeliveries: 10,
    });
    try {
      // Saturate PR #88 queue by filling active + maxPendingPerKey=1 via direct enqueue on internal queue
      // Wait: easiest deterministic way is sending 3 rapid valid webhook deliveries for PR #88 while active task blocks
      let unblock!: () => void;
      const gate = new Promise<void>(r => {
        unblock = r;
      });
      const origEnsure = (svc.watcher as unknown as { processWebhookPrEvent: (...a: unknown[]) => Promise<void> }).processWebhookPrEvent.bind(svc.watcher);
      let firstBlocked = false;
      (svc.watcher as unknown as { processWebhookPrEvent: (...a: unknown[]) => Promise<void> }).processWebhookPrEvent = async (...args: unknown[]) => {
        if (!firstBlocked) {
          firstBlocked = true;
          await gate;
        }
        return origEnsure(...args);
      };

      const sendPr88 = (delivId: string) => {
        const body = Buffer.from(
          JSON.stringify({
            action: 'synchronize',
            repository: { full_name: 'acme/reg' },
            pull_request: makeRawPr({ repo: 'acme/reg', number: 88 }),
          }),
          'utf8',
        );
        return loopbackRequest({
          port: svc.port,
          method: 'POST',
          path: '/webhooks/github',
          headers: {
            Host: `127.0.0.1:${svc.port}`,
            'Content-Type': 'application/json',
            'X-GitHub-Event': 'pull_request',
            'X-GitHub-Delivery': delivId,
            'X-Hub-Signature-256': signWebhook(body),
          },
          body,
        });
      };

      const r1 = await sendPr88('d-88-1'); // active
      const r2 = await sendPr88('d-88-2'); // pending (1/1)
      const r3 = await sendPr88('d-88-3'); // OVERFLOW -> MUST return 429 (NOT 202!)
      assert.equal(r1.status, 202);
      assert.equal(r2.status, 202);
      assert.equal(r3.status, 429, 'Full webhook queue MUST synchronously return retryable 429, never fake 202');
      assert.equal(r3.headers['retry-after'], '5');

      // Release blocker -> d-88-3 was aborted from dedup cache so retrying d-88-3 later succeeds!
      unblock();
      await new Promise(r => setTimeout(r, 80));
      const r3Retry = await sendPr88('d-88-3');
      assert.equal(r3Retry.status, 202);
    } finally {
      await svc.close();
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[P2 #9] reload failure returns 500 ok:false without committing hash/config and auto-recovers on next hash poll', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-reg-9-'));
    const pluginHome = join(tmp, 'plugin');
    const cfg1 = applyConfigPatch(createDefaultConfig(), {
      service: { pollIntervalSec: 60 },
    });
    await savePluginConfig(pluginHome, cfg1);

    const svc = await startGitHubService({
      pluginHome,
      port: 0,
      configPollIntervalMs: 80,
    });

    try {
      // Inject one transient failure in watcher.reloadConfig
      let reloadAttempts = 0;
      let shouldFail = true;
      const origReload = svc.watcher.reloadConfig.bind(svc.watcher);
      svc.watcher.reloadConfig = async next => {
        reloadAttempts++;
        if (shouldFail) {
          shouldFail = false;
          throw new Error('simulated transient reload error');
        }
        return origReload(next);
      };

      const cfg2 = applyConfigPatch(cfg1, { service: { pollIntervalSec: 45 } });
      await savePluginConfig(pluginHome, cfg2);

      // Call POST /api/reload while failing -> MUST return HTTP 500 { ok: false }!
      const failedResp = await loopbackRequest({
        port: svc.port,
        method: 'POST',
        path: '/api/reload',
        headers: {
          Host: `127.0.0.1:${svc.port}`,
          'Content-Type': 'application/json',
          'X-Botmux-Plugin-Control': '1',
          'X-Botmux-Github-Token': svc.controlToken,
        },
        body: '{}',
      });
      assert.equal(failedResp.status, 500);
      assert.equal(JSON.parse(failedResp.body.toString('utf8')).ok, false);
      assert.equal(svc.watcher.getConfig().service.pollIntervalSec, 60, 'Old config must stay intact on failed reload');

      // Wait for automatic hash poll retry (80ms interval) WITHOUT touching config.json again -> MUST auto-recover!
      await waitFor(() => svc.watcher.getConfig().service.pollIntervalSec === 45, 2000);
      assert.ok(reloadAttempts >= 2, 'Automatic hash poll must retry after failed reload');
    } finally {
      await svc.close();
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[P2 #10] github:test-auth --repo folds repoAccess.ok into top-level ok and returns CLI exit code 1 when repo is 403', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-reg-10-'));
    const pluginHome = join(tmp, 'plugin');

    const ghServer = http.createServer((req, res) => {
      if (req.url === '/user') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ login: 'octo-tester' }));
        return;
      }
      if (req.url === '/repos/acme/forbidden') {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'Resource not accessible by personal access token' }));
        return;
      }
      res.writeHead(404);
      res.end('{}');
    });
    await new Promise<void>(r => ghServer.listen(0, '127.0.0.1', () => r()));
    const ghPort = (ghServer.address() as { port: number }).port;

    const prevAllow = process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API;
    process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API = '1';
    try {
      const cfg = applyConfigPatch(
        createDefaultConfig(),
        {
          github: { mode: 'pat', apiBaseUrl: `http://127.0.0.1:${ghPort}`, pat: 'github_pat_reg10_token1234567890abcdef' },
        },
        { allowInsecureLocalApiForTests: true },
      );
      await savePluginConfig(pluginHome, cfg, { allowInsecureLocalApiForTests: true });

      const client = new GitHubClient({ auth: cfg.github, allowInsecureLocalForTests: true });
      const res = await client.testAuth({ repo: 'acme/forbidden' });
      assert.equal(res.ok, false, 'Top-level ok MUST be false when requested --repo fails');
      assert.equal(res.identity, '@octo-tester');
      assert.equal(res.repoAccess?.ok, false);

      const cliMod = await import(pathToFileURL(join(rootDir, 'dist', 'cli', 'index.js')).href);
      const exitCode = await cliMod.default['github:test-auth'].run(
        { args: ['--repo', 'acme/forbidden', '--json'], api: { config: { path: join(pluginHome, 'config.json') } } },
        { config: { path: join(pluginHome, 'config.json') } },
      );
      assert.equal(exitCode, 1, 'CLI github:test-auth --repo MUST exit 1 when repoAccess.ok is false');

      // Malformed --repo slug (no slash) and bare --repo flag must also fail with ok:false / exit 1
      const badSlugRes = await client.testAuth({ repo: 'not-a-valid-slug' });
      assert.equal(badSlugRes.ok, false);
      const bareFlagExit = await cliMod.default['github:test-auth'].run(
        { args: ['--repo', '--json'], api: { config: { path: join(pluginHome, 'config.json') } } },
        { config: { path: join(pluginHome, 'config.json') } },
      );
      assert.equal(bareFlagExit, 1);
    } finally {
      if (prevAllow === undefined) delete process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API;
      else process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API = prevAllow;
      await new Promise<void>(r => ghServer.close(() => r()));
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });
});

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { PullRequestInfo, RepoRule } from '../../src/types.ts';
import { applyConfigPatch, createDefaultConfig } from '../../src/config/schema.ts';
import { savePluginConfig } from '../../src/config/store.ts';
import { StateStore, StateCorruptError } from '../../src/state/store.ts';
import { GitHubClient } from '../../src/github/client.ts';
import { GitHubWatcher } from '../../src/engine/watcher.ts';
import { HostBridge } from '../../src/host/bridge.ts';
import { startGitHubService } from '../../src/service/runner.ts';
import { acquireSecureLock, readDurableProcessIdentity, SecurityFsError } from '../../src/security/fs.ts';
import { loopbackRequest } from '../../src/security/net.ts';
import { verifyDaemonIpcHeaders } from '../../src/host/discovery.ts';

const rootDir = resolve(import.meta.dirname, '..', '..');
const WH_SECRET = 'whsec_Round3Secret_1234567890ABCDEFGH';

function makeRawPr(number: number, repo = 'acme/r3', state: 'open' | 'closed' = 'open') {
  return {
    number,
    title: `PR #${number}`,
    body: `Body #${number}`,
    state,
    draft: false,
    merged: false,
    html_url: `https://github.com/${repo}/pull/${number}`,
    user: { login: 'alice' },
    base: { ref: 'main', repo: { full_name: repo } },
    head: { ref: `feat/pr-${number}`, sha: 'a'.repeat(40), repo: { full_name: repo, fork: false } },
    labels: [],
    maintainer_can_modify: true,
    created_at: '2026-11-26T00:00:00Z',
    updated_at: '2026-11-26T00:01:00Z',
  };
}

function makePrInfo(number: number, repo = 'acme/r3'): PullRequestInfo {
  return {
    repo,
    number,
    title: `PR #${number}`,
    body: `Body #${number}`,
    state: 'open',
    draft: false,
    merged: false,
    htmlUrl: `https://github.com/${repo}/pull/${number}`,
    author: 'alice',
    baseBranch: 'main',
    headBranch: `feat/pr-${number}`,
    headSha: 'a'.repeat(40),
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
    id: 'acme/r3',
    repo: 'acme/r3',
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

describe('PR #1 Round-3 Independent Review Boundary Regressions (2x P1, 4x P2)', () => {
  it('[R3-1 P1] saveSettings fails closed without overwriting when existing repo rules have wrong-typed boolean/array/enum fields', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-r3-p1-cfg-'));
    const pluginHome = join(tmp, 'plugin');
    await fsp.mkdir(pluginHome, { recursive: true, mode: 0o700 });
    const settingsMod = await import(pathToFileURL(join(rootDir, 'dist', 'server', 'settings.js')).href);

    try {
      const badCases: Array<{ label: string; badRepo: Record<string, unknown> }> = [
        {
          label: 'enabled as string, memberBotAppIds as string, triggerOn as string',
          badRepo: {
            repo: 'acme/r3',
            enabled: 'true',
            memberBotAppIds: 'cli_reviewer2',
            triggerOn: 'opened',
            creatorBotAppId: 'cli_creator1',
          },
        },
        {
          label: 'ignoreDrafts as string',
          badRepo: {
            repo: 'acme/r3',
            enabled: true,
            ignoreDrafts: 'false',
            creatorBotAppId: 'cli_creator1',
          },
        },
        {
          label: 'chatMode invalid enum',
          badRepo: {
            repo: 'acme/r3',
            enabled: true,
            chatMode: 'p2p',
            creatorBotAppId: 'cli_creator1',
          },
        },
        {
          label: 'triggerOn containing invalid value',
          badRepo: {
            repo: 'acme/r3',
            enabled: true,
            triggerOn: ['opened', 'unknown_event'],
            creatorBotAppId: 'cli_creator1',
          },
        },
        {
          label: 'pollIntervalSec as string',
          badRepo: {
            repo: 'acme/r3',
            enabled: true,
            pollIntervalSec: '60',
            creatorBotAppId: 'cli_creator1',
          },
        },
      ];

      for (const tc of badCases) {
        let replaceCalls = 0;
        const stored: Record<string, unknown> = {
          schemaVersion: 1,
          github: { mode: 'pat', apiBaseUrl: 'https://api.github.com', pat: 'github_pat_keepSafe1234567890abcdef' },
          service: { port: 18940, pollIntervalSec: 60 },
          repos: [tc.badRepo],
        };
        const api = {
          config: {
            path: join(pluginHome, 'config.json'),
            get: () => stored,
            set: () => {},
            replace: () => {
              replaceCalls++;
            },
          },
        };
        const res = await settingsMod.saveSettings(api, {
          action: 'saveConfig',
          patch: { service: { pollIntervalSec: 90 } },
        });
        assert.equal(res.ok, false, `Expected ok:false for wrong-typed repo (${tc.label})`);
        assert.equal(replaceCalls, 0, `Must NOT call replace() for wrong-typed repo (${tc.label})`);
      }

      // Also reject wrong-typed incoming patches (null scalar, non-object section, non-object patch wrapper)
      const validStored: Record<string, unknown> = {
        schemaVersion: 1,
        github: { mode: 'pat', apiBaseUrl: 'https://api.github.com', pat: 'github_pat_keepSafe1234567890abcdef' },
        service: { port: 18940, pollIntervalSec: 60 },
        repos: [makeRule()],
      };
      let validReplaces = 0;
      const validApi = {
        config: {
          path: join(pluginHome, 'valid-config.json'),
          get: () => validStored,
          set: () => {},
          replace: () => {
            validReplaces++;
          },
        },
      };
      for (const badPayload of [
        { action: 'saveConfig', patch: null },
        { action: 'saveConfig', patch: 'bad' },
        { action: 'saveConfig', patch: { service: { port: null } } },
        { action: 'saveConfig', patch: { github: 'bad' } },
        { action: 'saveConfig', patch: { github: { pat: { action: 'bogus' } } } },
      ]) {
        const res = await settingsMod.saveSettings(validApi, badPayload);
        assert.equal(res.ok, false, `Expected ok:false for bad patch ${JSON.stringify(badPayload)}`);
      }
      assert.equal(validReplaces, 0);
    } finally {
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[R3-2 P1] maxPages-capped pagination stays truncated=true across subsequent 304 polls (never flipping truncated->false)', async () => {
    let page1Etag = '"cap300-p1-v1"';
    let page1Version = 1;
    const page1Prs = () =>
      Array.from({ length: 100 }, (_, i) =>
        makeRawPr(i + 1, 'acme/r3', 'open'),
      ).map(pr => ({ ...pr, title: `PR #${pr.number} v${page1Version}` }));
    const page2Prs = Array.from({ length: 100 }, (_, i) => makeRawPr(101 + i, 'acme/r3', 'open'));
    let page3Calls = 0;

    const ghServer = http.createServer((req, res) => {
      if (req.url?.includes('&page=1')) {
        if (req.headers['if-none-match'] === page1Etag) {
          res.writeHead(304, { ETag: page1Etag });
          res.end();
          return;
        }
        res.writeHead(200, {
          'Content-Type': 'application/json',
          ETag: page1Etag,
          Link: '<http://127.0.0.1/pulls?page=2>; rel="next"',
        });
        res.end(JSON.stringify(page1Prs()));
        return;
      }
      if (req.url?.includes('&page=2')) {
        if (req.headers['if-none-match'] === '"cap300-p2-v1"') {
          // Legitimate 304 on page 2 WITHOUT Link header!
          res.writeHead(304, { ETag: '"cap300-p2-v1"' });
          res.end();
          return;
        }
        res.writeHead(200, {
          'Content-Type': 'application/json',
          ETag: '"cap300-p2-v1"',
          Link: '<http://127.0.0.1/pulls?page=3>; rel="next"',
        });
        res.end(JSON.stringify(page2Prs));
        return;
      }
      if (req.url?.includes('&page=3')) {
        page3Calls++;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify([makeRawPr(201)]));
        return;
      }
      res.writeHead(404);
      res.end('{}');
    });

    await new Promise<void>(r => ghServer.listen(0, '127.0.0.1', () => r()));
    const ghPort = (ghServer.address() as { port: number }).port;

    try {
      const client = new GitHubClient({
        auth: {
          mode: 'pat',
          apiBaseUrl: `http://127.0.0.1:${ghPort}`,
          pat: 'github_pat_r3cap_1234567890abcdef',
          app: { appId: '', installationId: '' },
        },
        allowInsecureLocalForTests: true,
      });

      // Poll 1: hits maxPages=2 -> pulls=200, pageCount=2, truncated=true
      const first = await client.listOpenPullRequests('acme', 'r3', { maxPages: 2 });
      assert.equal(first.pulls.length, 200);
      assert.equal(first.pageCount, 2);
      assert.equal(first.truncated, true);
      assert.equal(page3Calls, 0);

      // Poll 2: page 1 changes (200 OK), page 2 returns 304 WITHOUT Link -> truncated MUST STAY true!
      page1Version = 2;
      page1Etag = '"cap300-p1-v2"';
      const second = await client.listOpenPullRequests('acme', 'r3', {
        maxPages: 2,
        persistedEtag: first.etag,
        persistedEtagKey: first.etagKey,
        previousPageCount: first.pageCount,
        previousTruncated: first.truncated,
      });
      assert.equal(second.notModified, false);
      assert.equal(second.pulls.length, 200);
      assert.equal(second.pageCount, 2);
      assert.equal(second.truncated, true, 'Capped page 2 returning 304 MUST NEVER flip truncated from true to false!');
      assert.equal(page3Calls, 0);

      // Poll 3: both page 1 and page 2 return 304 -> notModified=true AND truncated MUST STILL BE true!
      const third = await client.listOpenPullRequests('acme', 'r3', {
        maxPages: 2,
        persistedEtag: second.etag,
        persistedEtagKey: second.etagKey,
        previousPageCount: second.pageCount,
        previousTruncated: second.truncated,
      });
      assert.equal(third.notModified, true);
      assert.equal(third.truncated, true);
    } finally {
      await new Promise<void>(r => ghServer.close(() => r()));
    }
  });

  it('[R3-3 P2] CLI pre-create classifier recognizes real Botmux production stderr formats (EN & ZH) and allows retry', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-r3-p2-cli-'));
    const pluginHome = join(tmp, 'plugin');
    const botmuxHome = join(tmp, 'botmux');
    const dataDir = join(tmp, 'data');
    await fsp.mkdir(botmuxHome, { recursive: true, mode: 0o700 });
    await fsp.mkdir(dataDir, { recursive: true, mode: 0o700 });
    await fsp.writeFile(join(botmuxHome, 'bots.json'), JSON.stringify([{ larkAppId: 'cli_creator1', larkAppSecret: 's1', brand: 'feishu' }]), { mode: 0o600 });

    const ghClient = new GitHubClient({
      auth: { mode: 'pat', apiBaseUrl: 'http://127.0.0.1:1', pat: 'github_pat_r3cli_1234567890abcdef', app: { appId: '', installationId: '' } },
      allowInsecureLocalForTests: true,
    });

    const realBotmuxErrors = [
      '--working-dir Directory does not exist: /definitely-absent\n',
      '--working-dir 目录不存在：/definitely-absent\n',
      '无法解析的 --bot 引用: cli_missing\n可用 bot：\n',
      '--kickoff-bot 与 --kickoff-prompt 必须同时提供且不能为空。\n',
      '--kickoff-bot 未匹配到本机 bot: ou_missing123\n',
      '--kickoff-bot 匹配到多个本机 bot，请检查 bots-info.json: ou_dup123\n',
      'botmux create-group is unavailable: apiOnly transport disabled\n',
    ];

    try {
      const stateStore = new StateStore(pluginHome);
      const rule = makeRule({ kickoffBotAppId: undefined, setTopNotice: false });

      for (let i = 0; i < realBotmuxErrors.length; i++) {
        let calls = 0;
        const prNum = 300 + i;
        const bridge = new HostBridge({
          stateStore,
          discovery: { botmuxHome, dataDir },
          cliExec: async () => {
            calls++;
            if (calls === 1) {
              return { exitCode: 1, stdout: '', stderr: realBotmuxErrors[i]! };
            }
            return {
              exitCode: 0,
              stdout: `oc_real_ok_${prNum}\n{"success":true,"chatCreated":true,"chatId":"oc_real_ok_${prNum}"}\n`,
              stderr: '',
            };
          },
        });
        await assert.rejects(() => bridge.ensurePrReviewGroup({ rule, pr: makePrInfo(prNum), githubClient: ghClient }));
        assert.equal(
          (await stateStore.load()).prGroups[`acme/r3#${prNum}`]?.createAttempt,
          undefined,
          `Real Botmux pre-create error must clear outcomeUnknown: ${realBotmuxErrors[i]!.trim()}`,
        );
        const ok = await bridge.ensurePrReviewGroup({ rule, pr: makePrInfo(prNum), githubClient: ghClient });
        assert.equal(ok.record.chatId, `oc_real_ok_${prNum}`);
        assert.equal(calls, 2);
      }
    } finally {
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[R3-4 P2] StateStore fails closed with StateCorruptError on non-string values inside processedEvents / processedDeliveries', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-r3-p2-state-'));
    try {
      const store = new StateStore(tmp);
      const corruptEventsJson = JSON.stringify({
        schemaVersion: 1,
        repos: {},
        prGroups: {},
        processedEvents: { 'acme/r3#1@aaa:opened:g1': 1700000000 },
        processedDeliveries: { 'd-1': '2026-11-26T00:00:00Z' },
        rateLimits: {},
        service: { mode: 'dormant', activeRepoCount: 0 },
      });
      await fsp.writeFile(store.statePath, corruptEventsJson, { mode: 0o600 });
      await assert.rejects(() => store.load(), StateCorruptError);
      await assert.rejects(() => store.update(() => {}), StateCorruptError);
      assert.equal(await fsp.readFile(store.statePath, 'utf8'), corruptEventsJson, 'Corrupt state must remain untouched');

      const corruptDelivJson = JSON.stringify({
        schemaVersion: 1,
        repos: {},
        prGroups: {},
        processedEvents: {},
        processedDeliveries: { 'd-bad': true },
        rateLimits: {},
        service: { mode: 'dormant', activeRepoCount: 0 },
      });
      await fsp.writeFile(store.statePath, corruptDelivJson, { mode: 0o600 });
      await assert.rejects(() => store.load(), StateCorruptError);
    } finally {
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[R3-5 P2] lockfile validates durable process-start + boot identity, immediately reclaiming PID-reused orphan locks while protecting live owner', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-r3-p2-lock-'));
    // Spawn a genuine live unrelated child process to simulate PID reuse!
    const unrelatedChild = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 30000)'], {
      stdio: 'ignore',
    });
    assert.ok(unrelatedChild.pid && unrelatedChild.pid > 1);
    // Wait briefly so child is running and has its own /proc/<pid>/stat entry
    await new Promise(r => setTimeout(r, 80));

    try {
      const childIdentity = readDurableProcessIdentity(unrelatedChild.pid);
      assert.ok(childIdentity, 'Linux/POSIX live child must resolve durable processIdentity');

      // Case A: Orphan lock holding unrelated child's live PID with DIFFERENT processIdentity (PID reuse / reboot!)
      const reusedLockPath = join(tmp, 'reused.lock');
      await fsp.writeFile(
        reusedLockPath,
        JSON.stringify({
          pid: unrelatedChild.pid,
          startedAt: Date.now() - 10_000,
          heartbeatAt: Date.now() - 10_000,
          processIdentity: '00000000-0000-0000-0000-000000000000:1',
          nonce: 'orphan-reused-nonce',
        }),
        { mode: 0o600 },
      );
      // Must reclaim IMMEDIATELY even though unrelatedChild is still alive and age < staleMs!
      const lockA = await acquireSecureLock(reusedLockPath, { timeoutMs: 1000, staleMs: 90_000, heartbeatIntervalMs: 0 });
      assert.equal(await lockA.verifyOwned(), true);
      await lockA.release();

      // Case B: Legacy orphan lock (no processIdentity) with unrelated live child PID aged > staleMs (10 minutes old)
      const legacyLockPath = join(tmp, 'legacy.lock');
      const tenMinAgo = Date.now() - 600_190;
      await fsp.writeFile(
        legacyLockPath,
        JSON.stringify({
          pid: unrelatedChild.pid,
          startedAt: tenMinAgo,
          nonce: 'legacy-orphan-nonce',
        }),
        { mode: 0o600 },
      );
      await fsp.utimes(legacyLockPath, new Date(tenMinAgo), new Date(tenMinAgo));
      const lockB = await acquireSecureLock(legacyLockPath, { timeoutMs: 1000, staleMs: 90_000, heartbeatIntervalMs: 0 });
      assert.equal(await lockB.verifyOwned(), true);
      await lockB.release();

      // Case C: Genuine live owner acquired via acquireSecureLock (records matching processIdentity) is NEVER stolen by age!
      let fakeNow = Date.now();
      const liveLockPath = join(tmp, 'live.lock');
      const lockC = await acquireSecureLock(liveLockPath, { timeoutMs: 1000, staleMs: 90_000, heartbeatIntervalMs: 0, now: () => fakeNow });
      fakeNow += 600_000;
      await assert.rejects(
        () => acquireSecureLock(liveLockPath, { timeoutMs: 120, staleMs: 90_000, pollMs: 25, heartbeatIntervalMs: 0, now: () => fakeNow }),
        (err: unknown) => err instanceof SecurityFsError && err.code === 'LOCK_TIMEOUT',
      );
      await lockC.release();
    } finally {
      unrelatedChild.kill('SIGKILL');
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[R3-6 P2] disable -> re-enable bumps per-repo epoch and aborts queued webhooks accepted before disable', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-r3-p2-epoch-'));
    const pluginHome = join(tmp, 'plugin');
    const botmuxHome = join(tmp, 'botmux');
    const dataDir = join(tmp, 'data');
    const daemonsDir = join(dataDir, 'dashboard-daemons');
    await fsp.mkdir(daemonsDir, { recursive: true, mode: 0o700 });
    await fsp.mkdir(botmuxHome, { recursive: true, mode: 0o700 });
    const dashSecret = 'z'.repeat(43);
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
        if (req.method === 'POST' && req.url === '/api/groups/oc_80/messages') {
          closeMessagesSent++;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, chatId: 'oc_80', messageId: 'om_cl80', requestId: body.requestId, replayed: false }));
          return;
        }
        res.writeHead(404);
        res.end('{}');
      });
    });
    const ghServer = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json', ETag: '"e80"' });
      res.end(JSON.stringify([makeRawPr(80, 'acme/r3', 'open')]));
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
      s.repos['acme/r3'] = {
        baselineCapturedAt: '2026-11-26T00:00:00Z',
        knownPrs: { '80': { headSha: 'a'.repeat(40), draft: false, state: 'open', updatedAt: '2026-11-26T00:00:00Z' } },
      };
      s.prGroups['acme/r3#80'] = {
        status: 'active',
        repo: 'acme/r3',
        prNumber: 80,
        chatId: 'oc_80',
        groupName: 'PR #80',
        creatorLarkAppId: 'cli_creator1',
        kickoffMessageId: 'om_k80',
        kickoffVerified: true,
        topNoticeSet: true,
        lifecycleGeneration: 1,
        lastHeadSha: 'a'.repeat(40),
        createdAt: '2026-11-26T00:00:00Z',
        updatedAt: '2026-11-26T00:00:00Z',
      };
    });

    const activeCfg = applyConfigPatch(
      createDefaultConfig(),
      {
        github: { mode: 'pat', apiBaseUrl: `http://127.0.0.1:${ghPort}`, pat: 'github_pat_r3ep_1234567890abcdef' },
        webhook: { enabled: true, secret: WH_SECRET },
        repos: [makeRule({ onPrClosed: true })],
      },
      { allowInsecureLocalApiForTests: true },
    );
    const dormantCfg = applyConfigPatch(
      activeCfg,
      { repos: [makeRule({ enabled: false, onPrClosed: true })] },
      { allowInsecureLocalApiForTests: true },
    );
    await savePluginConfig(pluginHome, activeCfg, { allowInsecureLocalApiForTests: true });

    const svc = await startGitHubService({
      pluginHome,
      port: 0,
      discovery: { botmuxHome, dataDir },
      allowInsecureLocalApiForTests: true,
    });

    try {
      // Queue a blocker on PR #80
      let releaseBlocker!: () => void;
      const blocker = new Promise<void>(r => {
        releaseBlocker = r;
      });
      const q = (svc.watcher as unknown as { queue: { enqueue: (k: string, fn: () => Promise<void>) => Promise<void> } }).queue;
      const blockerDone = q.enqueue('acme/r3#80', async () => blocker);

      // Deliver signed `closed` webhook BEFORE disable -> HTTP 202
      const body = Buffer.from(
        JSON.stringify({
          action: 'closed',
          repository: { full_name: 'acme/r3' },
          pull_request: makeRawPr(80, 'acme/r3', 'closed'),
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
          'X-GitHub-Delivery': 'd-pre-disable-80',
          'X-Hub-Signature-256': signWebhook(body),
        },
        body,
      });
      assert.equal(whResp.status, 202);

      // Transition active -> dormant -> active (disable then re-enable!) while webhook is STILL queued!
      await savePluginConfig(pluginHome, dormantCfg, { allowInsecureLocalApiForTests: true });
      assert.equal((await svc.reload()).mode, 'dormant');
      await savePluginConfig(pluginHome, activeCfg, { allowInsecureLocalApiForTests: true });
      assert.equal((await svc.reload()).mode, 'active');

      // Release blocker -> pre-disable queued webhook MUST abort due to per-repo epoch change!
      releaseBlocker();
      await blockerDone;
      await new Promise(r => setTimeout(r, 80));

      const st = await stateStore.load();
      assert.equal(closeMessagesSent, 0, 'Pre-disable queued webhook MUST NOT run after disable -> re-enable');
      assert.equal(st.prGroups['acme/r3#80']?.status, 'active');
      assert.equal(st.repos['acme/r3']?.knownPrs['80']?.state, 'open');
      assert.equal(st.processedDeliveries['d-pre-disable-80'], undefined);
    } finally {
      await svc.close();
      await Promise.all([
        new Promise<void>(r => daemonServer.close(() => r())),
        new Promise<void>(r => ghServer.close(() => r())),
      ]);
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });
});

describe('PR #1 Round-4 Pagination 304 Link-Transition Regressions', () => {
  it('[R4 P1] 2->1 shrink via page-1 304 with explicit terminal Link reconciles closed PR #101 in watcher and returns steady-state 304 afterward', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-r4-2to1-'));
    const pluginHome = join(tmp, 'plugin');
    const botmuxHome = join(tmp, 'botmux');
    const dataDir = join(tmp, 'data');
    const daemonsDir = join(dataDir, 'dashboard-daemons');
    await fsp.mkdir(daemonsDir, { recursive: true, mode: 0o700 });
    await fsp.mkdir(botmuxHome, { recursive: true, mode: 0o700 });
    const dashSecret = 'k'.repeat(43);
    await fsp.writeFile(join(botmuxHome, '.dashboard-secret'), `${dashSecret}\n`, { mode: 0o600 });
    await fsp.writeFile(join(botmuxHome, 'bots.json'), JSON.stringify([{ larkAppId: 'cli_creator1', larkAppSecret: 's1', brand: 'feishu' }]), { mode: 0o600 });

    const page1Prs = Array.from({ length: 100 }, (_, i) => makeRawPr(i + 1, 'acme/r3', 'open'));
    let pr101Open = true;
    let page1Calls = 0;
    let page2Calls = 0;
    let page1TerminalLinkHeader = '<http://127.0.0.1/pulls?page=1>; rel="first"';
    let closeMessagesSent = 0;

    const ghServer = http.createServer((req, res) => {
      if (req.url?.includes('&page=1')) {
        page1Calls++;
        if (req.headers['if-none-match'] === '"r4-p1"') {
          const headers: Record<string, string> = { ETag: '"r4-p1"' };
          if (pr101Open) {
            headers.Link = '<http://127.0.0.1/pulls?page=2>; rel="next"';
          } else if (page1TerminalLinkHeader) {
            headers.Link = page1TerminalLinkHeader;
          }
          res.writeHead(304, headers);
          res.end();
          return;
        }
        res.writeHead(200, {
          'Content-Type': 'application/json',
          ETag: '"r4-p1"',
          ...(pr101Open ? { Link: '<http://127.0.0.1/pulls?page=2>; rel="next"' } : {}),
        });
        res.end(JSON.stringify(page1Prs));
        return;
      }
      if (req.url?.includes('&page=2')) {
        page2Calls++;
        res.writeHead(200, { 'Content-Type': 'application/json', ETag: '"r4-p2"' });
        res.end(JSON.stringify(pr101Open ? [makeRawPr(101, 'acme/r3', 'open')] : []));
        return;
      }
      if (req.url === '/repos/acme/r3/pulls/101') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(makeRawPr(101, 'acme/r3', pr101Open ? 'open' : 'closed')));
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
        if (req.method === 'POST' && req.url === '/api/groups/oc_r4_101/messages') {
          closeMessagesSent++;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, chatId: 'oc_r4_101', messageId: 'om_r4_cl101', requestId: body.requestId, replayed: false }));
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
        s.prGroups['acme/r3#101'] = {
          status: 'active',
          repo: 'acme/r3',
          prNumber: 101,
          chatId: 'oc_r4_101',
          groupName: 'PR #101 acme/r3',
          creatorLarkAppId: 'cli_creator1',
          kickoffMessageId: 'om_k101',
          kickoffVerified: true,
          topNoticeSet: true,
          lifecycleGeneration: 1,
          lastHeadSha: 'a'.repeat(40),
          createdAt: '2026-11-26T00:00:00Z',
          updatedAt: '2026-11-26T00:00:00Z',
        };
      });

      const cfg = applyConfigPatch(
        createDefaultConfig(),
        {
          github: { mode: 'pat', apiBaseUrl: `http://127.0.0.1:${ghPort}`, pat: 'github_pat_r4_2to1_1234567890abcdef' },
          repos: [makeRule({ onPrClosed: true })],
        },
        { allowInsecureLocalApiForTests: true },
      );
      const watcher = new GitHubWatcher({ config: cfg, stateStore, discovery: { botmuxHome, dataDir }, allowInsecureLocalApiForTests: true });

      // Poll 1: baseline captures 101 open PRs across 2 pages (non-truncated!)
      const poll1 = await watcher.sync();
      assert.equal(poll1.actions[0]?.action, 'baseline_captured');
      assert.equal((await stateStore.load()).repos['acme/r3']?.lastPageCount, 2);
      assert.equal(page1Calls, 1);
      assert.equal(page2Calls, 1);

      // PR #101 closes -> Poll 2 gets page-1 304 with explicit terminal Link (rel="first")!
      // Must NOT return skip_not_modified; must reconcile PR #101 closed and evict page 2!
      pr101Open = false;
      const poll2 = await watcher.sync();
      assert.equal(poll2.ok, true);
      assert.ok(poll2.actions.some(a => a.prNumber === 101 && a.action === 'notify_pr_closed'));
      assert.equal(closeMessagesSent, 1);
      const stAfterClose = await stateStore.load();
      assert.equal(stAfterClose.prGroups['acme/r3#101']?.status, 'closed');
      assert.equal(stAfterClose.repos['acme/r3']?.knownPrs['101']?.state, 'closed');
      assert.equal(stAfterClose.repos['acme/r3']?.lastPageCount, 1);

      // Poll 3 (steady-state with terminal Link) & Poll 4 (steady-state with no Link) -> both return skip_not_modified with ZERO extra page-2 calls!
      const poll3 = await watcher.sync();
      assert.equal(poll3.actions[0]?.action, 'skip_not_modified');
      page1TerminalLinkHeader = '';
      const poll4 = await watcher.sync();
      assert.equal(poll4.actions[0]?.action, 'skip_not_modified');
      assert.equal(page1Calls, 4);
      assert.equal(page2Calls, 1, 'Steady-state polls after 2->1 shrink must NOT hit page 2');
    } finally {
      await Promise.all([
        new Promise<void>(r => ghServer.close(() => r())),
        new Promise<void>(r => daemonServer.close(() => r())),
      ]);
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('[R4 P1] handles 3->2 shrink via page-2 304 terminal Link, 3->1 shrink via page-1 304 terminal Link, and maxPages=1 capped->terminal transitions', async () => {
    const page1Prs = Array.from({ length: 100 }, (_, i) => makeRawPr(i + 1));
    const page2Prs = Array.from({ length: 100 }, (_, i) => makeRawPr(101 + i));
    const page3Prs = [makeRawPr(201)];

    let mode: '3pages' | '2pages_terminal' | '1page_terminal' | '1page_nolink' = '3pages';
    let page3Calls = 0;

    const ghServer = http.createServer((req, res) => {
      if (req.url?.includes('&page=1')) {
        if (req.headers['if-none-match'] === '"p1"') {
          const headers: Record<string, string> = { ETag: '"p1"' };
          if (mode === '3pages' || mode === '2pages_terminal') {
            headers.Link = '<http://127.0.0.1/pulls?page=2>; rel="next"';
          } else if (mode === '1page_terminal') {
            headers.Link = '<http://127.0.0.1/pulls?page=1>; rel="first"';
          }
          res.writeHead(304, headers);
          res.end();
          return;
        }
        res.writeHead(200, {
          'Content-Type': 'application/json',
          ETag: '"p1"',
          Link: '<http://127.0.0.1/pulls?page=2>; rel="next"',
        });
        res.end(JSON.stringify(page1Prs));
        return;
      }
      if (req.url?.includes('&page=2')) {
        if (req.headers['if-none-match'] === '"p2"') {
          const headers: Record<string, string> = { ETag: '"p2"' };
          if (mode === '3pages') {
            headers.Link = '<http://127.0.0.1/pulls?page=3>; rel="next"';
          } else {
            headers.Link = '<http://127.0.0.1/pulls?page=1>; rel="prev"';
          }
          res.writeHead(304, headers);
          res.end();
          return;
        }
        res.writeHead(200, {
          'Content-Type': 'application/json',
          ETag: '"p2"',
          Link: '<http://127.0.0.1/pulls?page=3>; rel="next"',
        });
        res.end(JSON.stringify(page2Prs));
        return;
      }
      if (req.url?.includes('&page=3')) {
        page3Calls++;
        res.writeHead(200, { 'Content-Type': 'application/json', ETag: '"p3"' });
        res.end(JSON.stringify(page3Prs));
        return;
      }
      res.writeHead(404);
      res.end('{}');
    });

    await new Promise<void>(r => ghServer.listen(0, '127.0.0.1', () => r()));
    const ghPort = (ghServer.address() as { port: number }).port;

    try {
      const client = new GitHubClient({
        auth: { mode: 'pat', apiBaseUrl: `http://127.0.0.1:${ghPort}`, pat: 'github_pat_r4_3to2_1234567890abcdef', app: { appId: '', installationId: '' } },
        allowInsecureLocalForTests: true,
      });

      // 1. 3 pages initial fetch (201 PRs)
      const r1 = await client.listOpenPullRequests('acme', 'r3');
      assert.equal(r1.pulls.length, 201);
      assert.equal(r1.pageCount, 3);
      assert.equal(r1.truncated, false);
      assert.equal(page3Calls, 1);

      // 2. Shrink 3->2 via page-2 304 with explicit terminal Link (rel="prev") -> MUST return notModified=false, pulls=200, pageCount=2!
      mode = '2pages_terminal';
      const r2 = await client.listOpenPullRequests('acme', 'r3', {
        persistedEtag: r1.etag,
        persistedEtagKey: r1.etagKey,
        previousPageCount: r1.pageCount,
        previousTruncated: r1.truncated,
      });
      assert.equal(r2.notModified, false);
      assert.equal(r2.pulls.length, 200);
      assert.equal(r2.pageCount, 2);
      assert.equal(r2.truncated, false);
      assert.equal(page3Calls, 1);

      // 3. Steady-state 2 pages -> returns notModified=true, pageCount=2, zero page-3 calls!
      const r3 = await client.listOpenPullRequests('acme', 'r3', {
        persistedEtag: r2.etag,
        persistedEtagKey: r2.etagKey,
        previousPageCount: r2.pageCount,
        previousTruncated: r2.truncated,
      });
      assert.equal(r3.notModified, true);
      assert.equal(r3.pageCount, 2);
      assert.equal(page3Calls, 1);

      // 4. Shrink 2->1 via page-1 304 terminal Link -> returns notModified=false, pulls=100, pageCount=1!
      mode = '1page_terminal';
      const r4 = await client.listOpenPullRequests('acme', 'r3', {
        persistedEtag: r3.etag,
        persistedEtagKey: r3.etagKey,
        previousPageCount: r3.pageCount,
        previousTruncated: r3.truncated,
      });
      assert.equal(r4.notModified, false);
      assert.equal(r4.pulls.length, 100);
      assert.equal(r4.pageCount, 1);
      assert.equal(r4.truncated, false);

      // 5. Steady-state 1 page with no Link -> returns notModified=true, pageCount=1!
      mode = '1page_nolink';
      const r5 = await client.listOpenPullRequests('acme', 'r3', {
        persistedEtag: r4.etag,
        persistedEtagKey: r4.etagKey,
        previousPageCount: r4.pageCount,
        previousTruncated: r4.truncated,
      });
      assert.equal(r5.notModified, true);
      assert.equal(r5.pageCount, 1);
      assert.equal(r5.truncated, false);

      // 6. Separate client testing maxPages=1 capped -> explicit terminal -> steady-state 304 (stays truncated=false)
      mode = '3pages';
      const cappedClient = new GitHubClient({
        auth: { mode: 'pat', apiBaseUrl: `http://127.0.0.1:${ghPort}`, pat: 'github_pat_r4_cap1_1234567890abcdef', app: { appId: '', installationId: '' } },
        allowInsecureLocalForTests: true,
      });
      const c1 = await cappedClient.listOpenPullRequests('acme', 'r3', { maxPages: 1 });
      assert.equal(c1.pulls.length, 100);
      assert.equal(c1.truncated, true);

      mode = '1page_terminal';
      const c2 = await cappedClient.listOpenPullRequests('acme', 'r3', {
        maxPages: 1,
        persistedEtag: c1.etag,
        persistedEtagKey: c1.etagKey,
        previousPageCount: c1.pageCount,
        previousTruncated: c1.truncated,
      });
      assert.equal(c2.notModified, false);
      assert.equal(c2.pulls.length, 100);
      assert.equal(c2.truncated, false);

      mode = '1page_nolink';
      const c3 = await cappedClient.listOpenPullRequests('acme', 'r3', {
        maxPages: 1,
        persistedEtag: c2.etag,
        persistedEtagKey: c2.etagKey,
        previousPageCount: c2.pageCount,
        previousTruncated: c2.truncated,
      });
      assert.equal(c3.notModified, true);
      assert.equal(c3.truncated, false, 'Once verified_terminal, subsequent 304 without Link must stay truncated=false');
    } finally {
      await new Promise<void>(r => ghServer.close(() => r()));
    }
  });
});

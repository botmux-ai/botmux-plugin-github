import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHmac } from 'node:crypto';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDefaultConfig, applyConfigPatch } from '../../src/config/schema.ts';
import { savePluginConfig } from '../../src/config/store.ts';
import { startGitHubService } from '../../src/service/runner.ts';
import { loopbackRequest } from '../../src/security/net.ts';
import { verifyDaemonIpcHeaders } from '../../src/host/discovery.ts';
import { StateStore } from '../../src/state/store.ts';

const WEBHOOK_SECRET = 'whsec_Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4';

function makeRawPr(opts: {
  repo: string;
  number: number;
  title: string;
  headSha: string;
  draft?: boolean;
  state?: 'open' | 'closed';
  merged?: boolean;
}) {
  return {
    number: opts.number,
    title: opts.title,
    body: `Description for PR #${opts.number}`,
    state: opts.state ?? 'open',
    draft: opts.draft === true,
    merged: opts.merged === true,
    html_url: `https://github.com/${opts.repo}/pull/${opts.number}`,
    user: { login: 'alice' },
    base: { ref: 'main', repo: { full_name: opts.repo } },
    head: {
      ref: `feat/pr-${opts.number}`,
      sha: opts.headSha,
      repo: { full_name: opts.repo, fork: false },
    },
    labels: [],
    maintainer_can_modify: true,
    created_at: '2026-11-25T00:00:00Z',
    updated_at: '2026-11-25T00:05:00Z',
  };
}

async function waitFor(predicate: () => Promise<boolean> | boolean, timeoutMs = 4000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await predicate()) return;
    await new Promise(r => setTimeout(r, 40));
  }
  throw new Error(`Timed out after ${timeoutMs}ms waiting for condition`);
}

describe('End-to-end Watcher: strict dormant default, first-run baseline zero-storm, webhook + poller shared queue, onNewCommit & onPrClosed', () => {
  it('stays strictly dormant with zero requests until enabled, captures baseline without group storm, then handles new PR, draft->ready, webhook race, commit & close', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-gh-e2e-watcher-'));
    const pluginHome = join(tmp, 'plugin-home');
    const botmuxHome = join(tmp, 'botmux-home');
    const dataDir = join(tmp, 'data');
    const daemonsDir = join(dataDir, 'dashboard-daemons');
    await fsp.mkdir(daemonsDir, { recursive: true, mode: 0o700 });
    await fsp.mkdir(botmuxHome, { recursive: true, mode: 0o700 });

    const dashSecret = 's'.repeat(43);
    await fsp.writeFile(join(botmuxHome, '.dashboard-secret'), `${dashSecret}\n`, { mode: 0o600 });
    await fsp.writeFile(
      join(botmuxHome, 'bots.json'),
      JSON.stringify([
        { larkAppId: 'cli_creator1', larkAppSecret: 'sec_creator', brand: 'feishu', name: 'Creator' },
        { larkAppId: 'cli_reviewer2', larkAppSecret: 'sec_reviewer', brand: 'feishu', name: 'Reviewer' },
      ]),
      { mode: 0o600 },
    );

    // Track all mock GitHub API & Botmux daemon calls
    let githubCalls = 0;
    let daemonCalls = 0;
    const createdGroups: Array<{ chatId: string; name: string; kickoffPrompt?: string }> = [];
    const postedMessages: Array<{ chatId: string; requestId: string; content: string }> = [];
    const topNotices: Array<{ chatId: string; messageId: string }> = [];

    let currentOpenPrs = [
      makeRawPr({ repo: 'acme/platform', number: 1, title: 'Old PR 1', headSha: '1'.repeat(40) }),
      makeRawPr({ repo: 'acme/platform', number: 2, title: 'Old PR 2', headSha: '2'.repeat(40) }),
      makeRawPr({ repo: 'acme/platform', number: 3, title: 'Old Draft PR 3', headSha: '3'.repeat(40), draft: true }),
    ];
    const prByNumber = new Map<number, ReturnType<typeof makeRawPr>>();
    for (const p of currentOpenPrs) prByNumber.set(p.number, p);
    let githubEtag = '"etag-1"';

    const githubServer = http.createServer((req, res) => {
      githubCalls++;
      if (req.url?.startsWith('/repos/acme/platform/pulls?')) {
        if (req.headers['if-none-match'] === githubEtag) {
          res.writeHead(304, { ETag: githubEtag });
          res.end();
          return;
        }
        res.writeHead(200, {
          'Content-Type': 'application/json',
          ETag: githubEtag,
          'X-RateLimit-Resource': 'core',
          'X-RateLimit-Limit': '5000',
          'X-RateLimit-Remaining': '4990',
          'X-RateLimit-Reset': String(Math.floor(Date.now() / 1000) + 3600),
        });
        res.end(JSON.stringify(currentOpenPrs));
        return;
      }
      const singleMatch = /^\/repos\/acme\/platform\/pulls\/(\d+)$/.exec(req.url ?? '');
      if (singleMatch) {
        const pr = prByNumber.get(Number(singleMatch[1]));
        if (!pr) {
          res.writeHead(404);
          res.end('{}');
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(pr));
        return;
      }
      res.writeHead(404);
      res.end('{}');
    });

    const seenNonces = new Map<string, number>();
    let chatCounter = 100;
    let msgCounter = 200;
    let daemonPort = 0;

    const daemonServer = http.createServer((req, res) => {
      daemonCalls++;
      const ok = verifyDaemonIpcHeaders(
        req.headers,
        dashSecret,
        req.method ?? 'GET',
        req.url ?? '/',
        daemonPort,
        seenNonces,
      );
      if (!ok) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'unauthorized' }));
        return;
      }

      const chunks: Buffer[] = [];
      req.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      req.on('end', () => {
        const body = chunks.length > 0 ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
        if (req.method === 'GET' && req.url === '/api/groups') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              chats: createdGroups.map(g => ({ chatId: g.chatId, name: g.name, chatStatus: 'normal' })),
            }),
          );
          return;
        }
        if (req.method === 'POST' && req.url === '/api/groups/create') {
          const chatId = `oc_${++chatCounter}`;
          const kickoffMessageId = `om_${++msgCounter}`;
          createdGroups.push({
            chatId,
            name: body.name,
            kickoffPrompt: body.kickoffPrompt,
          });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              ok: true,
              chatId,
              shareLink: `https://applink.feishu.cn/client/chat/open?openChatId=${chatId}`,
              kickoffMessageId,
              kickoffError: null,
            }),
          );
          return;
        }
        const readMsgMatch = /^\/api\/groups\/(oc_[^/]+)\/messages\/(om_[^/]+)$/.exec(req.url ?? '');
        if (req.method === 'GET' && readMsgMatch) {
          const group = createdGroups.find(g => g.chatId === readMsgMatch[1]);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              ok: true,
              messageId: readMsgMatch[2],
              chatId: readMsgMatch[1],
              deleted: false,
              text: group?.kickoffPrompt ?? '',
            }),
          );
          return;
        }
        const topMatch = /^\/api\/groups\/(oc_[^/]+)\/top-notice$/.exec(req.url ?? '');
        if (req.method === 'POST' && topMatch) {
          topNotices.push({ chatId: topMatch[1]!, messageId: body.messageId });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
          return;
        }
        const sendMatch = /^\/api\/groups\/(oc_[^/]+)\/messages$/.exec(req.url ?? '');
        if (req.method === 'POST' && sendMatch) {
          postedMessages.push({
            chatId: sendMatch[1]!,
            requestId: body.requestId,
            content: body.content,
          });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              ok: true,
              chatId: sendMatch[1],
              messageId: `om_${++msgCounter}`,
              requestId: body.requestId,
              replayed: false,
            }),
          );
          return;
        }
        res.writeHead(404);
        res.end('{}');
      });
    });

    await new Promise<void>(r => githubServer.listen(0, '127.0.0.1', () => r()));
    await new Promise<void>(r => daemonServer.listen(0, '127.0.0.1', () => r()));
    const ghPort = (githubServer.address() as { port: number }).port;
    daemonPort = (daemonServer.address() as { port: number }).port;

    await fsp.writeFile(
      join(daemonsDir, 'cli_creator1.json'),
      JSON.stringify({
        larkAppId: 'cli_creator1',
        ipcPort: daemonPort,
        lastHeartbeat: Date.now(),
        resolvedAllowedUsers: ['ou_owner1'],
      }),
      { mode: 0o600 },
    );

    // 1. Start with EMPTY default config => MUST be strictly dormant (0 GitHub calls, 0 daemon calls!)
    const svc = await startGitHubService({
      pluginHome,
      port: 0,
      discovery: { botmuxHome, dataDir },
      allowInsecureLocalApiForTests: true,
      configPollIntervalMs: 200,
    });

    try {
      const health1 = await loopbackRequest({
        port: svc.port,
        method: 'GET',
        path: '/health',
        headers: { Host: `127.0.0.1:${svc.port}` },
      });
      assert.equal(health1.status, 200);
      assert.equal(JSON.parse(health1.body.toString('utf8')).mode, 'dormant');

      await new Promise(r => setTimeout(r, 250));
      assert.equal(githubCalls, 0, 'Dormant mode MUST make zero GitHub API calls');
      assert.equal(daemonCalls, 0, 'Dormant mode MUST make zero Feishu/daemon calls');

      // 2. Enable repo rule atomically => transitions to active & captures baseline of PRs #1, #2, #3 with ZERO groups created!
      const enabledCfg = applyConfigPatch(
        createDefaultConfig(),
        {
          github: {
            mode: 'pat',
            apiBaseUrl: `http://127.0.0.1:${ghPort}`,
            pat: 'github_pat_watcherIntegrationToken1234567890',
          },
          webhook: { enabled: true, secret: WEBHOOK_SECRET },
          service: { pollIntervalSec: 60 },
          repos: [
            {
              repo: 'acme/platform',
              enabled: true,
              baseBranches: ['main'],
              triggerOn: ['opened', 'ready_for_review'],
              ignoreDrafts: true,
              creatorBotAppId: 'cli_creator1',
              memberBotAppIds: ['cli_reviewer2'],
              kickoffBotAppId: 'cli_reviewer2',
              setTopNotice: true,
              onNewCommit: true,
              onPrClosed: true,
            },
          ],
        },
        { allowInsecureLocalApiForTests: true },
      );
      await savePluginConfig(pluginHome, enabledCfg, { allowInsecureLocalApiForTests: true });
      await svc.reload();

      const stateStore = new StateStore(pluginHome);
      await waitFor(async () => Boolean((await stateStore.load()).repos['acme/platform']?.baselineCapturedAt));
      assert.equal(createdGroups.length, 0, 'First-run baseline MUST NOT create groups for historical PRs #1/#2/#3');

      // 3. Subsequent poll with unchanged ETag returns 304 Not Modified
      const sync304 = await svc.watcher.sync();
      assert.equal(sync304.actions[0]?.action, 'skip_not_modified');

      // 4. Open PR #4 + flip baseline draft PR #3 -> ready_for_review (leaving #1/#2 untouched)
      const pr3Ready = makeRawPr({ repo: 'acme/platform', number: 3, title: 'Old Draft PR 3', headSha: '3'.repeat(40), draft: false });
      const pr4New = makeRawPr({ repo: 'acme/platform', number: 4, title: 'Brand New PR 4', headSha: '4'.repeat(40), draft: false });
      currentOpenPrs = [currentOpenPrs[0]!, currentOpenPrs[1]!, pr3Ready, pr4New];
      prByNumber.set(3, pr3Ready);
      prByNumber.set(4, pr4New);
      githubEtag = '"etag-2"';

      const sync2 = await svc.watcher.sync();
      assert.equal(sync2.ok, true);
      assert.equal(createdGroups.length, 2, 'Only PR #3 (ready_for_review) and PR #4 (new) should get groups');
      assert.equal(topNotices.length, 2);

      // 5. Simultaneous Webhook + Poll for PR #5 shares per-PR serial queue -> strictly ONE group!
      const pr5 = makeRawPr({ repo: 'acme/platform', number: 5, title: 'Concurrent PR 5', headSha: '5'.repeat(40) });
      currentOpenPrs = [...currentOpenPrs, pr5];
      prByNumber.set(5, pr5);
      githubEtag = '"etag-3"';

      const whBody = Buffer.from(
        JSON.stringify({
          action: 'opened',
          repository: { full_name: 'acme/platform' },
          pull_request: pr5,
        }),
        'utf8',
      );
      const sig = `sha256=${createHmac('sha256', WEBHOOK_SECRET).update(whBody).digest('hex')}`;

      const [whResp, syncResp] = await Promise.all([
        loopbackRequest({
          port: svc.port,
          method: 'POST',
          path: '/webhooks/github',
          headers: {
            Host: `127.0.0.1:${svc.port}`,
            'Content-Type': 'application/json',
            'X-GitHub-Event': 'pull_request',
            'X-GitHub-Delivery': 'deliv-pr-5',
            'X-Hub-Signature-256': sig,
          },
          body: whBody,
        }),
        svc.watcher.sync(),
      ]);
      assert.equal(whResp.status, 202);
      assert.equal(syncResp.ok, true);
      await waitFor(async () => (await stateStore.load()).prGroups['acme/platform#5']?.status === 'active');
      assert.equal(createdGroups.length, 3, 'Simultaneous webhook + poll must create strictly ONE group for PR #5');

      // 6. onNewCommit for PR #4 (new headSha) -> sends 1 update, deduped on repeat
      const pr4Updated = makeRawPr({ repo: 'acme/platform', number: 4, title: 'Brand New PR 4', headSha: 'e'.repeat(40) });
      currentOpenPrs = currentOpenPrs.map(p => (p.number === 4 ? pr4Updated : p));
      prByNumber.set(4, pr4Updated);
      githubEtag = '"etag-4"';

      await svc.watcher.sync();
      assert.equal(postedMessages.length, 1);
      assert.ok(postedMessages[0]!.content.includes('New commit pushed'));
      // Repeat sync with same head must NOT send duplicate commit message
      githubEtag = '"etag-4b"';
      await svc.watcher.sync();
      assert.equal(postedMessages.length, 1);

      // 7. onPrClosed for PR #4 (disappears from open list, confirmed merged via GET /pulls/4)
      const pr4Closed = makeRawPr({
        repo: 'acme/platform',
        number: 4,
        title: 'Brand New PR 4',
        headSha: 'e'.repeat(40),
        state: 'closed',
        merged: true,
      });
      currentOpenPrs = currentOpenPrs.filter(p => p.number !== 4);
      prByNumber.set(4, pr4Closed);
      githubEtag = '"etag-5"';

      await svc.watcher.sync();
      assert.equal(postedMessages.length, 2);
      assert.ok(postedMessages[1]!.content.includes('was merged'));
      const finalState = await stateStore.load();
      assert.equal(finalState.prGroups['acme/platform#4']?.status, 'closed');
    } finally {
      await svc.close();
      await new Promise<void>(r => githubServer.close(() => r()));
      await new Promise<void>(r => daemonServer.close(() => r()));
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });
});

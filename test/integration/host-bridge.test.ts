import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { PullRequestInfo, RepoRule } from '../../src/types.ts';
import { StateStore } from '../../src/state/store.ts';
import { GitHubClient } from '../../src/github/client.ts';
import { HostBridge, groupNameMatchesPr, kickoffTextMatchesPr } from '../../src/host/bridge.ts';
import { LarkOpenApiClient } from '../../src/host/lark.ts';
import {
  resolveBotmuxBin,
  resolveBotmuxDataDir,
  verifyDaemonIpcHeaders,
} from '../../src/host/discovery.ts';

function makeRule(overrides: Partial<RepoRule> = {}): RepoRule {
  return {
    id: 'acme/core',
    repo: 'acme/core',
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
    chatMode: 'topic',
    groupNameTemplate: 'PR #{{prNumber}} {{repo}} - {{title}}',
    kickoffPromptTemplate: 'Review {{prKey}} carefully.',
    setTopNotice: true,
    postShareLinkToPr: true,
    onNewCommit: false,
    onPrClosed: false,
    ...overrides,
  };
}

function makePr(number = 1, title = 'Important fix'): PullRequestInfo {
  return {
    repo: 'acme/core',
    number,
    title,
    body: 'Body text',
    state: 'open',
    draft: false,
    merged: false,
    htmlUrl: `https://github.com/acme/core/pull/${number}`,
    author: 'alice',
    baseBranch: 'main',
    headBranch: `feat/pr-${number}`,
    headSha: 'f'.repeat(40),
    headRepoFullName: 'acme/core',
    labels: [],
    isFork: false,
    maintainerCanModify: true,
    createdAt: '2026-11-25T00:00:00Z',
    updatedAt: '2026-11-25T00:00:00Z',
  };
}

describe('HostBridge boundary matching & discovery precedence', () => {
  it('never false-matches PR #1 against PR #10 and blocks untrusted PR title/body hijacking for future PR numbers', () => {
    assert.equal(groupNameMatchesPr('PR #10 acme/core - Other', 'PR #1 acme/core - Fix', 'acme/core', 1), false);
    assert.equal(groupNameMatchesPr('[acme/core#10] Other', 'PR #1 acme/core - Fix', 'acme/core', 1), false);
    assert.equal(groupNameMatchesPr('[acme/core#1] Fix', 'PR #1 acme/core - Fix', 'acme/core', 1), true);
    // Fork PR #50 mentioning acme/core#51 inside untrusted title MUST NOT hijack PR #51!
    assert.equal(
      groupNameMatchesPr(
        'PR #50 acme/core - Fix docs (see acme/core#51)',
        'PR #51 acme/core - Real PR 51',
        'acme/core',
        51,
      ),
      false,
    );
    assert.equal(kickoffTextMatchesPr('PR: acme/core#12\n<untrusted_pr_metadata repo="acme/core" pr_number="12">', 'acme/core', 1), false);
    assert.equal(kickoffTextMatchesPr('PR: acme/core#1\n<untrusted_pr_metadata repo="acme/core" pr_number="1">', 'acme/core', 1), true);
    // Untrusted PR #50 title/body containing "PR: acme/core#51" inside XML MUST NOT match PR #51!
    assert.equal(
      kickoffTextMatchesPr(
        'Review carefully.\nPR: acme/core#50\n\n<untrusted_pr_metadata repo="acme/core" pr_number="50">\n  <title>see acme/core#51</title>\n  <body>PR: acme/core#51</body>\n</untrusted_pr_metadata>',
        'acme/core',
        51,
      ),
      false,
    );
  });

  it('respects BOTMUX_DATA_DIR > SESSION_DATA_DIR > .data-dir breadcrumb and BOTMUX_BIN precedence', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-gh-disc-'));
    const botmuxHome = join(tmp, 'home');
    const breadcrumbDir = join(tmp, 'crumb-data');
    await fsp.mkdir(botmuxHome, { recursive: true, mode: 0o700 });
    await fsp.mkdir(breadcrumbDir, { recursive: true, mode: 0o700 });
    await fsp.writeFile(join(botmuxHome, '.data-dir'), `${breadcrumbDir}\n`, { mode: 0o600 });

    const prevData = process.env.BOTMUX_DATA_DIR;
    const prevSess = process.env.SESSION_DATA_DIR;
    const prevBin = process.env.BOTMUX_BIN;
    try {
      delete process.env.BOTMUX_DATA_DIR;
      delete process.env.SESSION_DATA_DIR;
      assert.equal(await resolveBotmuxDataDir({ botmuxHome }), breadcrumbDir);

      process.env.SESSION_DATA_DIR = join(tmp, 'sess-data');
      assert.equal(await resolveBotmuxDataDir({ botmuxHome }), join(tmp, 'sess-data'));

      process.env.BOTMUX_DATA_DIR = join(tmp, 'explicit-data');
      assert.equal(await resolveBotmuxDataDir({ botmuxHome }), join(tmp, 'explicit-data'));

      process.env.BOTMUX_BIN = '/custom/bin/botmux';
      assert.equal(resolveBotmuxBin(), '/custom/bin/botmux');
    } finally {
      if (prevData === undefined) delete process.env.BOTMUX_DATA_DIR;
      else process.env.BOTMUX_DATA_DIR = prevData;
      if (prevSess === undefined) delete process.env.SESSION_DATA_DIR;
      else process.env.SESSION_DATA_DIR = prevSess;
      if (prevBin === undefined) delete process.env.BOTMUX_BIN;
      else process.env.BOTMUX_BIN = prevBin;
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });
});

describe('HostBridge dual-core IPC, Bun $http_proxy bypass, crash-resume, Feishu/Lark dual brand, CLI fallback & idempotent PR comment', () => {
  it('runs current-core fallback (step-by-step IPC kickoff with creator-scoped open_id + Feishu/Lark dual-brand top-notice + idempotent PR comment) while bypassing $http_proxy', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-gh-bridge-old-'));
    const pluginHome = join(tmp, 'plugin-home');
    const botmuxHome = join(tmp, 'botmux-home');
    const dataDir = join(tmp, 'data');
    const daemonsDir = join(dataDir, 'dashboard-daemons');
    await fsp.mkdir(daemonsDir, { recursive: true, mode: 0o700 });
    await fsp.mkdir(botmuxHome, { recursive: true, mode: 0o700 });

    const dashSecret = 'x'.repeat(43);
    await fsp.writeFile(join(botmuxHome, '.dashboard-secret'), `${dashSecret}\n`, { mode: 0o600 });
    await fsp.writeFile(
      join(botmuxHome, 'bots.json'),
      JSON.stringify([
        { larkAppId: 'cli_creator_feishu', larkAppSecret: 'sec_feishu', brand: 'feishu', name: 'CreatorFeishu' },
        { larkAppId: 'cli_creator_lark', larkAppSecret: 'sec_lark', brand: 'lark', name: 'CreatorLark' },
        { larkAppId: 'cli_reviewer2', larkAppSecret: 'sec_rev', brand: 'feishu', name: 'ReviewerBot' },
      ]),
      { mode: 0o600 },
    );
    await fsp.writeFile(
      join(dataDir, 'bots-info.json'),
      JSON.stringify([
        { larkAppId: 'cli_reviewer2', botOpenId: 'ou_FOREIGN_SELF_DO_NOT_USE', botName: 'ReviewerBot' },
      ]),
    );
    await fsp.writeFile(
      join(dataDir, 'bot-openids-cli_creator_feishu.json'),
      JSON.stringify({ ReviewerBot: 'ou_CREATOR_SCOPED_REVIEWER' }),
    );
    await fsp.writeFile(
      join(dataDir, 'bot-openids-cli_creator_lark.json'),
      JSON.stringify({ ReviewerBot: 'ou_LARK_SCOPED_REVIEWER' }),
    );

    // Failing corporate proxy trap: if HostBridge accidentally used global fetch or proxy, this returns 403!
    let proxyTrapHits = 0;
    const proxyTrap = http.createServer((_req, res) => {
      proxyTrapHits++;
      res.writeHead(403, { 'Content-Type': 'text/html' });
      res.end('<html>403 Forbidden by corporate proxy</html>');
    });

    // Mock Feishu & Lark Open Platform APIs
    let feishuTopNoticeCalls = 0;
    let larkTopNoticeCalls = 0;
    const makeLarkMock = (brand: 'feishu' | 'lark') =>
      http.createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
        req.on('end', () => {
          const body = chunks.length > 0 ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
          if (req.url === '/open-apis/auth/v3/tenant_access_token/internal') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                code: 0,
                msg: 'ok',
                tenant_access_token: `t-${brand}-token-1234567890abcdef`,
                expire: 7200,
              }),
            );
            return;
          }
          if (req.url?.includes('/top_notice/put_top_notice')) {
            assert.equal(body.chat_top_notice?.[0]?.action_type, '1', 'action_type must be string "1"');
            if (brand === 'feishu') feishuTopNoticeCalls++;
            else larkTopNoticeCalls++;
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ code: 0, msg: 'success', data: {} }));
            return;
          }
          res.writeHead(404);
          res.end('{}');
        });
      });

    const feishuServer = makeLarkMock('feishu');
    const larkServer = makeLarkMock('lark');

    // Mock GitHub comments API for idempotent postShareLinkToPr
    const prComments: Array<{ id: number; body: string }> = [];
    const githubServer = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      req.on('end', () => {
        if (req.method === 'GET' && req.url?.includes('/issues/') && req.url?.includes('/comments')) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(prComments));
          return;
        }
        if (req.method === 'POST' && req.url?.includes('/issues/') && req.url?.includes('/comments')) {
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          const entry = { id: prComments.length + 1, body: body.body, html_url: 'https://github.com/c/1', user: { login: 'bot' } };
          prComments.push(entry);
          res.writeHead(201, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(entry));
          return;
        }
        res.writeHead(404);
        res.end('{}');
      });
    });

    // Mock current-core daemon (ignores kickoff fields on /create, returns 404 on /top-notice)
    const seenNonces = new Map<string, number>();
    let daemonPort = 0;
    let createCalls = 0;
    const storedChats: Array<{ chatId: string; name: string; messages: Array<{ messageId: string; text: string }> }> = [];

    const daemonServer = http.createServer((req, res) => {
      const authOk = verifyDaemonIpcHeaders(
        req.headers,
        dashSecret,
        req.method ?? 'GET',
        req.url ?? '/',
        daemonPort,
        seenNonces,
      );
      if (!authOk) {
        res.writeHead(401);
        res.end('{}');
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
              chats: storedChats.map(c => ({ chatId: c.chatId, name: c.name, chatStatus: 'normal' })),
            }),
          );
          return;
        }
        if (req.method === 'POST' && req.url === '/api/groups/create') {
          createCalls++;
          // Verify human invitees & botCollaboration passed from resolvedAllowedUsers
          assert.deepEqual(body.userOpenIds, ['ou_human1']);
          assert.equal(body.transferOwnerTo, 'ou_human1');
          assert.equal(body.botCollaboration, true);
          const chatId = `oc_oldcore_${createCalls}`;
          storedChats.push({ chatId, name: body.name, messages: [] });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              ok: true,
              chatId,
              shareLink: `https://applink.feishu.cn/client/chat/open?openChatId=${chatId}`,
              kickoffMessageId: null, // Current core ignores kickoff fields!
              kickoffError: null,
            }),
          );
          return;
        }
        const sendMatch = /^\/api\/groups\/(oc_[^/]+)\/messages$/.exec(req.url ?? '');
        if (req.method === 'POST' && sendMatch) {
          // Verify strict 2-key body { requestId, content } and UTF-8 byte cap <= 8192
          assert.deepEqual(Object.keys(body).sort(), ['content', 'requestId']);
          assert.ok(Buffer.byteLength(body.content, 'utf8') <= 8192);
          // Verify creator-scoped open_id used (NEVER foreign self-view botOpenId!)
          assert.ok(!body.content.includes('ou_FOREIGN_SELF_DO_NOT_USE'));
          assert.ok(
            body.content.includes('ou_CREATOR_SCOPED_REVIEWER') ||
              body.content.includes('ou_LARK_SCOPED_REVIEWER'),
          );
          const chat = storedChats.find(c => c.chatId === sendMatch[1]);
          const messageId = `om_sent_${(chat?.messages.length ?? 0) + 1}`;
          chat?.messages.push({ messageId, text: body.content });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, chatId: sendMatch[1], messageId, requestId: body.requestId, replayed: false }));
          return;
        }
        const listMsgMatch = /^\/api\/groups\/(oc_[^/]+)\/messages$/.exec(req.url ?? '');
        if (req.method === 'GET' && listMsgMatch) {
          const chat = storedChats.find(c => c.chatId === listMsgMatch[1]);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              ok: true,
              messages: (chat?.messages ?? []).map(m => ({ messageId: m.messageId, preview: m.text, deleted: false })),
            }),
          );
          return;
        }
        const getMsgMatch = /^\/api\/groups\/(oc_[^/]+)\/messages\/(om_[^/]+)$/.exec(req.url ?? '');
        if (req.method === 'GET' && getMsgMatch) {
          const chat = storedChats.find(c => c.chatId === getMsgMatch[1]);
          const msg = chat?.messages.find(m => m.messageId === getMsgMatch[2]);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              ok: true,
              messageId: msg?.messageId,
              chatId: getMsgMatch[1],
              deleted: false,
              text: msg?.text ?? '',
            }),
          );
          return;
        }
        // Current core has no /top-notice IPC -> 404 triggers brand-aware Open API fallback
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'not_found' }));
      });
    });

    await Promise.all([
      new Promise<void>(r => proxyTrap.listen(0, '127.0.0.1', () => r())),
      new Promise<void>(r => feishuServer.listen(0, '127.0.0.1', () => r())),
      new Promise<void>(r => larkServer.listen(0, '127.0.0.1', () => r())),
      new Promise<void>(r => githubServer.listen(0, '127.0.0.1', () => r())),
      new Promise<void>(r => daemonServer.listen(0, '127.0.0.1', () => r())),
    ]);

    const proxyPort = (proxyTrap.address() as { port: number }).port;
    const feishuPort = (feishuServer.address() as { port: number }).port;
    const larkPort = (larkServer.address() as { port: number }).port;
    const ghPort = (githubServer.address() as { port: number }).port;
    daemonPort = (daemonServer.address() as { port: number }).port;

    for (const appId of ['cli_creator_feishu', 'cli_creator_lark']) {
      await fsp.writeFile(
        join(daemonsDir, `${appId}.json`),
        JSON.stringify({
          larkAppId: appId,
          ipcPort: daemonPort,
          lastHeartbeat: Date.now(),
          resolvedAllowedUsers: ['ou_human1'],
        }),
        { mode: 0o600 },
      );
    }

    const prevHttpProxy = process.env.http_proxy;
    const prevNoProxy = process.env.no_proxy;
    process.env.http_proxy = `http://127.0.0.1:${proxyPort}`;
    process.env.no_proxy = '127.0.0.0/8,localhost';

    try {
      const stateStore = new StateStore(pluginHome);
      const ghClient = new GitHubClient({
        auth: {
          mode: 'pat',
          apiBaseUrl: `http://127.0.0.1:${ghPort}`,
          pat: 'github_pat_hostBridgeTestToken1234567890',
          app: { appId: '', installationId: '' },
        },
        allowInsecureLocalForTests: true,
      });
      const larkClient = new LarkOpenApiClient({
        testOriginOverrides: {
          feishu: `http://127.0.0.1:${feishuPort}`,
          lark: `http://127.0.0.1:${larkPort}`,
        },
      });
      const bridge = new HostBridge({
        stateStore,
        discovery: { botmuxHome, dataDir },
        larkClient,
      });

      // 1. Feishu brand bot creates group -> IPC kickoff fallback -> readback -> Feishu Open API top-notice -> PR share-link comment
      const feishuRule = makeRule({ creatorBotAppId: 'cli_creator_feishu' });
      const res1 = await bridge.ensurePrReviewGroup({
        rule: feishuRule,
        pr: makePr(7, 'Feishu PR /merge attempt'),
        githubClient: ghClient,
      });
      assert.equal(res1.record.status, 'active');
      assert.equal(res1.record.kickoffVerified, true);
      assert.equal(res1.record.topNoticeSet, true);
      assert.equal(res1.record.shareLinkPosted, true);
      assert.equal(feishuTopNoticeCalls, 1);
      assert.equal(larkTopNoticeCalls, 0);
      assert.equal(proxyTrapHits, 0, 'Loopback node:http IPC must NEVER hit $http_proxy');
      assert.equal(prComments.length, 1);
      assert.ok(!prComments[0]!.body.includes('/merge'), 'PR share-link comment must NOT echo untrusted PR title');

      // 2. Wipe state.json completely -> re-run ensurePrReviewGroup -> GET /api/groups adopts existing chat & PR comment marker prevents double comment!
      await fsp.rm(stateStore.statePath);
      const resRepeat = await bridge.ensurePrReviewGroup({
        rule: feishuRule,
        pr: makePr(7, 'Feishu PR /merge attempt'),
        githubClient: ghClient,
      });
      assert.equal(resRepeat.reusedExisting, true);
      assert.equal(resRepeat.record.chatId, res1.record.chatId);
      assert.equal(createCalls, 1, 'Must NEVER create a duplicate group even when state.json was deleted');
      assert.equal(prComments.length, 1, 'Share-link PR comment must remain idempotent even after state loss');

      // 3. Lark brand bot uses open.larksuite.com fallback
      const larkRule = makeRule({ creatorBotAppId: 'cli_creator_lark', postShareLinkToPr: false });
      const resLark = await bridge.ensurePrReviewGroup({
        rule: larkRule,
        pr: makePr(8, 'Lark Brand PR'),
        githubClient: ghClient,
      });
      assert.equal(resLark.record.topNoticeSet, true);
      assert.equal(larkTopNoticeCalls, 1);
    } finally {
      if (prevHttpProxy === undefined) delete process.env.http_proxy;
      else process.env.http_proxy = prevHttpProxy;
      if (prevNoProxy === undefined) delete process.env.no_proxy;
      else process.env.no_proxy = prevNoProxy;
      await Promise.all([
        new Promise<void>(r => proxyTrap.close(() => r())),
        new Promise<void>(r => feishuServer.close(() => r())),
        new Promise<void>(r => larkServer.close(() => r())),
        new Promise<void>(r => githubServer.close(() => r())),
        new Promise<void>(r => daemonServer.close(() => r())),
      ]);
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('recovers from partial HTTP 502 chatId creation and supports botmux create-group CLI fallback when daemon is offline', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-gh-bridge-crash-'));
    const pluginHome = join(tmp, 'plugin-home');
    const botmuxHome = join(tmp, 'botmux-home');
    const dataDir = join(tmp, 'data');
    const daemonsDir = join(dataDir, 'dashboard-daemons');
    await fsp.mkdir(daemonsDir, { recursive: true, mode: 0o700 });
    await fsp.mkdir(botmuxHome, { recursive: true, mode: 0o700 });

    const dashSecret = 'y'.repeat(43);
    await fsp.writeFile(join(botmuxHome, '.dashboard-secret'), `${dashSecret}\n`, { mode: 0o600 });
    await fsp.writeFile(
      join(botmuxHome, 'bots.json'),
      JSON.stringify([{ larkAppId: 'cli_creator1', larkAppSecret: 'sec_1', brand: 'feishu' }]),
      { mode: 0o600 },
    );

    let createAttempts = 0;
    let kickoffMsgSent = 0;
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
          createAttempts++;
          // Simulate partial failure: Lark created oc_partial_502 before post-create step threw 502!
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, chatId: 'oc_partial_502', error: 'invite_partial_fail' }));
          return;
        }
        if (req.method === 'GET' && req.url === '/api/groups/oc_partial_502/messages') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, messages: [] }));
          return;
        }
        if (req.method === 'POST' && req.url === '/api/groups/oc_partial_502/messages') {
          kickoffMsgSent++;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, chatId: 'oc_partial_502', messageId: 'om_recovered_1', requestId: body.requestId, replayed: false }));
          return;
        }
        if (req.method === 'GET' && req.url === '/api/groups/oc_partial_502/messages/om_recovered_1') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, messageId: 'om_recovered_1', chatId: 'oc_partial_502', deleted: false, text: 'PR: acme/core#99\npr_number="99"' }));
          return;
        }
        if (req.method === 'POST' && req.url === '/api/groups/oc_partial_502/top-notice') {
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
      JSON.stringify({ larkAppId: 'cli_creator1', ipcPort: daemonPort, lastHeartbeat: Date.now(), resolvedAllowedUsers: [] }),
      { mode: 0o600 },
    );

    const ghClient = new GitHubClient({
      auth: { mode: 'pat', apiBaseUrl: 'http://127.0.0.1:1', pat: 'github_pat_1234567890abcdef1234', app: { appId: '', installationId: '' } },
      allowInsecureLocalForTests: true,
    });

    try {
      const stateStore = new StateStore(pluginHome);
      const bridge = new HostBridge({
        stateStore,
        discovery: { botmuxHome, dataDir },
      });

      const rule = makeRule({ postShareLinkToPr: false });
      const res = await bridge.ensurePrReviewGroup({ rule, pr: makePr(99, 'Partial 502 PR'), githubClient: ghClient });
      assert.equal(res.record.chatId, 'oc_partial_502');
      assert.equal(res.record.status, 'active');
      assert.equal(res.record.topNoticeSet, true);
      assert.equal(createAttempts, 1);
      assert.equal(kickoffMsgSent, 1);

      // Now remove online daemon descriptor -> verify CLI create-group fallback with stripped BUN_BE_BUN & line-1 chatId recovery even on exit code 1!
      await fsp.rm(join(daemonsDir, 'cli_creator1.json'));
      let capturedArgs: string[] = [];
      let capturedEnv: Record<string, string | undefined> = {};
      process.env.BUN_BE_BUN = '1';
      process.env.BOTMUX_SESSION_ID = 'sess_leak';
      const cliBridge = new HostBridge({
        stateStore,
        discovery: { botmuxHome, dataDir, botmuxBin: '/usr/local/bin/botmux' },
        cliExec: async (_bin, args, opts) => {
          capturedArgs = args;
          capturedEnv = opts.env;
          // Simulate CLI printing chatId on line 1 then exiting 1 after partial timeout
          return {
            exitCode: 1,
            stdout: 'oc_cli_line1_recovered\n{"success":false,"chatCreated":true,"chatId":"oc_cli_line1_recovered","kickoffMessageId":"om_cli_1","kickoffError":"minor"}\n',
            stderr: '',
          };
        },
      });
      const cliRes = await cliBridge.ensurePrReviewGroup({
        rule: makeRule({ postShareLinkToPr: false, setTopNotice: false }),
        pr: makePr(100, '--bind-working-dir=/etc; $(id)'),
        githubClient: ghClient,
      });
      delete process.env.BUN_BE_BUN;
      delete process.env.BOTMUX_SESSION_ID;

      assert.equal(cliRes.record.chatId, 'oc_cli_line1_recovered');
      assert.equal(cliRes.record.kickoffMessageId, 'om_cli_1');
      assert.equal(capturedEnv.BUN_BE_BUN, undefined, 'BUN_BE_BUN must be stripped');
      assert.equal(capturedEnv.BOTMUX_SESSION_ID, undefined, 'BOTMUX_SESSION_ID must be stripped');
      assert.ok(capturedArgs.some(a => a.startsWith('--name=')), 'Untrusted group name must use --name= flag syntax');
    } finally {
      await new Promise<void>(r => daemonServer.close(() => r()));
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('refuses to pin top notice or mark active when kickoff readback mismatches PR number, and rejects foreign self-view botOpenId from members-display', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-gh-bridge-mismatch-'));
    const pluginHome = join(tmp, 'plugin-home');
    const botmuxHome = join(tmp, 'botmux-home');
    const dataDir = join(tmp, 'data');
    const daemonsDir = join(dataDir, 'dashboard-daemons');
    await fsp.mkdir(daemonsDir, { recursive: true, mode: 0o700 });
    await fsp.mkdir(botmuxHome, { recursive: true, mode: 0o700 });

    const dashSecret = 'm'.repeat(43);
    await fsp.writeFile(join(botmuxHome, '.dashboard-secret'), `${dashSecret}\n`, { mode: 0o600 });
    await fsp.writeFile(
      join(botmuxHome, 'bots.json'),
      JSON.stringify([
        { larkAppId: 'cli_creator1', larkAppSecret: 'sec_1', brand: 'feishu' },
        { larkAppId: 'cli_reviewer2', larkAppSecret: 'sec_2', brand: 'feishu' },
      ]),
      { mode: 0o600 },
    );
    await fsp.writeFile(
      join(dataDir, 'bots-info.json'),
      JSON.stringify([{ larkAppId: 'cli_reviewer2', botOpenId: 'ou_FOREIGN_SELF', botName: 'RevBot' }]),
    );

    let topNoticeAttempted = false;
    let postedKickoffContent = '';
    let daemonPort = 0;
    const seenNonces = new Map<string, number>();

    const daemonServer = http.createServer((req, res) => {
      verifyDaemonIpcHeaders(req.headers, dashSecret, req.method ?? 'GET', req.url ?? '/', daemonPort, seenNonces);
      const chunks: Buffer[] = [];
      req.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      req.on('end', () => {
        const body = chunks.length > 0 ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
        if (req.method === 'GET' && req.url === '/api/groups/oc_resume_1/members-display') {
          // Simulate Botmux members-display returning foreign self-view botOpenId (must be rejected!)
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ members: [{ name: 'RevBot', openId: 'ou_FOREIGN_SELF', memberType: 'bot' }] }));
          return;
        }
        if (req.method === 'GET' && req.url === '/api/groups/oc_resume_1/messages') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, messages: [] }));
          return;
        }
        if (req.method === 'POST' && req.url === '/api/groups/oc_resume_1/messages') {
          postedKickoffContent = String(body.content ?? '');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, chatId: 'oc_resume_1', messageId: 'om_wrong_1', requestId: body.requestId, replayed: false }));
          return;
        }
        if (req.method === 'GET' && req.url === '/api/groups/oc_resume_1/messages/om_wrong_1') {
          // Simulate readback returning a DIFFERENT PR's message (PR #999 instead of #77)
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, messageId: 'om_wrong_1', chatId: 'oc_resume_1', deleted: false, text: 'PR: acme/core#999' }));
          return;
        }
        if (req.method === 'POST' && req.url === '/api/groups/oc_resume_1/top-notice') {
          topNoticeAttempted = true;
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
      JSON.stringify({ larkAppId: 'cli_creator1', ipcPort: daemonPort, lastHeartbeat: Date.now(), resolvedAllowedUsers: [] }),
      { mode: 0o600 },
    );

    try {
      const stateStore = new StateStore(pluginHome);
      // Pre-seed crash-interrupted 'creating' state with chatId already saved!
      await stateStore.update(s => {
        s.prGroups['acme/core#77'] = {
          status: 'creating',
          repo: 'acme/core',
          prNumber: 77,
          chatId: 'oc_resume_1',
          groupName: 'PR #77 acme/core - Crash resume',
          creatorLarkAppId: 'cli_creator1',
          kickoffBotAppId: 'cli_reviewer2',
          topNoticeSet: false,
          lastHeadSha: 'f'.repeat(40),
          createdAt: '2026-11-25T00:00:00Z',
          updatedAt: '2026-11-25T00:00:00Z',
        };
      });

      const ghClient = new GitHubClient({
        auth: { mode: 'pat', apiBaseUrl: 'http://127.0.0.1:1', pat: 'github_pat_1234567890abcdef1234', app: { appId: '', installationId: '' } },
        allowInsecureLocalForTests: true,
      });
      const bridge = new HostBridge({ stateStore, discovery: { botmuxHome, dataDir } });

      await assert.rejects(
        () => bridge.ensurePrReviewGroup({ rule: makeRule({ postShareLinkToPr: false }), pr: makePr(77, 'Crash resume'), githubClient: ghClient }),
        /kickoff_message_pr_mismatch/,
      );
      assert.equal(topNoticeAttempted, false, 'Must NEVER pin mismatched kickoff message as top notice');
      assert.ok(!postedKickoffContent.includes('ou_FOREIGN_SELF'), 'Must NEVER mention foreign self-view botOpenId');
      const st = await stateStore.load();
      assert.equal(st.prGroups['acme/core#77']?.status, 'creating', 'Must remain creating when readback fails');
      assert.equal(st.prGroups['acme/core#77']?.kickoffMessageId, null, 'Invalid kickoffMessageId must be cleared');
    } finally {
      await new Promise<void>(r => daemonServer.close(() => r()));
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });
});

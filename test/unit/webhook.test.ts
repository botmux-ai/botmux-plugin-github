import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import http from 'node:http';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  DeliveryDedupCache,
  verifyAndParseWebhookPayload,
  verifyGitHubWebhookSignature,
} from '../../src/engine/webhook.ts';
import { PerPrSerialQueue, QueueDrainingError } from '../../src/engine/queue.ts';
import { isWebhookSecretAcceptable } from '../../src/config/schema.ts';
import { savePluginConfig } from '../../src/config/store.ts';
import { createDefaultConfig } from '../../src/config/schema.ts';
import { startGitHubService } from '../../src/service/runner.ts';
import { loopbackRequest } from '../../src/security/net.ts';
import { signDaemonIpcHeaders } from '../../src/host/discovery.ts';
import { MAX_WEBHOOK_BODY_BYTES } from '../../src/types.ts';

const STRONG_SECRET = 'whsec_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6';

function sign(raw: Buffer | string, secret = STRONG_SECRET): string {
  const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw, 'utf8');
  return `sha256=${createHmac('sha256', secret).update(buf).digest('hex')}`;
}

function makeWebhookPrBody(repo = 'acme/example', prNumber = 12, action = 'opened'): Buffer {
  return Buffer.from(
    JSON.stringify({
      action,
      repository: { full_name: repo },
      pull_request: {
        number: prNumber,
        title: 'Webhook PR with 中文 UTF-8',
        body: 'Body text',
        state: 'open',
        draft: false,
        html_url: `https://github.com/${repo}/pull/${prNumber}`,
        user: { login: 'alice' },
        base: { ref: 'main', repo: { full_name: repo } },
        head: {
          ref: 'feat/webhook',
          sha: 'c'.repeat(40),
          repo: { full_name: repo, fork: false },
        },
        labels: [],
        maintainer_can_modify: true,
        created_at: '2026-11-25T00:00:00Z',
        updated_at: '2026-11-25T00:01:00Z',
      },
    }),
    'utf8',
  );
}

describe('Webhook cryptographic verification, secret strength & delivery dedup', () => {
  it('enforces >= 32 UTF-8 bytes and >= 8 distinct characters for webhook secrets', () => {
    assert.equal(isWebhookSecretAcceptable(''), false);
    assert.equal(isWebhookSecretAcceptable('short-secret-31-bytes-123456789'), false);
    assert.equal(isWebhookSecretAcceptable('a'.repeat(40)), false);
    assert.equal(isWebhookSecretAcceptable(' '.repeat(40)), false);
    assert.equal(isWebhookSecretAcceptable(STRONG_SECRET), true);
  });

  it('verifies exact raw-byte HMAC-SHA256 via timingSafeEqual BEFORE JSON.parse', () => {
    const raw = makeWebhookPrBody();
    assert.equal(verifyGitHubWebhookSignature(raw, sign(raw), STRONG_SECRET), true);

    // 1-byte mutation fails
    const mutated = Buffer.from(raw);
    mutated[mutated.length - 1] = mutated[mutated.length - 1]! ^ 0x01;
    assert.equal(verifyGitHubWebhookSignature(mutated, sign(raw), STRONG_SECRET), false);

    // Malformed JSON with invalid signature MUST return 401 (NOT 400 JSON error)
    const dedup = new DeliveryDedupCache();
    const res = verifyAndParseWebhookPayload({
      headers: {
        'content-type': 'application/json',
        'x-github-event': 'pull_request',
        'x-github-delivery': 'deliv-1',
        'x-hub-signature-256': 'sha256=' + '0'.repeat(64),
      },
      rawBody: Buffer.from('{not valid json!!!', 'utf8'),
      webhookEnabled: true,
      webhookSecret: STRONG_SECRET,
      allowedRepoKeys: new Set(['acme/example']),
      dedupCache: dedup,
    });
    assert.equal(res.status, 401);
    assert.equal(res.reason, 'invalid_signature');

    // Duplicate header array rejected
    assert.equal(verifyGitHubWebhookSignature(raw, [sign(raw), sign(raw)], STRONG_SECRET), false);
    // Uppercase hex rejected
    assert.equal(verifyGitHubWebhookSignature(raw, sign(raw).toUpperCase(), STRONG_SECRET), false);
  });

  it('does not pollute delivery dedup cache on unauthenticated or non-allowlisted repo deliveries and deduplicates replays', () => {
    const dedup = new DeliveryDedupCache();
    const allowed = new Set(['acme/example']);

    // Flood unauthenticated requests
    const body = makeWebhookPrBody('acme/example', 12);
    for (let i = 0; i < 50; i++) {
      const r = verifyAndParseWebhookPayload({
        headers: {
          'content-type': 'application/json',
          'x-github-event': 'pull_request',
          'x-github-delivery': `unauth-${i}`,
          'x-hub-signature-256': 'sha256=' + 'f'.repeat(64),
        },
        rawBody: body,
        webhookEnabled: true,
        webhookSecret: STRONG_SECRET,
        allowedRepoKeys: allowed,
        dedupCache: dedup,
      });
      assert.equal(r.status, 401);
    }
    assert.equal(dedup.size(), 0);

    // Signed delivery for non-allowlisted repo rejected 403 and NOT recorded in dedup
    const otherBody = makeWebhookPrBody('evil/other-repo', 1);
    const otherRes = verifyAndParseWebhookPayload({
      headers: {
        'content-type': 'application/json',
        'x-github-event': 'pull_request',
        'x-github-delivery': 'other-repo-deliv',
        'x-hub-signature-256': sign(otherBody),
      },
      rawBody: otherBody,
      webhookEnabled: true,
      webhookSecret: STRONG_SECRET,
      allowedRepoKeys: allowed,
      dedupCache: dedup,
    });
    assert.equal(otherRes.status, 403);
    assert.equal(dedup.size(), 0);

    // Valid allowlisted delivery accepted 202, replay returns 200 duplicate
    const first = verifyAndParseWebhookPayload({
      headers: {
        'content-type': 'application/json',
        'x-github-event': 'pull_request',
        'x-github-delivery': 'good-deliv-1',
        'x-hub-signature-256': sign(body),
      },
      rawBody: body,
      webhookEnabled: true,
      webhookSecret: STRONG_SECRET,
      allowedRepoKeys: allowed,
      dedupCache: dedup,
    });
    assert.equal(first.status, 202);
    assert.equal(first.duplicate, false);
    dedup.commit('good-deliv-1');

    const replay = verifyAndParseWebhookPayload({
      headers: {
        'content-type': 'application/json',
        'x-github-event': 'pull_request',
        'x-github-delivery': 'good-deliv-1',
        'x-hub-signature-256': sign(body),
      },
      rawBody: body,
      webhookEnabled: true,
      webhookSecret: STRONG_SECRET,
      allowedRepoKeys: allowed,
      dedupCache: dedup,
    });
    assert.equal(replay.status, 200);
    assert.equal(replay.duplicate, true);

    // Prototype keys like __proto__ must be rejected in X-GitHub-Delivery
    const protoRes = verifyAndParseWebhookPayload({
      headers: {
        'content-type': 'application/json',
        'x-github-event': 'pull_request',
        'x-github-delivery': '__proto__',
        'x-hub-signature-256': sign(body),
      },
      rawBody: body,
      webhookEnabled: true,
      webhookSecret: STRONG_SECRET,
      allowedRepoKeys: allowed,
      dedupCache: dedup,
    });
    assert.equal(protoRes.status, 400);
  });

  it('PerPrSerialQueue executes same-PR tasks strictly FIFO without dropping callbacks or deadlocking on drain', async () => {
    const queue = new PerPrSerialQueue({ maxConcurrency: 2 });
    const order: string[] = [];

    const p1 = queue.enqueue('acme/repo#1', async () => {
      order.push('start-1');
      await new Promise(r => setTimeout(r, 30));
      order.push('end-1');
      return 1;
    });
    const p2 = queue.enqueue('acme/repo#1', async () => {
      order.push('start-2');
      order.push('end-2');
      return 2;
    });
    const p3 = queue.enqueue('acme/repo#1', async () => {
      order.push('start-3');
      order.push('end-3');
      return 3;
    });

    assert.deepEqual(await Promise.all([p1, p2, p3]), [1, 2, 3]);
    assert.deepEqual(order, ['start-1', 'end-1', 'start-2', 'end-2', 'start-3', 'end-3']);

    // Draining rejects queued unstarted tasks cleanly rather than hanging forever
    const slow = queue.enqueue('acme/repo#2', async () => {
      await new Promise(r => setTimeout(r, 40));
      return 'done';
    });
    const queued = queue.enqueue('acme/repo#2', async () => 'never');
    const drainPromise = queue.drain(2000);
    await assert.rejects(() => queued, QueueDrainingError);
    assert.equal(await slow, 'done');
    await drainPromise;
  });
});

describe('Loopback HTTP webhook size limits (1 MiB) and Control API Anti-CSRF / Auth', () => {
  it('enforces <= 1 MiB streaming body limit and protects /api/* against DNS rebinding, CSRF, and missing auth', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-gh-wh-http-'));
    const pluginHome = join(tmp, 'plugin-home');
    const botmuxHome = join(tmp, 'botmux-home');
    await fsp.mkdir(botmuxHome, { recursive: true, mode: 0o700 });
    const dashSecret = 'd'.repeat(43);
    await fsp.writeFile(join(botmuxHome, '.dashboard-secret'), `${dashSecret}\n`, { mode: 0o600 });

    const cfg = createDefaultConfig();
    cfg.webhook.enabled = true;
    cfg.webhook.secret = STRONG_SECRET;
    await savePluginConfig(pluginHome, cfg);

    const svc = await startGitHubService({
      pluginHome,
      port: 0,
      discovery: { botmuxHome },
    });

    try {
      // 1. Oversized Content-Length (> 1 MiB) rejected 413
      const huge = Buffer.alloc(MAX_WEBHOOK_BODY_BYTES + 10, 0x61);
      const res413 = await loopbackRequest({
        port: svc.port,
        method: 'POST',
        path: '/webhooks/github',
        headers: {
          Host: `127.0.0.1:${svc.port}`,
          'Content-Type': 'application/json',
          'X-GitHub-Event': 'pull_request',
          'X-GitHub-Delivery': 'too-big-1',
          'X-Hub-Signature-256': sign(huge),
        },
        body: huge,
      });
      assert.equal(res413.status, 413);

      // 2. Chunked Transfer-Encoding exceeding 1 MiB aborts immediately with 413 or socket destroy
      const chunkedResult = await new Promise<{ status?: number; destroyed?: boolean }>(resolve => {
        const req = http.request(
          {
            host: '127.0.0.1',
            port: svc.port,
            method: 'POST',
            path: '/webhooks/github',
            headers: {
              Host: `127.0.0.1:${svc.port}`,
              'Content-Type': 'application/json',
              'Transfer-Encoding': 'chunked',
              'X-GitHub-Event': 'pull_request',
              'X-GitHub-Delivery': 'chunked-big',
              'X-Hub-Signature-256': 'sha256=' + '0'.repeat(64),
            },
          },
          res => {
            res.resume();
            resolve({ status: res.statusCode });
          },
        );
        req.on('error', () => resolve({ destroyed: true }));
        const chunk = Buffer.alloc(128 * 1024, 0x78);
        for (let i = 0; i < 10; i++) {
          if (!req.destroyed) req.write(chunk);
        }
        if (!req.destroyed) req.end();
      });
      assert.ok(chunkedResult.status === 413 || chunkedResult.destroyed === true);

      // 3. Control API anti-CSRF & DNS rebinding checks
      const badHost = await loopbackRequest({
        port: svc.port,
        method: 'GET',
        path: '/api/status',
        headers: {
          Host: `evil.example:${svc.port}`,
          'X-Botmux-Github-Token': svc.controlToken,
        },
      });
      assert.equal(badHost.status, 403);

      const badOrigin = await loopbackRequest({
        port: svc.port,
        method: 'GET',
        path: '/api/status',
        headers: {
          Host: `127.0.0.1:${svc.port}`,
          Origin: 'https://evil.example',
          'X-Botmux-Github-Token': svc.controlToken,
        },
      });
      assert.equal(badOrigin.status, 403);

      const unauth = await loopbackRequest({
        port: svc.port,
        method: 'GET',
        path: '/api/status',
        headers: { Host: `127.0.0.1:${svc.port}` },
      });
      assert.equal(unauth.status, 401);

      const missingCtrlHeader = await loopbackRequest({
        port: svc.port,
        method: 'POST',
        path: '/api/reload',
        headers: {
          Host: `127.0.0.1:${svc.port}`,
          'Content-Type': 'application/json',
          'X-Botmux-Github-Token': svc.controlToken,
        },
        body: '{}',
      });
      assert.equal(missingCtrlHeader.status, 403);

      // Valid control token succeeds
      const okToken = await loopbackRequest({
        port: svc.port,
        method: 'GET',
        path: '/api/status',
        headers: {
          Host: `127.0.0.1:${svc.port}`,
          'X-Botmux-Github-Token': svc.controlToken,
        },
      });
      assert.equal(okToken.status, 200);

      // Valid .dashboard-secret HMAC also succeeds
      const hmacHeaders = signDaemonIpcHeaders(dashSecret, 'GET', '/api/status', svc.port);
      const okHmac = await loopbackRequest({
        port: svc.port,
        method: 'GET',
        path: '/api/status',
        headers: {
          Host: `127.0.0.1:${svc.port}`,
          ...hmacHeaders,
        },
      });
      assert.equal(okHmac.status, 200);

      // Replaying the same HMAC nonce must be rejected!
      const replayHmac = await loopbackRequest({
        port: svc.port,
        method: 'GET',
        path: '/api/status',
        headers: {
          Host: `127.0.0.1:${svc.port}`,
          ...hmacHeaders,
        },
      });
      assert.equal(replayHmac.status, 401);
    } finally {
      await svc.close();
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });
});

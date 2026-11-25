import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { execFileSync } from 'node:child_process';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { GitHubClient, GitHubRateLimitPausedError } from '../../src/github/client.ts';
import { RateLimitTracker } from '../../src/github/ratelimit.ts';
import {
  CrossOriginRedirectError,
  isIpAddressBlocked,
  ProxyConfigError,
  SsrfBlockedError,
  validateGitHubApiBaseUrl,
} from '../../src/security/net.ts';

async function withMockServer(
  handler: http.RequestListener,
  fn: (baseUrl: string, port: number) => Promise<void>,
): Promise<void> {
  const server = http.createServer(handler);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()));
  const addr = server.address();
  assert.ok(addr && typeof addr === 'object');
  const baseUrl = `http://127.0.0.1:${addr.port}`;
  try {
    await fn(baseUrl, addr.port);
  } finally {
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
}

describe('RateLimitTracker invariants', () => {
  it('isolates core and search quotas with <10% threshold and ignores untracked resources', () => {
    let nowMs = 1_700_000_000_000;
    const resetSec = Math.floor((nowMs + 600_000) / 1000);
    const tracker = new RateLimitTracker({ now: () => nowMs });

    // Core 499 / 5000 => 499*10 = 4990 < 5000 => low!
    tracker.noteHeaders({
      'x-ratelimit-resource': 'core',
      'x-ratelimit-limit': '5000',
      'x-ratelimit-remaining': '499',
      'x-ratelimit-reset': String(resetSec),
    });
    assert.equal(tracker.isCoreLow(), true);
    assert.equal(tracker.shouldPause({ resource: 'core', priority: 'non_core' }).paused, true);
    assert.equal(tracker.shouldPause({ resource: 'core', priority: 'core' }).paused, false);

    // Core exactly 500 / 5000 => 500*10 = 5000 (not < 5000) => healthy!
    tracker.noteHeaders({
      'x-ratelimit-resource': 'core',
      'x-ratelimit-limit': '5000',
      'x-ratelimit-remaining': '500',
      'x-ratelimit-reset': String(resetSec),
    });
    assert.equal(tracker.isCoreLow(), false);

    // Untracked graphql remaining=0 must NOT pollute core
    tracker.noteHeaders({
      'x-ratelimit-resource': 'graphql',
      'x-ratelimit-limit': '5000',
      'x-ratelimit-remaining': '0',
      'x-ratelimit-reset': String(resetSec),
    });
    assert.equal(tracker.isCoreLow(), false);

    // Search 2 / 30 (<10%) pauses search only, never core
    tracker.noteHeaders({
      'x-ratelimit-resource': 'search',
      'x-ratelimit-limit': '30',
      'x-ratelimit-remaining': '2',
      'x-ratelimit-reset': String(resetSec),
    });
    assert.equal(tracker.isSearchLow(), true);
    assert.equal(tracker.isCoreLow(), false);
    assert.equal(tracker.shouldPause({ resource: 'search', priority: 'non_core' }).paused, true);
    assert.equal(tracker.shouldPause({ resource: 'core', priority: 'non_core' }).paused, false);
  });

  it('enforces secondary 429/403 precedence (Retry-After -> core reset if remaining==0 -> 1m..1h monotonic backoff) without single-200 reset', () => {
    let nowMs = 1_700_000_000_000;
    const tracker = new RateLimitTracker({ now: () => nowMs });

    // 1. Secondary 403 WITHOUT Retry-After and with core remaining=4000 must IGNORE X-RateLimit-Reset and use 1m backoff!
    const farResetSec = Math.floor((nowMs + 3_000_000) / 1000);
    tracker.notePause(
      403,
      {
        'x-ratelimit-resource': 'core',
        'x-ratelimit-remaining': '4000',
        'x-ratelimit-reset': String(farResetSec),
      },
      'You have exceeded a secondary rate limit',
    );
    assert.equal(tracker.pauseRemainingMs(), 60_000, 'First secondary pause must be 1m');

    // Concurrent hit during active pause coalesces without doubling
    nowMs += 10_000;
    tracker.notePause(429, {}, 'Too Many Requests');
    assert.equal(tracker.pauseRemainingMs(), 50_000);

    // Advance past 1m pause (within 1*pauseStep quiet window): even after a 200 OK header, next hit doubles to 2m!
    nowMs += 55_000; // now = T + 65s (< backoffUntil + 60s = T + 120s)
    tracker.noteHeaders({
      'x-ratelimit-resource': 'core',
      'x-ratelimit-limit': '5000',
      'x-ratelimit-remaining': '4900',
      'x-ratelimit-reset': String(farResetSec),
    });
    tracker.notePause(429, {}, 'Too Many Requests');
    assert.equal(tracker.pauseRemainingMs(), 120_000, 'Second secondary pause must double to 2m');

    // Advance far past quiet window (now >= backoffUntil + pauseStep): resets cleanly to 1m
    nowMs += 120_000 + 120_001;
    tracker.notePause(429, {}, 'Too Many Requests');
    assert.equal(tracker.pauseRemainingMs(), 60_000, 'Backoff resets to 1m only after quiet window');

    // Explicit Retry-After respects exact seconds and NEVER shortens active pause or mutates pauseStep
    nowMs += 60_000 + 60_001; // quiet reset
    tracker.notePause(429, { 'retry-after': '180' }, 'Too Many Requests');
    assert.equal(tracker.pauseRemainingMs(), 180_000);

    // Non-core quota exhaustion (search remaining=0, no Retry-After) must NOT trigger global pause
    nowMs += 200_000;
    tracker.notePause(
      403,
      {
        'x-ratelimit-resource': 'search',
        'x-ratelimit-remaining': '0',
        'x-ratelimit-reset': String(Math.floor((nowMs + 600_000) / 1000)),
      },
      'API rate limit exceeded',
    );
    assert.equal(tracker.isGloballyPaused(), false);

    // Monotonic 1m -> 2m -> 4m -> 8m -> 16m -> 32m -> 1h -> 1h cap
    const capTracker = new RateLimitTracker({ now: () => nowMs });
    const expectedMins = [1, 2, 4, 8, 16, 32, 60, 60];
    for (const m of expectedMins) {
      capTracker.notePause(429, {}, 'Too Many Requests');
      assert.equal(capTracker.pauseRemainingMs(), m * 60_000);
      nowMs += m * 60_000 + 1000; // past pause, within 1*pauseStep quiet window
    }

    // HTTP-date Retry-After and core remaining == 0 X-RateLimit-Reset precedence
    const dateTracker = new RateLimitTracker({ now: () => nowMs });
    const futureDate = new Date(nowMs + 95_000).toUTCString();
    dateTracker.notePause(429, { 'retry-after': futureDate }, 'Too Many Requests');
    assert.ok(dateTracker.pauseRemainingMs() >= 90_000 && dateTracker.pauseRemainingMs() <= 96_000);

    nowMs += 120_000;
    const coreResetSec = Math.floor((nowMs + 240_000) / 1000);
    dateTracker.notePause(
      403,
      { 'x-ratelimit-resource': 'core', 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': String(coreResetSec) },
      'API rate limit exceeded',
    );
    assert.ok(dateTracker.pauseRemainingMs() >= 235_000 && dateTracker.pauseRemainingMs() <= 241_000);
  });
});

describe('GitHubClient (ETag 304, auth modes, fail-closed proxy, SSRF & redirect protection)', () => {
  it('uses If-None-Match ETag for 304 Not Modified with zero quota consumption and isolates ETags per credential', async () => {
    let reqCount = 0;
    const seenEtags: Array<string | undefined> = [];

    await withMockServer(
      (req, res) => {
        reqCount++;
        seenEtags.push(req.headers['if-none-match']);
        if (req.headers['if-none-match'] === '"etag-v1"') {
          res.writeHead(304, {
            ETag: '"etag-v1"',
            'X-RateLimit-Resource': 'core',
            'X-RateLimit-Limit': '5000',
            'X-RateLimit-Remaining': '4999',
            'X-RateLimit-Reset': String(Math.floor(Date.now() / 1000) + 3600),
          });
          res.end();
          return;
        }
        res.writeHead(200, {
          'Content-Type': 'application/json',
          ETag: '"etag-v1"',
          'X-RateLimit-Resource': 'core',
          'X-RateLimit-Limit': '5000',
          'X-RateLimit-Remaining': '4999',
          'X-RateLimit-Reset': String(Math.floor(Date.now() / 1000) + 3600),
        });
        res.end(
          JSON.stringify([
            {
              number: 7,
              title: 'Sample PR',
              body: 'Body',
              state: 'open',
              draft: false,
              html_url: 'https://github.com/acme/repo/pull/7',
              user: { login: 'alice' },
              base: { ref: 'main', repo: { full_name: 'acme/repo' } },
              head: { ref: 'feat/x', sha: 'b'.repeat(40), repo: { full_name: 'acme/repo', fork: false } },
              labels: [],
              maintainer_can_modify: true,
              created_at: '2026-11-25T00:00:00Z',
              updated_at: '2026-11-25T00:01:00Z',
            },
          ]),
        );
      },
      async baseUrl => {
        const clientA = new GitHubClient({
          auth: {
            mode: 'pat',
            apiBaseUrl: baseUrl,
            pat: 'github_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            app: { appId: '', installationId: '' },
          },
          allowInsecureLocalForTests: true,
        });

        const first = await clientA.listOpenPullRequests('acme', 'repo');
        assert.equal(first.notModified, false);
        assert.equal(first.pulls.length, 1);
        assert.equal(first.etag, '"etag-v1"');

        const second = await clientA.listOpenPullRequests('acme', 'repo', {
          persistedEtag: first.etag,
          persistedEtagKey: first.etagKey,
        });
        assert.equal(second.notModified, true);
        assert.equal(seenEtags[1], '"etag-v1"');

        // Different PAT credential must NOT reuse clientA's persisted ETag!
        const clientB = new GitHubClient({
          auth: {
            mode: 'pat',
            apiBaseUrl: baseUrl,
            pat: 'github_pat_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            app: { appId: '', installationId: '' },
          },
          allowInsecureLocalForTests: true,
        });
        const third = await clientB.listOpenPullRequests('acme', 'repo', {
          persistedEtag: first.etag,
          persistedEtagKey: first.etagKey,
        });
        assert.equal(third.notModified, false);
        assert.equal(seenEtags[2], undefined);
        assert.equal(reqCount, 3);
      },
    );
  });

  it('supports GitHub App RS256 JWT installation token exchange & testAuth on custom GHES apiBaseUrl', async () => {
    const { privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });

    let tokenExchanges = 0;
    await withMockServer(
      (req, res) => {
        if (req.method === 'POST' && req.url === '/api/v3/app/installations/999/access_tokens') {
          tokenExchanges++;
          const auth = req.headers.authorization ?? '';
          assert.ok(auth.startsWith('Bearer eyJ'), 'Must authenticate exchange with RS256 JWT');
          res.writeHead(201, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              token: 'ghs_installToken1234567890abcdef1234',
              expires_at: new Date(Date.now() + 3600_000).toISOString(),
            }),
          );
          return;
        }
        if (req.method === 'GET' && req.url === '/api/v3/installation/repositories?per_page=1') {
          assert.equal(req.headers.authorization, 'Bearer ghs_installToken1234567890abcdef1234');
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'X-RateLimit-Resource': 'core',
            'X-RateLimit-Limit': '5000',
            'X-RateLimit-Remaining': '4950',
            'X-RateLimit-Reset': String(Math.floor(Date.now() / 1000) + 3600),
          });
          res.end(JSON.stringify({ total_count: 3, repositories: [] }));
          return;
        }
        res.writeHead(404);
        res.end();
      },
      async baseUrl => {
        const client = new GitHubClient({
          auth: {
            mode: 'github_app',
            apiBaseUrl: `${baseUrl}/api/v3`,
            app: {
              appId: '12345',
              installationId: '999',
              privateKeyPem: privateKey,
            },
          },
          allowInsecureLocalForTests: true,
        });

        const r1 = await client.testAuth();
        assert.equal(r1.ok, true);
        assert.equal(r1.resolvedMethod, 'github_app');
        assert.ok(r1.identity?.includes('app:12345/installation:999'));
        assert.equal(r1.rateLimit?.remaining, 4950);

        // Second call reuses cached installation token (still 1 exchange)
        const r2 = await client.testAuth();
        assert.equal(r2.ok, true);
        assert.equal(tokenExchanges, 1);
      },
    );
  });

  it('supports gh auth token in-memory fallback with single 401 refresh retry', async () => {
    let ghCalls = 0;
    await withMockServer(
      (req, res) => {
        if (req.headers.authorization === 'Bearer gho_expiredToken1234567890abcdef12') {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ message: 'Bad credentials' }));
          return;
        }
        if (req.headers.authorization === 'Bearer gho_freshToken1234567890abcdef1234') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ login: 'dev-user' }));
          return;
        }
        res.writeHead(401);
        res.end();
      },
      async baseUrl => {
        const client = new GitHubClient({
          auth: {
            mode: 'gh_cli',
            apiBaseUrl: baseUrl,
            app: { appId: '', installationId: '' },
          },
          ghRunner: async () => {
            ghCalls++;
            return ghCalls === 1
              ? 'gho_expiredToken1234567890abcdef12'
              : 'gho_freshToken1234567890abcdef1234';
          },
          allowInsecureLocalForTests: true,
        });

        const res = await client.testAuth();
        assert.equal(res.ok, true);
        assert.equal(res.resolvedMethod, 'gh_cli');
        assert.equal(res.identity, '@dev-user');
        assert.equal(ghCalls, 2);
      },
    );
  });

  it('fails closed on invalid proxy URLs with zero direct connections and blocks cross-origin redirects & SSRF apiBaseUrls', async () => {
    let directHits = 0;
    await withMockServer(
      (_req, res) => {
        directHits++;
        res.writeHead(200);
        res.end('{}');
      },
      async baseUrl => {
        for (const badProxy of [
          'socks5://127.0.0.1:1080',
          'not-a-valid-url',
          'http://user:s3cr3t@proxy.local:8080/bad-path',
          'http://proxy.local:8080\r\nX-Inject: 1',
        ]) {
          const client = new GitHubClient({
            auth: {
              mode: 'pat',
              apiBaseUrl: baseUrl,
              pat: 'github_pat_1234567890abcdef1234567890',
              app: { appId: '', installationId: '' },
            },
            proxy: { url: badProxy },
            allowInsecureLocalForTests: true,
          });
          await assert.rejects(
            () => client.request({ method: 'GET', path: '/user' }),
            (err: unknown) => {
              assert.ok(err instanceof ProxyConfigError);
              assert.ok(!err.message.includes('s3cr3t'), 'Proxy password must be redacted');
              return true;
            },
          );
        }
        assert.equal(directHits, 0, 'Fail-closed proxy must NEVER fall back to direct connection');
      },
    );

    // Cross-origin redirect must be refused without leaking token
    await withMockServer(
      (_req, res) => {
        res.writeHead(302, { Location: 'https://evil.example/steal-token' });
        res.end();
      },
      async baseUrl => {
        const client = new GitHubClient({
          auth: {
            mode: 'pat',
            apiBaseUrl: baseUrl,
            pat: 'github_pat_1234567890abcdef1234567890',
            app: { appId: '', installationId: '' },
          },
          allowInsecureLocalForTests: true,
        });
        await assert.rejects(
          () => client.request({ method: 'GET', path: '/user' }),
          (err: unknown) =>
            err instanceof CrossOriginRedirectError ||
            (err instanceof Error && err.message.includes('cross-origin redirect')),
        );
      },
    );

    // Production SSRF validation blocks http://, loopback, trailing-dot FQDN, NAT64, and cloud metadata IPs
    const prevEnv = process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API;
    delete process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API;
    try {
      for (const badBase of [
        'http://api.github.com',
        'https://127.0.0.1/api/v3',
        'https://169.254.169.254/latest',
        'https://[::ffff:127.0.0.1]/api/v3',
        'https://[64:ff9b::169.254.169.254]/api/v3',
        'https://localhost/api/v3',
        'https://localhost./api/v3',
        'https://metadata.google.internal./api/v3',
      ]) {
        assert.throws(
          () => validateGitHubApiBaseUrl(badBase, { allowInsecureLocalForTests: false }),
          SsrfBlockedError,
        );
      }
      assert.equal(isIpAddressBlocked('0:0:0:0:0:0:0:1', { allowPrivateIntranet: true }), true);
      assert.equal(isIpAddressBlocked('fd00:0ec2::254', { allowPrivateIntranet: true }), true);
    } finally {
      if (prevEnv !== undefined) process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API = prevEnv;
    }

    // Segment-bounded redirect prefix: /api/v3 must reject redirect to /api/v3-evil
    await withMockServer(
      (_req, res) => {
        res.writeHead(302, { Location: '/api/v3-evil/steal' });
        res.end();
      },
      async baseUrl => {
        const client = new GitHubClient({
          auth: {
            mode: 'pat',
            apiBaseUrl: `${baseUrl}/api/v3`,
            pat: 'github_pat_1234567890abcdef1234567890',
            app: { appId: '', installationId: '' },
          },
          allowInsecureLocalForTests: true,
        });
        await assert.rejects(
          () => client.request({ method: 'GET', path: '/user' }),
          (err: unknown) => err instanceof Error && err.message.includes('outside allowed path prefix'),
        );
      },
    );
  });

  it('tunnels HTTPS through a real HTTP CONNECT proxy without leaking target Authorization on CONNECT, verifies TLS, and fails closed on 407', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-gh-tls-'));
    const keyPath = join(tmp, 'key.pem');
    const certPath = join(tmp, 'cert.pem');
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-keyout',
        keyPath,
        '-out',
        certPath,
        '-days',
        '1',
        '-nodes',
        '-subj',
        '/CN=127.0.0.1',
        '-addext',
        'subjectAltName=IP:127.0.0.1',
      ],
      { stdio: 'ignore' },
    );
    const keyPem = await fsp.readFile(keyPath);
    const certPem = await fsp.readFile(certPath);

    let targetHits = 0;
    const tlsTarget = https.createServer({ key: keyPem, cert: certPem }, (req, res) => {
      targetHits++;
      assert.equal(req.headers.authorization, 'Bearer github_pat_connectTunnelToken12345678');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ login: 'proxied-user' }));
    });

    let connectCount = 0;
    let rejectWith407 = false;
    const proxyServer = http.createServer((_req, res) => {
      res.writeHead(405);
      res.end();
    });
    proxyServer.on('connect', (req, clientSocket, head) => {
      connectCount++;
      assert.equal(req.headers.authorization, undefined, 'Target GitHub Authorization MUST NOT be sent on CONNECT');
      assert.ok(
        String(req.headers['proxy-authorization'] ?? '').startsWith('Basic '),
        'Proxy-Authorization must be sent on CONNECT',
      );
      if (rejectWith407) {
        clientSocket.end('HTTP/1.1 407 Proxy Authentication Required\r\nConnection: close\r\n\r\n');
        return;
      }
      const [host, portStr] = String(req.url).split(':');
      const upstream = net.connect(Number(portStr), host!, () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head.length > 0) upstream.write(head);
        upstream.pipe(clientSocket);
        clientSocket.pipe(upstream);
      });
      upstream.on('close', () => clientSocket.destroy());
      clientSocket.on('close', () => upstream.destroy());
      upstream.on('error', () => clientSocket.destroy());
      clientSocket.on('error', () => upstream.destroy());
    });

    await Promise.all([
      new Promise<void>(r => tlsTarget.listen(0, '127.0.0.1', () => r())),
      new Promise<void>(r => proxyServer.listen(0, '127.0.0.1', () => r())),
    ]);
    const targetPort = (tlsTarget.address() as { port: number }).port;
    const proxyPort = (proxyServer.address() as { port: number }).port;

    try {
      const client = new GitHubClient({
        auth: {
          mode: 'pat',
          apiBaseUrl: `https://127.0.0.1:${targetPort}`,
          pat: 'github_pat_connectTunnelToken12345678',
          app: { appId: '', installationId: '' },
        },
        proxy: {
          url: `http://127.0.0.1:${proxyPort}`,
          username: 'puser',
          password: 'ppassword',
        },
        allowInsecureLocalForTests: true,
        testCa: certPem,
      });

      const okRes = await client.testAuth();
      assert.equal(okRes.ok, true, `CONNECT testAuth failed: ${okRes.error}`);
      assert.equal(okRes.identity, '@proxied-user');
      assert.equal(connectCount, 1);
      assert.equal(targetHits, 1);

      // Proxy 407 fails closed with zero direct fallback
      rejectWith407 = true;
      const failRes = await client.testAuth();
      assert.equal(failRes.ok, false);
      assert.equal(targetHits, 1, 'Failed CONNECT proxy must NEVER fall back direct');
    } finally {
      await Promise.all([
        new Promise<void>(r => tlsTarget.close(() => r())),
        new Promise<void>(r => proxyServer.close(() => r())),
      ]);
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('respects bypassEtag over in-memory cache and avoids poisoning ETag when page 2 fails', async () => {
    let page2Fail = true;
    await withMockServer(
      (req, res) => {
        if (req.url?.includes('&page=1')) {
          if (req.headers['if-none-match'] === '"etag-p1"') {
            res.writeHead(304, { ETag: '"etag-p1"' });
            res.end();
            return;
          }
          // Return 100 items on page 1 to trigger page 2 fetch
          const items = Array.from({ length: 100 }, (_, i) => ({
            number: i + 1,
            title: `PR ${i + 1}`,
            body: '',
            state: 'open',
            draft: false,
            html_url: `https://github.com/acme/big/pull/${i + 1}`,
            user: { login: 'alice' },
            base: { ref: 'main', repo: { full_name: 'acme/big' } },
            head: { ref: 'f', sha: 'a'.repeat(40), repo: { full_name: 'acme/big', fork: false } },
            labels: [],
            created_at: '2026-11-25T00:00:00Z',
            updated_at: '2026-11-25T00:00:00Z',
          }));
          res.writeHead(200, {
            'Content-Type': 'application/json',
            ETag: '"etag-p1"',
            Link: '<http://127.0.0.1/page=2>; rel="next"',
          });
          res.end(JSON.stringify(items));
          return;
        }
        if (page2Fail) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ message: 'Transient error' }));
          return;
        }
        if (req.headers['if-none-match'] === '"etag-p2"') {
          res.writeHead(304, { ETag: '"etag-p2"' });
          res.end();
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json', ETag: '"etag-p2"' });
        res.end('[]');
      },
      async baseUrl => {
        const client = new GitHubClient({
          auth: {
            mode: 'pat',
            apiBaseUrl: baseUrl,
            pat: 'github_pat_etagPaginationToken123456789',
            app: { appId: '', installationId: '' },
          },
          allowInsecureLocalForTests: true,
        });

        await assert.rejects(() => client.listOpenPullRequests('acme', 'big'));
        // Next poll MUST NOT get 304 because failed page 2 must NOT have cached page-1 ETag!
        page2Fail = false;
        const ok = await client.listOpenPullRequests('acme', 'big');
        assert.equal(ok.notModified, false);
        assert.equal(ok.pulls.length, 100);

        // Now cached -> normal poll gets 304, while bypassEtag: true gets fresh 200
        const cached304 = await client.listOpenPullRequests('acme', 'big');
        assert.equal(cached304.notModified, true);
        const bypassed = await client.listOpenPullRequests('acme', 'big', { bypassEtag: true });
        assert.equal(bypassed.notModified, false);
      },
    );
  });

  it('pauses non-core requests when core quota < 10% and pauses all requests during secondary 429 backoff', async () => {
    await withMockServer(
      (req, res) => {
        if (req.url === '/trigger-429') {
          res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '120' });
          res.end(JSON.stringify({ message: 'Secondary rate limit' }));
          return;
        }
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'X-RateLimit-Resource': 'core',
          'X-RateLimit-Limit': '5000',
          'X-RateLimit-Remaining': '400', // 8% < 10%
          'X-RateLimit-Reset': String(Math.floor(Date.now() / 1000) + 1800),
        });
        res.end('{}');
      },
      async baseUrl => {
        const client = new GitHubClient({
          auth: {
            mode: 'pat',
            apiBaseUrl: baseUrl,
            pat: 'github_pat_1234567890abcdef1234567890',
            app: { appId: '', installationId: '' },
          },
          allowInsecureLocalForTests: true,
        });

        await client.request({ method: 'GET', path: '/core-check', priority: 'core' });
        await assert.rejects(
          () => client.request({ method: 'GET', path: '/non-core-check', priority: 'non_core' }),
          GitHubRateLimitPausedError,
        );

        await assert.rejects(() =>
          client.request({ method: 'GET', path: '/trigger-429', priority: 'core' }),
        );
        await assert.rejects(
          () => client.request({ method: 'GET', path: '/after-429', priority: 'core' }),
          GitHubRateLimitPausedError,
        );
      },
    );
  });
});
